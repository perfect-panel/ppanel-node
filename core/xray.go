package core

import (
	"sync"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/common/task"
	"github.com/perfect-panel/ppanel-node/conf"
	"github.com/perfect-panel/ppanel-node/core/app/dispatcher"
	_ "github.com/perfect-panel/ppanel-node/core/distro/all"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	coreConf "github.com/xtls/xray-core/infra/conf"
	"google.golang.org/protobuf/proto"
)

type AddUsersParams struct {
	Tag   string
	Users []panel.UserInfo
	*panel.NodeInfo
}

type XrayCore struct {
	Config                      *conf.Conf
	Client                      *panel.ClientV2
	ReloadCh                    chan struct{}
	serverConfigMonitorPeriodic *task.Task
	access                      sync.Mutex
	Server                      *core.Instance
	users                       *UserMap
	ihm                         inbound.Manager
	ohm                         outbound.Manager
	dispatcher                  *dispatcher.DefaultDispatcher
}

type UserMap struct {
	uidMap  map[string]int
	mapLock sync.RWMutex
}

func New(config *conf.Conf, client *panel.ClientV2) *XrayCore {
	core := &XrayCore{
		Config: config,
		Client: client,
		users: &UserMap{
			uidMap: make(map[string]int),
		},
	}
	return core
}

func (v *XrayCore) Start(serverconfig *panel.ServerConfigResponse) error {
	v.access.Lock()
	defer v.access.Unlock()
	v.Server = getCore(v.Config, serverconfig)
	if err := v.Server.Start(); err != nil {
		return err
	}
	v.ihm = v.Server.GetFeature(inbound.ManagerType()).(inbound.Manager)
	v.ohm = v.Server.GetFeature(outbound.ManagerType()).(outbound.Manager)
	v.dispatcher = v.Server.GetFeature(routing.DispatcherType()).(*dispatcher.DefaultDispatcher)
	v.startTasks(serverconfig)
	return nil
}

func (v *XrayCore) Close() error {
	v.access.Lock()
	defer v.access.Unlock()
	if v.serverConfigMonitorPeriodic != nil {
		v.serverConfigMonitorPeriodic.Close()
	}
	v.Config = nil
	v.ihm = nil
	v.ohm = nil
	v.dispatcher = nil
	err := v.Server.Close()
	if err != nil {
		return err
	}
	return nil
}

func getCore(c *conf.Conf, serverconfig *panel.ServerConfigResponse) *core.Instance {
	// Log Config
	coreLogConfig := &coreConf.LogConfig{
		LogLevel:  c.LogConfig.Level,
		AccessLog: c.LogConfig.Access,
		ErrorLog:  c.LogConfig.Output,
	}
	// Custom config
	dnsConfig, outBoundConfig, routeConfig, err := GetCustomConfig(serverconfig, c.Outbound)
	if err != nil {
		log.WithField("err", err).Panic("failed to build custom config")
	}
	// Inbound config
	var inBoundConfig []*core.InboundHandlerConfig

	// Policy config
	levelPolicyConfig := &coreConf.Policy{
		StatsUserUplink:   true,
		StatsUserDownlink: true,
		Handshake:         proto.Uint32(4),
		ConnectionIdle:    proto.Uint32(30),
		UplinkOnly:        proto.Uint32(2),
		DownlinkOnly:      proto.Uint32(4),
		BufferSize:        proto.Int32(64),
	}
	corePolicyConfig := &coreConf.PolicyConfig{}
	corePolicyConfig.Levels = map[uint32]*coreConf.Policy{0: levelPolicyConfig}
	policyConfig, _ := corePolicyConfig.Build()
	// Build Xray conf
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(coreLogConfig.Build()),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(policyConfig),
			serial.ToTypedMessage(dnsConfig),
			serial.ToTypedMessage(routeConfig),
		},
		Inbound:  inBoundConfig,
		Outbound: outBoundConfig,
	}
	server, err := core.New(config)
	if err != nil {
		log.WithField("err", err).Panic("failed to create instance")
	}
	return server
}

func (c *XrayCore) startTasks(serverconfig *panel.ServerConfigResponse) {
	// fetch node info task
	pullinverval := serverconfig.Data.PullInterval
	if pullinverval <= 0 {
		pullinverval = 60
	}
	c.serverConfigMonitorPeriodic = &task.Task{
		Interval: time.Duration(pullinverval) * time.Second,
		Execute:  c.ServerConfigMonitor,
	}
	_ = c.serverConfigMonitorPeriodic.Start(false)
}

func (c *XrayCore) ServerConfigMonitor() (err error) {
	newServerConfig, err := panel.GetServerConfig(c.Client)
	if err != nil {
		log.WithField("err", err).Error("获取服务端配置失败")
		return nil
	}
	if newServerConfig != nil {
		log.Error("检测到服务端配置变更，正在重启节点...")
		// Non-blocking signal to avoid goroutine stuck when channel is full or nil
		if c.ReloadCh != nil {
			select {
			case c.ReloadCh <- struct{}{}:
			default:
			}
		}
	}
	return nil
}
