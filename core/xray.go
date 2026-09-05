package core

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/common/logx"
	"github.com/perfect-panel/ppanel-node/common/task"
	"github.com/perfect-panel/ppanel-node/conf"
	"github.com/perfect-panel/ppanel-node/core/app/dispatcher"
	_ "github.com/perfect-panel/ppanel-node/core/distro/all"
	"github.com/perfect-panel/ppanel-node/limiter"
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
	Client                      *panel.ServerClient
	ReloadCh                    chan struct{}
	serverConfigMonitorPeriodic *task.Task
	access                      sync.Mutex
	Server                      *core.Instance
	LimiterManager              *limiter.Manager
	users                       *UserMap
	ihm                         inbound.Manager
	ohm                         outbound.Manager
	dispatcher                  *dispatcher.DefaultDispatcher
}

type UserMap struct {
	uidMap  map[string]int
	mapLock sync.RWMutex
}

func New(config *conf.Conf, client *panel.ServerClient) *XrayCore {
	core := &XrayCore{
		Config:         config,
		Client:         client,
		LimiterManager: limiter.NewManager(),
		users: &UserMap{
			uidMap: make(map[string]int),
		},
	}
	return core
}

func (v *XrayCore) Start(serverconfig *panel.ServerConfigResponse) error {
	v.access.Lock()
	defer v.access.Unlock()
	server, err := getCore(v.Config, serverconfig)
	if err != nil {
		return err
	}
	v.Server = server
	if err := v.Server.Start(); err != nil {
		_ = v.Server.Close()
		return err
	}
	v.ihm = v.Server.GetFeature(inbound.ManagerType()).(inbound.Manager)
	v.ohm = v.Server.GetFeature(outbound.ManagerType()).(outbound.Manager)
	v.dispatcher = v.Server.GetFeature(routing.DispatcherType()).(*dispatcher.DefaultDispatcher)
	v.dispatcher.LimiterManager = v.LimiterManager
	v.startTasks(serverconfig)
	return nil
}

func (v *XrayCore) Close() error {
	if v == nil {
		return nil
	}
	v.access.Lock()
	defer v.access.Unlock()
	if v.serverConfigMonitorPeriodic != nil {
		v.serverConfigMonitorPeriodic.Close()
		v.serverConfigMonitorPeriodic = nil
	}
	server := v.Server
	v.Config = nil
	v.ihm = nil
	v.ohm = nil
	v.dispatcher = nil
	v.LimiterManager = nil
	v.Server = nil
	if server == nil {
		return nil
	}
	err := server.Close()
	if err != nil {
		return err
	}
	return nil
}

func getCore(c *conf.Conf, serverconfig *panel.ServerConfigResponse) (*core.Instance, error) {
	// Log Config
	coreLogConfig := &coreConf.LogConfig{
		LogLevel:  c.LogConfig.Level,
		AccessLog: c.LogConfig.Access,
		ErrorLog:  c.LogConfig.Output,
	}
	// Custom config
	dnsConfig, outBoundConfig, routeConfig, err := GetCustomConfig(serverconfig)
	if err != nil {
		return nil, fmt.Errorf("build custom configuration: %w", err)
	}
	// Inbound config
	var inBoundConfig []*core.InboundHandlerConfig

	// Policy config
	levelPolicyConfig := &coreConf.Policy{
		StatsUserUplink:   true,
		StatsUserDownlink: true,
		Handshake:         proto.Uint32(4),
		// ppnode lowered this to 30s, which xray's polling activity timer turns
		// into a ~60s effective timeout, dropping idle-but-healthy long-lived
		// connections (interactive SSH, database sessions, MQTT/WebSocket, etc.).
		// Restore it to 120 — the value used by upstream wyx2685/v2node, which
		// this project is modified from.
		ConnectionIdle: proto.Uint32(120),
		UplinkOnly:     proto.Uint32(2),
		DownlinkOnly:   proto.Uint32(4),
		BufferSize:     proto.Int32(64),
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
		return nil, fmt.Errorf("create Xray instance: %w", err)
	}
	return server, nil
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
		ReloadCh: c.ReloadCh,
	}
	_ = c.serverConfigMonitorPeriodic.Start(false)
}

func (c *XrayCore) ServerConfigMonitor(ctx context.Context) (err error) {
	newServerConfig, err := panel.GetServerConfig(ctx, c.Client)
	if err != nil {
		logx.Component("xray").WithError(err).Error("获取服务端配置失败")
		return nil
	}
	if newServerConfig != nil {
		logx.Component("xray").Info("检测到服务端配置变更，已投递重载信号")
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
