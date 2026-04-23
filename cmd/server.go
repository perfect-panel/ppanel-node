package cmd

import (
	"context"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
	"github.com/perfect-panel/ppanel-node/core"
	"github.com/perfect-panel/ppanel-node/limiter"
	"github.com/perfect-panel/ppanel-node/node"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	config string
	watch  bool
)

var serverCommand = cobra.Command{
	Use:   "server",
	Short: "Run ppnode server",
	Run:   serverHandle,
	Args:  cobra.NoArgs,
}

func init() {
	serverCommand.PersistentFlags().
		StringVarP(&config, "config", "c",
			"/etc/PPanel-node/config.yml", "config file path")
	serverCommand.PersistentFlags().
		BoolVarP(&watch, "watch", "w",
			true, "watch file path change")
	command.AddCommand(&serverCommand)
}

type Backend struct {
	Config   conf.ServerApiConfig
	XrayCore *core.XrayCore
	Nodes    *node.Node
	ApiDir   string
}

func serverHandle(_ *cobra.Command, _ []string) {
	showVersion()
	c := conf.New()
	err := c.LoadFromPath(config)
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp: true,
		DisableQuote:     true,
		PadLevelText:     false,
	})
	if err != nil {
		log.WithField("err", err).Error("读取配置文件失败")
		return
	}
	switch c.LogConfig.Level {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn", "warning":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	}
	if c.LogConfig.Output != "" {
		f, err := os.OpenFile(c.LogConfig.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.WithField("err", err).Error("打开日志文件失败，使用stdout替代")
		}
		log.SetOutput(f)
	}
	// Enable pprof if configured
	if c.PprofPort != 0 {
		go func() {
			log.Infof("Starting pprof server on :%d", c.PprofPort)
			if err := http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", c.PprofPort), nil); err != nil {
				log.WithField("err", err).Error("pprof server failed")
			}
		}()
	}
	limiter.Init()
	
	var reloadCh = make(chan struct{}, 1)
	backends := startBackends(c, reloadCh)

	if watch {
		// On file change, just signal reload; do not run reload concurrently here
		err = c.Watch(config, func() {
			select {
			case reloadCh <- struct{}{}:
			default: // drop if a reload is already queued
			}
		})
		if err != nil {
			log.WithField("err", err).Error("start watch failed")
			return
		}
	}
	// clear memory
	runtime.GC()

	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-osSignals:
			for _, b := range backends {
				b.Nodes.Close()
				_ = b.XrayCore.Close()
			}
			return
		case <-reloadCh:
			log.Info("收到重启信号，正在重新加载配置...")
			if err := reload(config, &backends, reloadCh); err != nil {
				log.WithField("err", err).Error("重启失败")
			}
		}
	}
}

func startBackends(c *conf.Conf, reloadCh chan struct{}) []*Backend {
	var backends []*Backend
	usedPorts := make(map[int]string)

	for _, apiConf := range c.Nodes {
		u, err := url.Parse(apiConf.ApiHost)
		if err != nil {
			log.WithField("err", err).Errorf("解析ApiHost失败: %s", apiConf.ApiHost)
			continue
		}
		
		apiDir := filepath.Join("/etc/PPanel-node", u.Hostname())
		if err := os.MkdirAll(apiDir, 0755); err != nil {
			log.WithField("err", err).Errorf("创建目录失败: %s", apiDir)
			continue
		}

		p := panel.NewClientV2(&apiConf)
		serverconfig, err := panel.GetServerConfig(context.Background(), p)
		if err != nil {
			log.WithField("err", err).Errorf("获取服务端配置失败: %s", apiConf.ApiHost)
			continue
		}
		if serverconfig == nil || serverconfig.Data == nil || serverconfig.Data.Protocols == nil {
			continue
		}

		// Check port conflicts
		for _, proto := range *serverconfig.Data.Protocols {
			if proto.Enable {
				if host, exists := usedPorts[proto.Port]; exists {
					log.Errorf("[警告] 发现重复监听端口: %d. (API: %s 与 API: %s 冲突)", proto.Port, host, apiConf.ApiHost)
				} else {
					usedPorts[proto.Port] = apiConf.ApiHost
				}
			}
		}

		xraycore := core.New(c, p)
		xraycore.ReloadCh = reloadCh
		err = xraycore.Start(serverconfig, apiDir)
		if err != nil {
			log.WithField("err", err).Errorf("启动Xray核心失败: %s", apiConf.ApiHost)
			continue
		}

		apiConfCopy := apiConf // prevent pointer capture in loop
		nodes, err := node.New(xraycore, &apiConfCopy, serverconfig)
		if err != nil {
			log.WithField("err", err).Errorf("获取节点配置失败: %s", apiConf.ApiHost)
			xraycore.Close()
			continue
		}
		err = nodes.Start()
		if err != nil {
			log.WithField("err", err).Errorf("启动节点失败: %s", apiConf.ApiHost)
			xraycore.Close()
			continue
		}
		log.Infof("API %s 已启动 %d 个节点", apiConf.ApiHost, serverconfig.Data.Total)
		backends = append(backends, &Backend{
			Config:   apiConfCopy,
			XrayCore: xraycore,
			Nodes:    nodes,
			ApiDir:   apiDir,
		})
	}
	return backends
}

func reload(configFile string, backends *[]*Backend, reloadCh chan struct{}) error {
	for _, b := range *backends {
		b.Nodes.Close()
		if err := b.XrayCore.Close(); err != nil {
			log.WithField("err", err).Error("关闭Xray核心失败")
		}
	}
	*backends = nil

	newConf := conf.New()
	if err := newConf.LoadFromPath(configFile); err != nil {
		return err
	}

	*backends = startBackends(newConf, reloadCh)
	log.Infof("全部节点重启成功，当前运行 %d 个后端", len(*backends))
	runtime.GC()
	return nil
}
