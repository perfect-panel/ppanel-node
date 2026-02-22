package cmd

import (
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
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
	p := panel.NewClientV2(&c.ApiConfig)
	serverconfig, err := panel.GetServerConfig(p)
	if err != nil {
		log.WithField("err", err).Error("获取服务端配置失败")
		return
	}
	var reloadCh = make(chan struct{}, 1)
	xraycore := core.New(c, p)
	xraycore.ReloadCh = reloadCh
	err = xraycore.Start(serverconfig)
	if err != nil {
		log.WithField("err", err).Error("启动Xray核心失败")
		return
	}
	defer xraycore.Close()
	nodes, err := node.New(xraycore, c, serverconfig)
	if err != nil {
		log.WithField("err", err).Error("获取节点配置失败")
		return
	}
	err = nodes.Start()
	if err != nil {
		log.WithField("err", err).Error("启动节点失败")
		return
	}
	log.Infof("已启动 %d 个节点（共 %d 个，%d 个已禁用）", nodes.Len(), serverconfig.Data.Total, serverconfig.Data.Total-nodes.Len())
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
			nodes.Close()
			_ = xraycore.Close()
			return
		case <-reloadCh:
			log.Info("收到重启信号，正在重新加载配置...")
			if err := reload(config, &nodes, &xraycore); err != nil {
				log.WithField("err", err).Error("重启失败")
			}
		}
	}
}

func reload(config string, nodes **node.Node, xcore **core.XrayCore) error {
	// Preserve old reload channel so new core continues to receive signals
	var oldReloadCh chan struct{}

	if *xcore != nil {
		oldReloadCh = (*xcore).ReloadCh
	}

	(*nodes).Close()
	if err := (*xcore).Close(); err != nil {
		return err
	}

	newConf := conf.New()
	if err := newConf.LoadFromPath(config); err != nil {
		return err
	}
	p := panel.NewClientV2(&newConf.ApiConfig)
	serverconfig, err := panel.GetServerConfig(p)
	if err != nil {
		log.WithField("err", err).Error("获取服务端配置失败")
		return err
	}

	newCore := core.New(newConf, p)
	// Reattach reload channel
	newCore.ReloadCh = oldReloadCh
	if err := newCore.Start(serverconfig); err != nil {
		return err
	}
	newNodes, err := node.New(newCore, newConf, serverconfig)
	if err != nil {
		return err
	}
	if err := newNodes.Start(); err != nil {
		return err
	}

	*nodes = newNodes
	*xcore = newCore
	log.Infof("%d 个节点重启成功（共 %d 个，%d 个已禁用）", newNodes.Len(), serverconfig.Data.Total, serverconfig.Data.Total-newNodes.Len())
	runtime.GC()
	return nil
}
