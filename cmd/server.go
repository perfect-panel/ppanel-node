package cmd

import (
	"context"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/common/logx"
	"github.com/perfect-panel/ppanel-node/conf"
	"github.com/perfect-panel/ppanel-node/core"
	"github.com/perfect-panel/ppanel-node/node"
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
	if err != nil {
		logx.Component("server").WithError(err).Error("读取配置文件失败")
		return
	}
	logHandle, err := logx.Setup(logx.Config{
		Level:  c.LogConfig.Level,
		Output: c.LogConfig.Output,
	})
	if err != nil {
		logx.Component("server").WithError(err).Error("初始化日志失败，使用stdout替代")
	}
	defer func() {
		_ = logHandle.Close()
	}()
	// Enable pprof if configured
	if c.PprofPort != 0 {
		go func() {
			logx.Component("server").WithField("pprof_port", c.PprofPort).Info("启动pprof服务")
			if err := http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", c.PprofPort), nil); err != nil {
				logx.Component("server").WithError(err).Error("pprof服务失败")
			}
		}()
	}
	p := panel.NewServerClient(&c.ApiConfig)
	serverconfig, err := panel.GetServerConfig(context.Background(), p)
	if err != nil {
		logx.Component("server").WithError(err).Error("获取服务端配置失败")
		return
	}
	if err := core.ValidateServerConfig(serverconfig); err != nil {
		logx.Component("server").WithError(err).Error("服务端配置校验失败")
		return
	}
	var reloadCh = make(chan struct{}, 1)
	xraycore := core.New(c, p)
	xraycore.ReloadCh = reloadCh
	err = xraycore.Start(serverconfig)
	if err != nil {
		logx.Component("server").WithError(err).Error("启动Xray核心失败")
		return
	}
	defer func() { _ = xraycore.Close() }()
	nodes, err := node.New(xraycore, c, serverconfig)
	if err != nil {
		logx.Component("server").WithError(err).Error("获取节点配置失败")
		return
	}
	defer func() {
		nodes.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := nodes.FlushTraffic(ctx); err != nil {
			logx.Component("server").WithError(err).Error("退出前上报剩余流量失败")
		}
	}()
	err = nodes.Start()
	if err != nil {
		logx.Component("server").WithError(err).Error("启动节点失败")
		return
	}
	logx.Component("server").WithField("server_total", serverconfig.Data.Total).Info("节点启动成功")
	if watch {
		// On file change, just signal reload; do not run reload concurrently here
		err = c.Watch(config, func() {
			select {
			case reloadCh <- struct{}{}:
			default: // drop if a reload is already queued
			}
		})
		if err != nil {
			logx.Component("server").WithError(err).Error("启动配置监听失败")
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
			return
		case <-reloadCh:
			logx.Component("server").Info("收到重载信号，正在重新加载配置")
			newLogHandle, err := reload(config, &nodes, &xraycore, logHandle)
			if err != nil {
				logx.Component("server").WithError(err).Error("重载失败")
				continue
			}
			logHandle = newLogHandle
		}
	}
}

func reload(config string, nodes **node.Node, xcore **core.XrayCore, logHandle *logx.Handle) (*logx.Handle, error) {
	// Preserve old reload channel so new core continues to receive signals
	var oldReloadCh chan struct{}
	if xcore != nil && *xcore != nil {
		oldReloadCh = (*xcore).ReloadCh
	}

	newConf := conf.New()
	if err := newConf.LoadFromPath(config); err != nil {
		return logHandle, err
	}
	logx.Component("server").Info("新配置加载成功")
	p := panel.NewServerClient(&newConf.ApiConfig)
	serverconfig, err := panel.GetServerConfig(context.Background(), p)
	if err != nil {
		logx.Component("server").WithError(err).Error("获取服务端配置失败")
		return logHandle, err
	}
	if err := core.ValidateServerConfig(serverconfig); err != nil {
		return logHandle, err
	}

	newCore := core.New(newConf, p)
	// Reattach reload channel
	newCore.ReloadCh = oldReloadCh
	if err := newCore.Start(serverconfig); err != nil {
		return logHandle, err
	}
	logx.Component("server").Info("新Xray核心启动成功")
	newNodes, err := node.New(newCore, newConf, serverconfig)
	if err != nil {
		_ = newCore.Close()
		return logHandle, err
	}

	if err := newNodes.Prepare(); err != nil {
		newNodes.Close()
		_ = newCore.Close()
		return logHandle, err
	}

	oldNodes := *nodes
	oldCore := *xcore
	newNodes.InheritTraffic(oldNodes)
	restore := func(cause error) (*logx.Handle, error) {
		newNodes.Close()
		_ = newCore.Close()
		if oldNodes != nil {
			if err := oldNodes.Start(); err != nil {
				return logHandle, fmt.Errorf("reload failed: %w; restoring previous nodes failed: %v", cause, err)
			}
		}
		return logHandle, fmt.Errorf("reload failed, previous nodes restored: %w", cause)
	}
	// Keep the old core and the prepared node snapshots until the new listeners
	// are bound. Rollback never fetches users or certificates from the panel.
	if oldNodes != nil {
		if err := oldNodes.Stop(); err != nil {
			return restore(err)
		}
	}
	if err := newNodes.Start(); err != nil {
		return restore(err)
	}

	*nodes = newNodes
	*xcore = newCore
	if oldNodes != nil {
		oldNodes.Close()
	}
	if oldCore != nil {
		_ = oldCore.Close()
	}
	logx.Component("server").Info("实例切换成功")
	newLogHandle := logHandle
	if h, err := logx.Setup(logx.Config{
		Level:  newConf.LogConfig.Level,
		Output: newConf.LogConfig.Output,
	}); err != nil {
		logx.Component("server").WithError(err).Error("重载日志配置失败，继续使用旧日志配置")
	} else {
		if logHandle != nil {
			_ = logHandle.Close()
		}
		newLogHandle = h
	}
	logx.Component("server").WithField("server_total", serverconfig.Data.Total).Info("节点重载成功")
	runtime.GC()
	return newLogHandle, nil
}
