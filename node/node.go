package node

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/perfect-panel/ppanel-node/common/task"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/common/logx"
	"github.com/perfect-panel/ppanel-node/conf"
	vCore "github.com/perfect-panel/ppanel-node/core"
)

type Node struct {
	controllers    []*Controller
	traffic        *trafficQueue
	reportPeriodic *task.Task
	pushInterval   time.Duration
}

func New(core *vCore.XrayCore, config *conf.Conf, serverconfig *panel.ServerConfigResponse) (*Node, error) {
	node := &Node{
		controllers: make([]*Controller, 0, len(*serverconfig.Data.Protocols)),
		traffic:     newTrafficQueue(),
	}
	pushinterval := serverconfig.Data.PushInterval
	if pushinterval <= 0 {
		pushinterval = 60
	}
	pullinterval := serverconfig.Data.PullInterval
	if pullinterval <= 0 {
		pullinterval = 60
	}
	node.pushInterval = time.Duration(pushinterval) * time.Second
	for _, nodeconfig := range *serverconfig.Data.Protocols {
		if !panel.IsSupportedProtocol(nodeconfig.Type) {
			logx.Component("node").WithField("protocol", nodeconfig.Type).Warn("节点不支持该协议，已跳过对应配置")
			continue
		}
		n := &panel.NodeInfo{
			Id:                     config.ApiConfig.ServerId,
			Type:                   nodeconfig.Type,
			TrafficReportThreshold: serverconfig.Data.TrafficReportThreshold,
			PushInterval:           pushinterval,
			PullInterval:           pullinterval,
			ACMEEmail:              config.ApiConfig.ACMEEmail,
			ACMECADirURL:           config.ApiConfig.ACMECADirURL,
			Protocol:               &nodeconfig,
		}
		p, err := panel.NewNodeClient(&conf.NodeApiConfig{
			APIHost:     config.ApiConfig.ApiHost,
			NodeType:    nodeconfig.Type,
			NodeID:      config.ApiConfig.ServerId,
			SecretKey:   config.ApiConfig.SecretKey,
			Timeout:     config.ApiConfig.Timeout,
			UseProtobuf: serverconfig.UseProtobuf,
		})
		if err != nil {
			return nil, err
		}
		controller := NewController(core, p, n)
		controller.traffic = node.traffic
		node.controllers = append(node.controllers, controller)
	}

	return node, nil
}

func (n *Node) Prepare() error {
	for _, c := range n.controllers {
		if c != nil && c.info.Protocol.Enable {
			if err := c.Prepare(); err != nil {
				return err
			}
		}
	}
	return nil
}

// InheritTraffic keeps unacknowledged reports even if a protocol is removed.
func (n *Node) InheritTraffic(old *Node) {
	if old == nil {
		return
	}
	n.traffic = old.traffic
	for _, c := range n.controllers {
		c.traffic = n.traffic
	}
}

func (n *Node) Start() error {
	if err := n.Prepare(); err != nil {
		return err
	}
	for i := range n.controllers {
		if n.controllers[i] == nil {
			continue
		}
		if !n.controllers[i].info.Protocol.Enable {
			continue
		}
		err := n.controllers[i].Start()
		if err != nil {
			_ = n.Stop()
			return fmt.Errorf("启动节点 [%s-%s-%d] 失败: %s",
				n.controllers[i].apiClient.APIHost,
				n.controllers[i].info.Type,
				n.controllers[i].info.Id,
				err)
		}
	}
	if n.reportPeriodic == nil {
		n.reportPeriodic = &task.Task{Name: "reportNode", Interval: n.pushInterval, Execute: n.report}
		_ = n.reportPeriodic.Start(false)
	}
	return nil
}

func (n *Node) report(ctx context.Context) error {
	snapshots := make(map[*Controller][]panel.UserTraffic)
	for _, c := range n.controllers {
		if c.started {
			snapshots[c] = c.collectTraffic(max(c.info.TrafficReportThreshold, 0))
		}
	}
	// Traffic ACKs take priority over online/status calls, which may time out.
	result := n.traffic.report(ctx)
	for _, c := range n.controllers {
		if ctx.Err() != nil {
			return errors.Join(result, ctx.Err())
		}
		if c.started {
			_ = c.reportOnlineAndStatus(ctx, snapshots[c])
		}
	}
	return result
}

func (n *Node) Stop() error {
	if n == nil {
		return nil
	}
	if n.reportPeriodic != nil {
		n.reportPeriodic.Close()
		n.reportPeriodic = nil
	}
	var result error
	for _, c := range n.controllers {
		result = errors.Join(result, c.Stop())
	}
	return result
}

func (n *Node) Close() {
	if n == nil {
		return
	}
	_ = n.Stop()
	for _, c := range n.controllers {
		if c == nil {
			continue
		}
		if err := c.Close(); err != nil {
			logx.Node(c.tag).WithError(err).Error("关闭节点控制器失败")
		}
	}
	n.controllers = nil
}

// FlushTraffic attempts final delivery after Stop has collected the last batch.
func (n *Node) FlushTraffic(ctx context.Context) error { return n.traffic.report(ctx) }
