package node

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/common/logx"
	"github.com/perfect-panel/ppanel-node/common/serverstatus"
	"github.com/perfect-panel/ppanel-node/common/task"
	vCore "github.com/perfect-panel/ppanel-node/core"
)

func (c *Controller) startTasks(node *panel.NodeInfo) {
	// fetch user list task
	c.userListMonitorPeriodic = &task.Task{
		Name:     "userListMonitor",
		Interval: time.Duration(node.PullInterval) * time.Second,
		Execute:  c.userListMonitor,
		ReloadCh: c.server.ReloadCh,
	}
	_ = c.userListMonitorPeriodic.Start(false)
	logx.Node(c.tag).Info("用户列表监控任务已启动")
	if usesTLSCertificate(node) {
		switch node.Protocol.CertMode {
		case "none", "", "file", "self":
		default:
			c.renewCertPeriodic = &task.Task{
				Name:     "renewCert",
				Interval: time.Hour * 24,
				Execute:  c.renewCertTask,
				ReloadCh: c.server.ReloadCh,
			}
			logx.Node(c.tag).Info("证书定期更新任务已启动")
			// delay to start renewCert
			_ = c.renewCertPeriodic.Start(true)
		}
	}
}

func usesTLSCertificate(node *panel.NodeInfo) bool {
	if node == nil || node.Protocol == nil {
		return false
	}
	if node.Protocol.Security == "tls" {
		return true
	}
	switch node.Type {
	case "tuic", "hysteria", "hysteria2":
		mode := strings.TrimSpace(node.Protocol.CertMode)
		return mode != "" && mode != "none"
	default:
		return false
	}
}

func (c *Controller) userListMonitor(ctx context.Context) (err error) {
	// get user info
	newU, err := c.apiClient.GetUserList(ctx)
	if err != nil {
		logx.Node(c.tag).WithError(err).Error("获取用户列表失败")
		return nil
	}
	// get user alive
	newA, err := c.apiClient.GetUserAlive()
	if err != nil {
		logx.Node(c.tag).WithError(err).Error("获取在线列表失败")
		return nil
	}
	// update alive list
	if newA != nil {
		c.limiter.AliveList = newA
	}
	// update user list
	// newU == nil indicates 304 Not Modified; empty slice means the list is empty
	if newU == nil {
		return nil
	}
	deleted, added := compareUserList(c.userList, newU)
	if len(deleted) > 0 {
		c.collectTraffic(0)
		// have deleted users
		err = c.server.DelUsers(deleted, c.tag, c.info)
		if err != nil {
			logx.Node(c.tag).WithError(err).Error("删除用户失败")
			return nil
		}
	}
	if len(added) > 0 {
		// have added users
		_, err = c.server.AddUsers(&vCore.AddUsersParams{
			Tag:      c.tag,
			NodeInfo: c.info,
			Users:    added,
		})
		if err != nil {
			logx.Node(c.tag).WithError(err).Error("添加用户失败")
			return nil
		}
	}
	if len(added) > 0 || len(deleted) > 0 {
		// update Limiter
		c.limiter.UpdateUser(c.tag, added, deleted)
		if err != nil {
			logx.Node(c.tag).WithError(err).Error("更新限速用户失败")
			return nil
		}
	}
	c.userList = newU
	if len(added)+len(deleted) != 0 {
		logx.Node(c.tag).WithFields(map[string]interface{}{
			"user_deleted": len(deleted),
			"user_added":   len(added),
		}).Info("用户列表已更新")
	}
	return nil
}

func (c *Controller) reportOnlineAndStatus(ctx context.Context, userTraffic []panel.UserTraffic) (err error) {
	if onlineDevice, err := c.limiter.GetOnlineDevice(); err != nil {
		logx.Node(c.tag).WithError(err).Error("获取在线设备失败")
	} else if len(*onlineDevice) > 0 {
		// Only report user has traffic > 100kb to allow ping test
		var result []panel.OnlineUser
		var nocountUID = make(map[int]struct{})
		for _, traffic := range userTraffic {
			total := traffic.Upload + traffic.Download
			if total <= 0 {
				nocountUID[traffic.UID] = struct{}{}
			}
		}
		for _, online := range *onlineDevice {
			if _, ok := nocountUID[online.UID]; !ok {
				result = append(result, online)
			}
		}
		if err = c.apiClient.ReportNodeOnlineUsers(ctx, &result); err != nil {
			logx.Node(c.tag).WithError(err).Error("上报在线用户失败")
		} else {
			logx.Node(c.tag).WithFields(map[string]interface{}{
				"online_total":    len(*onlineDevice),
				"online_reported": len(result),
			}).Info("已上报在线用户")
		}
	}

	CPU, Mem, Disk, Uptime, err := serverstatus.GetSystemInfo()
	if err != nil {
		logx.Node(c.tag).WithError(err).Error("获取系统信息失败")
	}
	err = c.apiClient.ReportNodeStatusContext(ctx,
		&panel.NodeStatus{
			CPU:    CPU,
			Mem:    Mem,
			Disk:   Disk,
			Uptime: Uptime,
		})
	if err != nil {
		logx.Node(c.tag).WithError(err).Error("上报节点状态失败")
	}

	userTraffic = nil
	return nil
}

func compareUserList(old, new []panel.UserInfo) (deleted, added []panel.UserInfo) {
	oldMap := make(map[string]int)
	for i, user := range old {
		key := user.Uuid + strconv.Itoa(user.SpeedLimit)
		oldMap[key] = i
	}

	for _, user := range new {
		key := user.Uuid + strconv.Itoa(user.SpeedLimit)
		if _, exists := oldMap[key]; !exists {
			added = append(added, user)
		} else {
			delete(oldMap, key)
		}
	}

	for _, index := range oldMap {
		deleted = append(deleted, old[index])
	}

	return deleted, added
}
