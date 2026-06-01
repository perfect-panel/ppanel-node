package panel

import (
	"fmt"
	"path"
	"time"
)

type NodeInfo struct {
	Id                     int
	Type                   string
	PushInterval           int
	PullInterval           int
	TrafficReportThreshold int
	Protocol               *Protocol
}

type ServerPushStatusRequest struct {
	Cpu                   float64 `json:"cpu"`
	Mem                   float64 `json:"mem"`
	Disk                  float64 `json:"disk"`
	UpdatedAt             int64   `json:"updated_at"`
	CertFingerprintSha256 string  `json:"cert_fingerprint_sha256,omitempty"`
}

type NodeStatus struct {
	CPU                   float64
	Mem                   float64
	Disk                  float64
	Uptime                uint64
	CertFingerprintSha256 string
}

func (c *ClientV1) ReportNodeStatus(nodeStatus *NodeStatus) (err error) {
	p := "/v1/server/status"
	status := ServerPushStatusRequest{
		Cpu:                   nodeStatus.CPU,
		Mem:                   nodeStatus.Mem,
		Disk:                  nodeStatus.Disk,
		UpdatedAt:             time.Now().UnixMilli(),
		CertFingerprintSha256: nodeStatus.CertFingerprintSha256,
	}
	if _, err = c.Client.R().SetBody(status).ForceContentType("application/json").Post(p); err != nil {
		return fmt.Errorf("访问 %s 失败: %v", path.Join(c.APIHost+p), err.Error())
	}
	return nil
}
