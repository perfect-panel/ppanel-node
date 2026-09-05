package panel

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/perfect-panel/ppanel-node/common/logx"
	"github.com/perfect-panel/ppanel-node/conf"
)

const CertificateSHA256Header = "X-Node-Certificate-SHA256"

type NodeClient struct {
	Client      *resty.Client
	APIHost     string
	SecretKey   string
	NodeType    string
	NodeId      int
	UseProtobuf bool
	userEtag    string
	UserList    *UserListBody
	AliveMap    *AliveMap
}

type ServerClient struct {
	Client           *resty.Client
	APIHost          string
	SecretKey        string
	ServerId         int
	ServerConfigEtag string
	responseBodyHash string
	UseProtobuf      bool
}

func NewNodeClient(c *conf.NodeApiConfig) (*NodeClient, error) {
	client := resty.New()
	client.SetRetryCount(0)
	if c.Timeout > 0 {
		client.SetTimeout(time.Duration(c.Timeout) * time.Second)
	} else {
		client.SetTimeout(30 * time.Second)
	}
	client.OnError(func(req *resty.Request, err error) {
		if v, ok := errors.AsType[*resty.ResponseError](err); ok {
			logx.Component("panel").WithError(v.Err).Error("面板请求失败")
		}
	})
	client.SetBaseURL(c.APIHost)
	// Check node type
	c.NodeType = strings.ToLower(c.NodeType)
	if !IsSupportedProtocol(c.NodeType) {
		return nil, fmt.Errorf("unsupported Node type: %s", c.NodeType)
	}
	// set params
	client.SetQueryParams(map[string]string{
		"protocol":   c.NodeType,
		"server_id":  strconv.Itoa(c.NodeID),
		"secret_key": c.SecretKey,
	})
	return &NodeClient{
		Client:      client,
		SecretKey:   c.SecretKey,
		APIHost:     c.APIHost,
		NodeType:    c.NodeType,
		NodeId:      c.NodeID,
		UseProtobuf: c.UseProtobuf,
		UserList:    &UserListBody{},
		AliveMap:    &AliveMap{},
	}, nil
}

// SetCertificateSHA256 attaches the normalized certificate fingerprint to all
// subsequent requests made by this node client. The fingerprint is set only
// for self-signed nodes by the node controller.
func (c *NodeClient) SetCertificateSHA256(fingerprint string) {
	if c == nil || c.Client == nil {
		return
	}
	fingerprint = strings.ToLower(strings.TrimSpace(fingerprint))
	if fingerprint == "" {
		c.Client.Header.Del(CertificateSHA256Header)
		return
	}
	c.Client.SetHeader(CertificateSHA256Header, fingerprint)
}

func NewServerClient(c *conf.ServerApiConfig) *ServerClient {
	client := resty.New()
	client.SetRetryCount(0)
	if c.Timeout > 0 {
		client.SetTimeout(time.Duration(c.Timeout) * time.Second)
	} else {
		client.SetTimeout(30 * time.Second)
	}
	client.OnError(func(req *resty.Request, err error) {
		if v, ok := errors.AsType[*resty.ResponseError](err); ok {
			logx.Component("panel").WithError(v.Err).Error("面板请求失败")
		}
	})
	client.SetBaseURL(c.ApiHost)
	client.SetQueryParams(map[string]string{
		"secret_key": c.SecretKey,
	})
	return &ServerClient{
		Client:    client,
		APIHost:   c.ApiHost,
		SecretKey: c.SecretKey,
		ServerId:  c.ServerId,
	}
}

// IsSupportedProtocol reports whether this node binary can consume and run a
// server protocol. PPanel may return more protocol types than a node release
// supports; callers use this to leave unsupported configurations untouched.
func IsSupportedProtocol(protocol string) bool {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "vmess", "trojan", "shadowsocks", "tuic", "hysteria", "hysteria2", "anytls", "vless":
		return true
	default:
		return false
	}
}
