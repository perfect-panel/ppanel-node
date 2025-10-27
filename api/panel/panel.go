package panel

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/go-resty/resty/v2"
	"github.com/perfect-panel/ppanel-node/conf"
)

type ClientV1 struct {
	Client    *resty.Client
	APIHost   string
	SecretKey string
	NodeType  string
	NodeId    int
	userEtag  string
	UserList  *UserListBody
	AliveMap  *AliveMap
}

type ClientV2 struct {
	Client           *resty.Client
	APIHost          string
	SecretKey        string
	ServerId         int
	ServerConfigEtag string
	responseBodyHash string
}

func NewClientV1(c *conf.NodeApiConfig) (*ClientV1, error) {
	client := resty.New()
	client.SetRetryCount(0)
	if c.Timeout > 0 {
		client.SetTimeout(time.Duration(c.Timeout) * time.Second)
	} else {
		client.SetTimeout(30 * time.Second)
	}
	client.OnError(func(req *resty.Request, err error) {
		var v *resty.ResponseError
		if errors.As(err, &v) {
			logrus.Error(v.Err)
		}
	})
	client.SetBaseURL(c.APIHost)
	// Check node type
	c.NodeType = strings.ToLower(c.NodeType)
	switch c.NodeType {
	case
		"vmess",
		"trojan",
		"shadowsocks",
		"tuic",
		"hysteria",
		"hysteria2",
		"anytls",
		"vless":
	default:
		return nil, fmt.Errorf("unsupported Node type: %s", c.NodeType)
	}
	// set params
	client.SetQueryParams(map[string]string{
		"protocol":   c.NodeType,
		"server_id":  strconv.Itoa(c.NodeID),
		"secret_key": c.SecretKey,
	})
	return &ClientV1{
		Client:    client,
		SecretKey: c.SecretKey,
		APIHost:   c.APIHost,
		NodeType:  c.NodeType,
		NodeId:    c.NodeID,
		UserList:  &UserListBody{},
		AliveMap:  &AliveMap{},
	}, nil
}

func NewClientV2(c *conf.ServerApiConfig) *ClientV2 {
	client := resty.New()
	client.SetRetryCount(0)
	if c.Timeout > 0 {
		client.SetTimeout(time.Duration(c.Timeout) * time.Second)
	} else {
		client.SetTimeout(30 * time.Second)
	}
	client.OnError(func(req *resty.Request, err error) {
		var v *resty.ResponseError
		if errors.As(err, &v) {
			logrus.Error(v.Err)
		}
	})
	client.SetBaseURL(c.ApiHost)
	client.SetQueryParams(map[string]string{
		"secret_key": c.SecretKey,
	})
	return &ClientV2{
		Client:    client,
		APIHost:   c.ApiHost,
		SecretKey: c.SecretKey,
		ServerId:  c.ServerId,
	}
}
