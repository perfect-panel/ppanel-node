package core

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

func (v *XrayCore) removeInbound(tag string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return v.ihm.RemoveHandler(ctx, tag)
}

func (v *XrayCore) addInbound(config *core.InboundHandlerConfig) error {
	rawHandler, err := core.CreateObject(v.Server, config)
	if err != nil {
		return err
	}
	handler, ok := rawHandler.(inbound.Handler)
	if !ok {
		return fmt.Errorf("not an InboundHandler: %s", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := v.ihm.AddHandler(ctx, handler); err != nil {
		return err
	}
	return nil
}

// BuildInbound build Inbound config for different protocol
func buildInbound(nodeInfo *panel.NodeInfo, tag string) (*core.InboundHandlerConfig, error) {
	in := &coreConf.InboundDetourConfig{}
	var err error
	switch nodeInfo.Type {
	case "vless":
		err = buildVLess(nodeInfo, in)
	case "vmess":
		err = buildVMess(nodeInfo, in)
	case "trojan":
		err = buildTrojan(nodeInfo, in)
	case "shadowsocks":
		err = buildShadowsocks(nodeInfo, in)
	case "hysteria2", "hysteria":
		err = buildHysteria2(nodeInfo, in)
	case "tuic":
		err = buildTuic(nodeInfo, in)
	case "anytls":
		err = buildAnyTLS(nodeInfo, in)
	default:
		return nil, fmt.Errorf("unsupported node type: %s", nodeInfo.Type)
	}
	if err != nil {
		return nil, err
	}
	// Set network protocol
	// Set server port
	in.PortList = &coreConf.PortList{
		Range: []coreConf.PortRange{
			{
				From: uint32(nodeInfo.Protocol.Port),
				To:   uint32(nodeInfo.Protocol.Port),
			}},
	}
	// Set Listen IP address
	ipAddress := net.ParseAddress("0.0.0.0")
	in.ListenOn = &coreConf.Address{Address: ipAddress}
	// Set SniffingConfig
	sniffingConfig := &coreConf.SniffingConfig{
		Enabled:      true,
		DestOverride: &coreConf.StringList{"http", "tls"},
	}
	in.SniffingConfig = sniffingConfig

	// Set TLS or Reality settings
	switch nodeInfo.Protocol.Security {
	case "tls":
		switch nodeInfo.Protocol.CertMode {
		case "none", "":
			break
		default:
			if in.StreamSetting == nil {
				in.StreamSetting = &coreConf.StreamConfig{}
			}
			in.StreamSetting.Security = "tls"
			in.StreamSetting.TLSSettings = &coreConf.TLSConfig{
				Certs: []*coreConf.TLSCertConfig{
					{
						CertFile: filepath.Join("/etc/PPanel-node/", nodeInfo.Type+strconv.Itoa(nodeInfo.Id)+".cer"),
						KeyFile:  filepath.Join("/etc/PPanel-node/", nodeInfo.Type+strconv.Itoa(nodeInfo.Id)+".key"),
					},
				},
			}
		}
	case "reality":
		if in.StreamSetting == nil {
			in.StreamSetting = &coreConf.StreamConfig{}
		}
		in.StreamSetting.Security = "reality"
		v := nodeInfo.Protocol
		add := v.RealityServerAddr
		if add == "" {
			add = v.SNI
		}
		d, err := json.Marshal(fmt.Sprintf(
			"%s:%d",
			add,
			v.RealityServerPort))
		if err != nil {
			return nil, fmt.Errorf("marshal reality dest error: %s", err)
		}
		in.StreamSetting.REALITYSettings = &coreConf.REALITYConfig{
			Dest:        d,
			Xver:        uint64(0),
			Show:        false,
			ServerNames: []string{v.SNI},
			PrivateKey:  v.RealityPrivateKey,
			ShortIds:    []string{v.RealityShortID},
			//Mldsa65Seed: v.RealityMldsa65Seed,
		}
	default:
		break
	}
	in.Tag = tag
	return in.Build()
}

func buildVLess(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "vless"
	var err error
	decryption := "none"
	if nodeInfo.Protocol.Encryption != "" && nodeInfo.Protocol.Encryption != "none" {
		switch nodeInfo.Protocol.Encryption {
		case "mlkem768x25519plus":
			parts := []string{
				"mlkem768x25519plus",
				nodeInfo.Protocol.EncryptionMode,
				nodeInfo.Protocol.EncryptionTicket + "s",
			}
			if nodeInfo.Protocol.EncryptionServerPadding != "" {
				parts = append(parts, nodeInfo.Protocol.EncryptionServerPadding)
			}
			parts = append(parts, nodeInfo.Protocol.EncryptionPrivateKey)
			decryption = strings.Join(parts, ".")
		default:
			return fmt.Errorf("vless decryption method %s is not support", nodeInfo.Protocol.Encryption)
		}
	}
	s, err := json.Marshal(&coreConf.VLessInboundConfig{
		Decryption: decryption,
	})
	if err != nil {
		return fmt.Errorf("marshal vless config error: %s", err)
	}
	inbound.Settings = (*json.RawMessage)(&s)
	t := coreConf.TransportProtocol(nodeInfo.Protocol.Transport)
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	switch nodeInfo.Protocol.Transport {
	case "tcp":
		inbound.StreamSetting.TCPSettings = &coreConf.TCPConfig{}
	case "ws", "websocket":
		inbound.StreamSetting.WSSettings = &coreConf.WebSocketConfig{
			Host: nodeInfo.Protocol.Host,
			Path: nodeInfo.Protocol.Path,
		}
	case "grpc":
		inbound.StreamSetting.GRPCSettings = &coreConf.GRPCConfig{
			ServiceName: nodeInfo.Protocol.ServiceName,
		}
	/*case "mkcp":
	inbound.StreamSetting.KCPSettings = &coreConf.KCPConfig{
	}*/
	case "httpupgrade":
		inbound.StreamSetting.HTTPUPGRADESettings = &coreConf.HttpUpgradeConfig{
			Host: nodeInfo.Protocol.Host,
			Path: nodeInfo.Protocol.Path,
		}
	case "splithttp", "xhttp":
		inbound.StreamSetting.SplitHTTPSettings = &coreConf.SplitHTTPConfig{
			Host: nodeInfo.Protocol.Host,
			Path: nodeInfo.Protocol.Path,
			Mode: nodeInfo.Protocol.XHTTPMode,
			//Extra: json.RawMessage(nodeInfo.Protocol.XHTTPExtra),
		}
	default:
		return errors.New("the network type is not vail")
	}
	return nil
}

func buildVMess(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "vmess"
	var err error
	s, err := json.Marshal(&coreConf.VMessInboundConfig{})
	if err != nil {
		return fmt.Errorf("marshal vmess settings error: %s", err)
	}
	inbound.Settings = (*json.RawMessage)(&s)
	t := coreConf.TransportProtocol(nodeInfo.Protocol.Transport)
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	switch nodeInfo.Protocol.Transport {
	case "tcp":
		inbound.StreamSetting.TCPSettings = &coreConf.TCPConfig{}
	case "ws", "websocket":
		inbound.StreamSetting.WSSettings = &coreConf.WebSocketConfig{
			Host: nodeInfo.Protocol.Host,
			Path: nodeInfo.Protocol.Path,
		}
	case "grpc":
		inbound.StreamSetting.GRPCSettings = &coreConf.GRPCConfig{
			ServiceName: nodeInfo.Protocol.ServiceName,
		}
	/*case "mkcp":
	inbound.StreamSetting.KCPSettings = &coreConf.KCPConfig{
	}*/
	case "httpupgrade":
		inbound.StreamSetting.HTTPUPGRADESettings = &coreConf.HttpUpgradeConfig{
			Host: nodeInfo.Protocol.Host,
			Path: nodeInfo.Protocol.Path,
		}
	case "splithttp", "xhttp":
		inbound.StreamSetting.SplitHTTPSettings = &coreConf.SplitHTTPConfig{
			Host: nodeInfo.Protocol.Host,
			Path: nodeInfo.Protocol.Path,
			Mode: nodeInfo.Protocol.XHTTPMode,
			//Extra: json.RawMessage(nodeInfo.Protocol.XHTTPExtra),
		}
	default:
		return errors.New("the network type is not vail")
	}
	return nil
}

func buildTrojan(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "trojan"
	s, err := json.Marshal(&coreConf.TrojanServerConfig{})
	if err != nil {
		return fmt.Errorf("marshal trojan settings error: %s", err)
	}
	inbound.Settings = (*json.RawMessage)(&s)
	network := nodeInfo.Protocol.Transport
	t := coreConf.TransportProtocol(network)
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	switch network {
	case "tcp":
		inbound.StreamSetting.TCPSettings = &coreConf.TCPConfig{}
	case "ws", "websocket":
		inbound.StreamSetting.WSSettings = &coreConf.WebSocketConfig{
			Host: nodeInfo.Protocol.Host,
			Path: nodeInfo.Protocol.Path,
		}
	case "grpc":
		inbound.StreamSetting.GRPCSettings = &coreConf.GRPCConfig{
			ServiceName: nodeInfo.Protocol.ServiceName,
		}
	default:
		return errors.New("the network type is not vail")
	}
	return nil
}

func buildShadowsocks(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "shadowsocks"
	cipher := nodeInfo.Protocol.Cipher
	settings := &coreConf.ShadowsocksServerConfig{
		Cipher: cipher,
	}
	p := make([]byte, 32)
	_, err := rand.Read(p)
	if err != nil {
		return fmt.Errorf("generate random password error: %s", err)
	}
	randomPasswd := hex.EncodeToString(p)

	if nodeInfo.Protocol.ServerKey != "" && strings.Contains(cipher, "2022") {
		nodeInfo.Protocol.ServerKey = base64.StdEncoding.EncodeToString([]byte(nodeInfo.Protocol.ServerKey))
		settings.Password = nodeInfo.Protocol.ServerKey
		randomPasswd = base64.StdEncoding.EncodeToString([]byte(randomPasswd))
		cipher = ""
	}
	defaultSSuser := &coreConf.ShadowsocksUserConfig{
		Cipher:   cipher,
		Password: randomPasswd,
	}
	settings.Users = append(settings.Users, defaultSSuser)
	settings.NetworkList = &coreConf.NetworkList{"tcp", "udp"}
	settings.IVCheck = true

	if nodeInfo.Protocol.Obfs != "" && nodeInfo.Protocol.Obfs == "http" {
		if nodeInfo.Protocol.ObfsPath != "" || nodeInfo.Protocol.ObfsHost != "" {
			settings.NetworkList = &coreConf.NetworkList{"tcp"}
		}
		t := coreConf.TransportProtocol("tcp")
		inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
		inbound.StreamSetting.TCPSettings = &coreConf.TCPConfig{}
		//inbound.StreamSetting.TCPSettings.AcceptProxyProtocol = false

		httpHeader := map[string]interface{}{
			"type":    "http",
			"request": map[string]interface{}{},
		}
		request := httpHeader["request"].(map[string]interface{})

		path := nodeInfo.Protocol.ObfsPath
		if path == "" {
			path = "/"
		}
		request["path"] = []string{path}

		if nodeInfo.Protocol.ObfsHost != "" {
			request["headers"] = map[string]interface{}{
				"Host": []string{nodeInfo.Protocol.ObfsHost},
			}
		}
		headerJSON, err := json.Marshal(httpHeader)
		if err == nil {
			inbound.StreamSetting.TCPSettings.HeaderConfig = json.RawMessage(headerJSON)
		}
	}

	sets, err := json.Marshal(settings)
	inbound.Settings = (*json.RawMessage)(&sets)
	if err != nil {
		return fmt.Errorf("marshal shadowsocks settings error: %s", err)
	}
	return nil
}

func buildHysteria2(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "hysteria2"
	up := nodeInfo.Protocol.UpMbps
	down := nodeInfo.Protocol.DownMbps
	ignore := false
	if up == 0 && down == 0 {
		ignore = true
	}
	obfs := nodeInfo.Protocol.Obfs
	obfs_password := nodeInfo.Protocol.ObfsPassword
	if obfs != "" {
		if obfs == "none" {
			obfs = ""
			obfs_password = ""
		}
	}
	settings := &coreConf.Hysteria2ServerConfig{
		UpMbps:                uint64(up),
		DownMbps:              uint64(down),
		IgnoreClientBandwidth: ignore,
		Obfs: &coreConf.Hysteria2ObfsConfig{
			Type:     obfs,
			Password: obfs_password,
		},
	}

	t := coreConf.TransportProtocol("hysteria2")
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}

	sets, err := json.Marshal(settings)
	inbound.Settings = (*json.RawMessage)(&sets)
	if err != nil {
		return fmt.Errorf("marshal hysteria2 settings error: %s", err)
	}
	return nil
}

func buildTuic(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "tuic"
	settings := &coreConf.TuicServerConfig{
		CongestionControl: nodeInfo.Protocol.CongestionController,
		ZeroRttHandshake:  nodeInfo.Protocol.ReduceRTT,
	}
	t := coreConf.TransportProtocol("tuic")
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	sets, err := json.Marshal(settings)
	inbound.Settings = (*json.RawMessage)(&sets)
	if err != nil {
		return fmt.Errorf("marshal tuic settings error: %s", err)
	}
	return nil
}

func buildAnyTLS(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "anytls"
	var padding []string
	//nodeInfo.Protocol.PaddingScheme "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000"
	if nodeInfo.Protocol.PaddingScheme != "" {
		padding = strings.Split(nodeInfo.Protocol.PaddingScheme, "\n")
	}
	settings := &coreConf.AnyTLSServerConfig{
		PaddingScheme: padding,
	}
	t := coreConf.TransportProtocol("tcp")
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	sets, err := json.Marshal(settings)
	inbound.Settings = (*json.RawMessage)(&sets)
	if err != nil {
		return fmt.Errorf("marshal anytls settings error: %s", err)
	}
	return nil
}
