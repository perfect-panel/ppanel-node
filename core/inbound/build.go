package inbound

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/perfect-panel/ppanel-node/api/panel"
	tuiccompat "github.com/perfect-panel/ppanel-node/core/transport/tuic"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

// Build builds Inbound config for different protocol.
func Build(nodeInfo *panel.NodeInfo, tag string) (*core.InboundHandlerConfig, error) {
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
		DestOverride: coreConf.StringList{"http", "tls", "quic"},
	}
	in.SniffingConfig = sniffingConfig

	// Set TLS or Reality settings. TUIC and Hysteria use TLS natively; panel
	// configurations that select a certificate mode must therefore enable the
	// same certificate path even when their generic Security field is omitted.
	if shouldConfigureTLS(nodeInfo) {
		applyTLSSettings(nodeInfo, in)
	}
	if nodeInfo.Protocol.Security == "reality" {
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
			// Explicit zero preserves older clients; empty uses Xray's version floor.
			MinClientVer: "0.0.0",
			//Mldsa65Seed: v.RealityMldsa65Seed,
		}
	}
	in.Tag = tag
	built, err := in.Build()
	if err != nil {
		return nil, err
	}
	if nodeInfo.Type == "tuic" {
		value, err := built.ReceiverSettings.GetInstance()
		if err != nil {
			return nil, err
		}
		receiver := value.(*proxyman.ReceiverConfig)
		receiver.StreamSettings.ProtocolName = tuiccompat.ProtocolName
		built.ReceiverSettings = serial.ToTypedMessage(receiver)
	}
	return built, nil
}

func shouldConfigureTLS(nodeInfo *panel.NodeInfo) bool {
	if nodeInfo == nil || nodeInfo.Protocol == nil {
		return false
	}
	mode := strings.TrimSpace(nodeInfo.Protocol.CertMode)
	if mode == "" || mode == "none" {
		return false
	}
	if nodeInfo.Protocol.Security == "tls" {
		return true
	}
	switch nodeInfo.Type {
	case "tuic", "hysteria", "hysteria2":
		return true
	default:
		return false
	}
}

func applyTLSSettings(nodeInfo *panel.NodeInfo, in *coreConf.InboundDetourConfig) {
	if in.StreamSetting == nil {
		in.StreamSetting = &coreConf.StreamConfig{}
	}
	in.StreamSetting.Security = "tls"
	// Only TLS 1.3 is accepted; the post-quantum hybrid key exchange is
	// preferred, with plain X25519 as the fallback for clients without
	// X25519MLKEM768 support (Go < 1.24 cores, older mobile clients).
	curvePreferences := coreConf.StringList{"X25519MLKEM768", "X25519"}
	in.StreamSetting.TLSSettings = &coreConf.TLSConfig{
		MinVersion:       "1.3",
		CurvePreferences: &curvePreferences,
		Certs: []*coreConf.TLSCertConfig{
			{
				CertFile: filepath.Join("/etc/PPanel-node/", nodeInfo.Type+strconv.Itoa(nodeInfo.Id)+".cer"),
				KeyFile:  filepath.Join("/etc/PPanel-node/", nodeInfo.Type+strconv.Itoa(nodeInfo.Id)+".key"),
			},
		},
	}
	if nodeInfo.Type == "hysteria2" || nodeInfo.Type == "hysteria" {
		alpn := coreConf.StringList{"h3"}
		in.StreamSetting.TLSSettings.ALPN = &alpn
	}
}

func buildTransportSetting(nodeInfo *panel.NodeInfo) (*coreConf.StreamConfig, error) {
	t := coreConf.TransportProtocol(nodeInfo.Protocol.Transport)
	stream := &coreConf.StreamConfig{Network: &t}
	switch nodeInfo.Protocol.Transport {
	case "tcp":
		stream.TCPSettings = &coreConf.TCPConfig{
			AcceptProxyProtocol: nodeInfo.Protocol.AcceptProxyProtocol,
		}
	case "ws", "websocket":
		stream.WSSettings = &coreConf.WebSocketConfig{
			Host:                nodeInfo.Protocol.Host,
			Path:                nodeInfo.Protocol.Path,
			AcceptProxyProtocol: nodeInfo.Protocol.AcceptProxyProtocol,
		}
	case "grpc":
		stream.GRPCSettings = &coreConf.GRPCConfig{
			ServiceName: nodeInfo.Protocol.ServiceName,
		}
	case "httpupgrade":
		stream.HTTPUPGRADESettings = &coreConf.HttpUpgradeConfig{
			Host:                nodeInfo.Protocol.Host,
			Path:                nodeInfo.Protocol.Path,
			AcceptProxyProtocol: nodeInfo.Protocol.AcceptProxyProtocol,
		}
	case "splithttp", "xhttp":
		stream.SplitHTTPSettings = &coreConf.SplitHTTPConfig{
			Host: nodeInfo.Protocol.Host,
			Path: nodeInfo.Protocol.Path,
			Mode: nodeInfo.Protocol.XHTTPMode,
		}
		if nodeInfo.Protocol.XHTTPExtra != "" {
			stream.SplitHTTPSettings.Extra = json.RawMessage(nodeInfo.Protocol.XHTTPExtra)
		}
	default:
		return nil, errors.New("the network type is not vail")
	}
	return stream, nil
}
