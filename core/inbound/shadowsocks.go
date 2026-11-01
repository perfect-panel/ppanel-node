package inbound

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/perfect-panel/ppanel-node/api/panel"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

func buildShadowsocks(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "shadowsocks"
	cipher := nodeInfo.Protocol.Cipher
	settings := &coreConf.ShadowsocksServerConfig{
		Cipher: cipher,
	}
	keyLength := 32
	if cipher == "2022-blake3-aes-128-gcm" {
		keyLength = 16
	}
	p := make([]byte, keyLength)
	_, err := rand.Read(p)
	if err != nil {
		return fmt.Errorf("generate random password error: %s", err)
	}
	randomPasswd := hex.EncodeToString(p)

	if nodeInfo.Protocol.ServerKey != "" && strings.Contains(cipher, "2022") {
		settings.Password = base64.StdEncoding.EncodeToString([]byte(nodeInfo.Protocol.ServerKey))
		// SS2022 now validates every user's decoded key length, including the
		// placeholder that selects the multi-user inbound before users load.
		randomPasswd = base64.StdEncoding.EncodeToString(p)
		cipher = ""
	}
	defaultSSuser := &coreConf.ShadowsocksUserConfig{
		Cipher:   cipher,
		Password: randomPasswd,
	}
	settings.Users = append(settings.Users, defaultSSuser)
	settings.NetworkList = &coreConf.NetworkList{"tcp", "udp"}

	if nodeInfo.Protocol.Obfs != "" && nodeInfo.Protocol.Obfs == "http" {
		if nodeInfo.Protocol.ObfsPath != "" || nodeInfo.Protocol.ObfsHost != "" {
			settings.NetworkList = &coreConf.NetworkList{"tcp"}
		}
		t := coreConf.TransportProtocol("tcp")
		inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
		inbound.StreamSetting.TCPSettings = &coreConf.TCPConfig{
			AcceptProxyProtocol: nodeInfo.Protocol.AcceptProxyProtocol,
		}

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
