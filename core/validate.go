package core

import (
	"fmt"
	"strings"

	"github.com/perfect-panel/ppanel-node/api/panel"
)

func ValidateServerConfig(serverconfig *panel.ServerConfigResponse) error {
	if serverconfig == nil {
		return fmt.Errorf("server config is nil")
	}
	if serverconfig.Data == nil {
		return fmt.Errorf("server config data is nil")
	}
	if serverconfig.Data.Protocols == nil {
		return fmt.Errorf("protocol config is nil")
	}
	for i, protocol := range *serverconfig.Data.Protocols {
		if !panel.IsSupportedProtocol(protocol.Type) {
			continue
		}
		if err := validateProtocol(protocol); err != nil {
			return fmt.Errorf("protocol[%d] %s config invalid: %w", i, protocol.Type, err)
		}
	}
	return nil
}

func validateProtocol(protocol panel.Protocol) error {
	if !protocol.Enable {
		return nil
	}
	if strings.TrimSpace(protocol.Type) == "" {
		return fmt.Errorf("type is required")
	}
	if protocol.Port <= 0 || protocol.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}

	switch protocol.Type {
	case "vless", "vmess", "trojan":
		if err := validateStreamProtocol(protocol); err != nil {
			return err
		}
	case "shadowsocks":
		if strings.TrimSpace(protocol.Cipher) == "" {
			return fmt.Errorf("cipher is required")
		}
		switch strings.ToLower(strings.TrimSpace(protocol.Cipher)) {
		case "none", "plain":
			return fmt.Errorf("Shadowsocks cipher %q is no longer supported by Xray", protocol.Cipher)
		}
	case "tuic", "hysteria", "hysteria2":
		if err := validateTLSConfig(protocol); err != nil {
			return err
		}
	case "anytls":
	}
	return nil
}

func validateStreamProtocol(protocol panel.Protocol) error {
	if strings.TrimSpace(protocol.Transport) == "" {
		return fmt.Errorf("transport is required")
	}
	switch protocol.Transport {
	case "tcp", "ws", "websocket", "grpc", "httpupgrade", "splithttp", "xhttp":
	default:
		return fmt.Errorf("unsupported transport %q", protocol.Transport)
	}

	switch protocol.Security {
	case "", "none":
	case "tls":
		if err := validateTLSConfig(protocol); err != nil {
			return err
		}
	case "reality":
		if strings.TrimSpace(protocol.RealityPrivateKey) == "" {
			return fmt.Errorf("reality_private_key is required")
		}
		if strings.TrimSpace(protocol.RealityShortID) == "" {
			return fmt.Errorf("reality_short_id is required")
		}
		if strings.TrimSpace(protocol.SNI) == "" {
			return fmt.Errorf("sni is required for reality")
		}
		if protocol.RealityServerPort <= 0 || protocol.RealityServerPort > 65535 {
			return fmt.Errorf("reality_server_port must be between 1 and 65535")
		}
	default:
		return fmt.Errorf("unsupported security %q", protocol.Security)
	}

	if protocol.Type == "vless" {
		return validateVlessEncryption(protocol)
	}
	return nil
}

func validateTLSConfig(protocol panel.Protocol) error {
	switch strings.TrimSpace(protocol.CertMode) {
	case "", "none", "file":
		return nil
	case "self", "dns", "http":
		if strings.TrimSpace(protocol.SNI) == "" {
			return fmt.Errorf("sni is required for tls cert_mode %q", protocol.CertMode)
		}
		return nil
	default:
		return fmt.Errorf("unsupported cert_mode %q", protocol.CertMode)
	}
}

func validateVlessEncryption(protocol panel.Protocol) error {
	if protocol.Encryption == "" || protocol.Encryption == "none" {
		return nil
	}
	if protocol.Encryption != "mlkem768x25519plus" {
		return fmt.Errorf("unsupported vless encryption %q", protocol.Encryption)
	}
	if strings.TrimSpace(protocol.EncryptionMode) == "" {
		return fmt.Errorf("encryption_mode is required")
	}
	switch protocol.EncryptionMode {
	case "native", "xorpub", "random":
	default:
		return fmt.Errorf("unsupported encryption_mode %q", protocol.EncryptionMode)
	}
	if strings.TrimSpace(protocol.EncryptionTicket) == "" {
		return fmt.Errorf("encryption_ticket is required")
	}
	if strings.TrimSpace(protocol.EncryptionPrivateKey) == "" {
		return fmt.Errorf("encryption_private_key is required")
	}
	return nil
}
