// Copyright (C) 2026 PPanel contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// Package nowhere adapts the NW3 portal to Xray's public inbound and
// dispatcher interfaces. It owns its TLS/QUIC listeners without Xray workers.
package nowhere

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"

	nw "github.com/perfect-panel/nowhere"
	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/xtls/xray-core/app/proxyman"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	xray "github.com/xtls/xray-core/core"
	"google.golang.org/protobuf/proto"
)

const (
	NetworkTCP uint32 = 1 << iota
	NetworkQUIC
	NetworkMixed = NetworkTCP | NetworkQUIC
	ALPN         = "nw3"
)

func ValidateProtocol(p panel.Protocol) error {
	if p.Type != "nowhere" || p.Port < 1 || p.Port > 65535 {
		return errors.New("nowhere: invalid protocol or port")
	}
	if p.Version != 0 && p.Version != 3 {
		return errors.New("nowhere requires NW3; older wire versions are unsupported")
	}
	if p.Security != "tls" || p.SNI == "" || p.CertMode == "" || p.CertMode == "none" {
		return errors.New("nowhere requires TLS and a certificate")
	}
	switch p.CertMode {
	case "self", "file", "dns", "http":
	default:
		return errors.New("nowhere: unsupported certificate mode")
	}
	if _, err := parseNetwork(p.Network); err != nil {
		return err
	}
	if len(p.ALPN) > 1 || len(p.ALPN) == 1 && p.ALPN[0] != ALPN {
		return errors.New("nowhere requires nw3 ALPN")
	}
	if p.Obfs != "" && p.Obfs != "morph" && p.Obfs != "none" {
		return errors.New("nowhere supports morph or none obfuscation")
	}
	if p.Mode != "" || p.Transport != "" || p.Cipher != "" || p.ServerKey != "" || p.AllowInsecure || p.Fingerprint != "" ||
		p.RealityServerAddr != "" || p.RealityServerPort != 0 || p.RealityPrivateKey != "" || p.RealityPublicKey != "" || p.RealityShortID != "" ||
		p.Host != "" || p.Path != "" || p.ServiceName != "" || p.Flow != "" || p.AcceptProxyProtocol || p.UoT || p.UoTVersion != 0 ||
		p.HopPorts != "" || p.HopInterval != 0 || p.ObfsPassword != "" || p.DisableSNI || p.ReduceRTT || p.UDPRelayMode != "" ||
		p.CongestionController != "" || p.Multiplex != "" || p.PaddingScheme != "" || p.UpMbps != 0 || p.DownMbps != 0 ||
		p.ObfsHost != "" || p.ObfsPath != "" || p.XHTTPMode != "" || p.XHTTPExtra != "" || p.Encryption != "" ||
		p.EncryptionMode != "" || p.EncryptionRTT != "" || p.EncryptionTicket != "" || p.EncryptionServerPadding != "" ||
		p.EncryptionPrivateKey != "" || p.EncryptionClientPadding != "" || p.EncryptionPassword != "" {
		return errors.New("nowhere: unsupported protocol options")
	}
	return nil
}

func parseNetwork(value string) (uint32, error) {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), " ", "")) {
	case "", "mix", "mixed", "tcp,udp", "udp,tcp":
		return NetworkMixed, nil
	case "tcp":
		return NetworkTCP, nil
	case "udp", "quic":
		return NetworkQUIC, nil
	default:
		return 0, fmt.Errorf("nowhere: unsupported network %q", value)
	}
}

// Build bypasses Xray's fixed JSON protocol-name table using our own protobuf
// configuration. Certificate validation happens before a running node is stopped.
func Build(info *panel.NodeInfo, tag string) (*xray.InboundHandlerConfig, error) {
	if info == nil || info.Protocol == nil {
		return nil, errors.New("nowhere: missing protocol")
	}
	p := *info.Protocol
	if err := ValidateProtocol(p); err != nil {
		return nil, err
	}
	network, _ := parseNetwork(p.Network)
	base := filepath.Join("/etc/PPanel-node", "nowhere"+strconv.Itoa(info.Id))
	cfg := &Config{Listen: net.JoinHostPort("0.0.0.0", strconv.Itoa(p.Port)), Network: network, CertificateFile: base + ".cer", KeyFile: base + ".key", Morph: p.Obfs != "none", Alpn: ALPN}
	if _, err := loadTLS(cfg); err != nil {
		return nil, err
	}
	return &xray.InboundHandlerConfig{Tag: tag,
		ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{Listen: xnet.NewIPOrDomain(xnet.AnyIP)}),
		ProxySettings:    serial.ToTypedMessage(cfg)}, nil
}

func loadTLS(c *Config) (*tls.Config, error) {
	if c.Alpn != ALPN || c.Network == 0 || c.Network & ^uint32(NetworkMixed) != 0 {
		return nil, errors.New("nowhere: invalid carrier configuration")
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return nil, fmt.Errorf("nowhere listen: %w", err)
	}
	pair, err := tls.LoadX509KeyPair(c.CertificateFile, c.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("nowhere certificate: %w", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{pair}, NextProtos: []string{ALPN}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519}}, nil
}

type memoryAccount struct{ key string }

func (a *Account) AsAccount() (protocol.Account, error) {
	if !nw.ValidSharedKey([]byte(a.Key)) {
		return nil, nw.ErrInvalidSharedKey
	}
	return &memoryAccount{key: a.Key}, nil
}
func (a *memoryAccount) Equals(other protocol.Account) bool {
	b, ok := other.(*memoryAccount)
	return ok && a.key == b.key
}
func (a *memoryAccount) ToProto() proto.Message { return &Account{Key: a.key} }
