package core

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/router"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

// hasPublicIPv6 checks if the machine has a public IPv6 address
func hasPublicIPv6() bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP
		// Check if it's IPv6, not loopback, not link-local, not private/ULA
		if ip.To4() == nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsPrivate() {
			return true
		}
	}
	return false
}

func hasOutboundWithTag(list []*core.OutboundHandlerConfig, tag string) bool {
	for _, o := range list {
		if o != nil && o.Tag == tag {
			return true
		}
	}
	return false
}

func buildRouteDomains(rules []string) []string {
	domains := make([]string, 0, len(rules))
	seen := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		rule = strings.TrimSpace(rule)
		if rule == "" {
			continue
		}

		value := ""
		data := strings.SplitN(rule, ":", 2)
		if len(data) == 2 {
			data[0] = strings.TrimSpace(data[0])
			data[1] = strings.TrimSpace(data[1])
			if data[1] == "" {
				continue
			}
			switch data[0] {
			case "keyword":
				value = data[1]
			case "suffix":
				value = "domain:" + data[1]
			case "regex":
				value = "regexp:" + data[1]
			default:
				value = data[1]
			}
		} else {
			value = "full:" + rule
		}

		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		domains = append(domains, value)
	}
	return domains
}

func normalizeOutboundProtocol(protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "direct":
		return "freedom"
	case "reject", "block":
		return "blackhole"
	default:
		return strings.ToLower(strings.TrimSpace(protocol))
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func rawJSONMessage(value string, field string) (*json.RawMessage, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	if !json.Valid([]byte(value)) {
		return nil, fmt.Errorf("invalid outbound %s json", field)
	}
	raw := json.RawMessage(value)
	return &raw, nil
}

func buildOutboundSettings(item panel.Outbound) (string, *json.RawMessage, error) {
	protocol := normalizeOutboundProtocol(item.Protocol)
	if raw, err := rawJSONMessage(item.Settings, "settings"); err != nil || raw != nil {
		return protocol, raw, err
	}

	settings := map[string]interface{}{}
	switch protocol {
	case "freedom", "blackhole":
	case "http", "socks":
		settings["address"] = strings.TrimSpace(item.Address)
		settings["port"] = item.Port
		if strings.TrimSpace(item.User) != "" {
			settings["user"] = strings.TrimSpace(item.User)
			settings["pass"] = item.Password
		}
	case "shadowsocks":
		settings["address"] = strings.TrimSpace(item.Address)
		settings["port"] = item.Port
		settings["method"] = firstNonEmpty(item.Cipher, "chacha20-ietf-poly1305")
		settings["password"] = item.Password
		settings["uot"] = true
		if item.UoT {
			settings["uot"] = item.UoT
		}
		uotVersion := item.UoTVersion
		if uotVersion == 0 {
			uotVersion = 2
		}
		settings["uotVersion"] = uotVersion
	case "trojan":
		settings["address"] = strings.TrimSpace(item.Address)
		settings["port"] = item.Port
		settings["password"] = item.Password
	case "vmess":
		settings["address"] = strings.TrimSpace(item.Address)
		settings["port"] = item.Port
		settings["id"] = firstNonEmpty(item.UUID, item.Password)
		settings["security"] = firstNonEmpty(item.Cipher, "auto")
	case "vless":
		settings["address"] = strings.TrimSpace(item.Address)
		settings["port"] = item.Port
		settings["id"] = firstNonEmpty(item.UUID, item.Password)
		settings["encryption"] = "none"
		if flow := strings.TrimSpace(item.Flow); flow != "" && flow != "none" {
			settings["flow"] = flow
		}
	case "anytls":
		settings["address"] = strings.TrimSpace(item.Address)
		settings["port"] = item.Port
		settings["password"] = item.Password
	case "tuic":
		settings["address"] = strings.TrimSpace(item.Address)
		settings["port"] = item.Port
		settings["uuid"] = firstNonEmpty(item.UUID, item.Password)
		settings["password"] = item.Password
		if congestion := strings.TrimSpace(item.CongestionController); congestion != "" {
			settings["congestionControl"] = congestion
		}
		settings["udpStream"] = item.UDPStream
		settings["zeroRttHandshake"] = item.ReduceRTT
		if item.Heartbeat > 0 {
			settings["heartbeat"] = item.Heartbeat
		}
	case "hysteria":
		settings["version"] = 2
		settings["address"] = strings.TrimSpace(item.Address)
		settings["port"] = item.Port
	case "wireguard":
		return "", nil, nil
	default:
		return "", nil, nil
	}

	data, err := json.Marshal(settings)
	if err != nil {
		return "", nil, err
	}
	raw := json.RawMessage(data)
	return protocol, &raw, nil
}

func buildOutboundStreamConfig(item panel.Outbound) (*coreConf.StreamConfig, error) {
	if raw := strings.TrimSpace(item.StreamSettings); raw != "" {
		var stream coreConf.StreamConfig
		if err := json.Unmarshal([]byte(raw), &stream); err != nil {
			return nil, fmt.Errorf("invalid outbound stream_settings json: %w", err)
		}
		return &stream, nil
	}

	protocol := normalizeOutboundProtocol(item.Protocol)
	transport := strings.ToLower(strings.TrimSpace(item.Transport))
	if transport == "" {
		switch protocol {
		case "vmess", "vless", "trojan", "anytls":
			transport = "tcp"
		case "tuic":
			transport = "tuic"
		case "hysteria":
			transport = "hysteria"
		}
	}
	security := strings.ToLower(strings.TrimSpace(item.Security))
	hasStreamField := transport != "" ||
		security != "" ||
		strings.TrimSpace(item.SNI) != "" ||
		strings.TrimSpace(item.Fingerprint) != "" ||
		strings.TrimSpace(item.Host) != "" ||
		strings.TrimSpace(item.Path) != "" ||
		strings.TrimSpace(item.ServiceName) != "" ||
		strings.TrimSpace(item.RealityPublicKey) != "" ||
		strings.TrimSpace(item.RealityShortID) != ""
	if !hasStreamField {
		return nil, nil
	}

	stream := &coreConf.StreamConfig{Security: security}
	if transport != "" {
		t := coreConf.TransportProtocol(transport)
		stream.Network = &t
	}
	switch security {
	case "", "none":
	case "tls":
		stream.TLSSettings = &coreConf.TLSConfig{
			ServerName:    strings.TrimSpace(item.SNI),
			AllowInsecure: item.AllowInsecure,
			Fingerprint:   firstNonEmpty(item.Fingerprint, "chrome"),
		}
	case "reality":
		stream.REALITYSettings = &coreConf.REALITYConfig{
			ServerName:  strings.TrimSpace(item.SNI),
			PublicKey:   strings.TrimSpace(item.RealityPublicKey),
			ShortId:     strings.TrimSpace(item.RealityShortID),
			Fingerprint: firstNonEmpty(item.Fingerprint, "chrome"),
			SpiderX:     firstNonEmpty(item.SpiderX, "/"),
		}
	default:
		return nil, fmt.Errorf("unsupported outbound security %q", item.Security)
	}

	switch transport {
	case "", "tcp", "raw":
		if transport != "" {
			stream.TCPSettings = &coreConf.TCPConfig{}
		}
	case "ws", "websocket":
		stream.WSSettings = &coreConf.WebSocketConfig{
			Host: strings.TrimSpace(item.Host),
			Path: strings.TrimSpace(item.Path),
		}
	case "grpc":
		stream.GRPCSettings = &coreConf.GRPCConfig{
			Authority:   strings.TrimSpace(item.Host),
			ServiceName: strings.TrimSpace(item.ServiceName),
		}
	case "httpupgrade":
		stream.HTTPUPGRADESettings = &coreConf.HttpUpgradeConfig{
			Host: strings.TrimSpace(item.Host),
			Path: strings.TrimSpace(item.Path),
		}
	case "splithttp", "xhttp":
		stream.SplitHTTPSettings = &coreConf.SplitHTTPConfig{
			Host: strings.TrimSpace(item.Host),
			Path: strings.TrimSpace(item.Path),
		}
	case "tuic", "hysteria":
	default:
		return nil, fmt.Errorf("unsupported outbound transport %q", item.Transport)
	}

	return stream, nil
}

func GetCustomConfig(serverconfig *panel.ServerConfigResponse) (*dns.Config, []*core.OutboundHandlerConfig, *router.Config, error) {
	var ip_strategy string
	if serverconfig.Data.IPStrategy != "" {
		switch serverconfig.Data.IPStrategy {
		case "prefer_ipv4":
			ip_strategy = "UseIPv4v6"
		case "prefer_ipv6":
			ip_strategy = "UseIPv6v4"
		default:
			ip_strategy = "UseIPv4v6"
		}
	} else {
		if hasPublicIPv6() {
			ip_strategy = "UseIPv4v6"
		} else {
			ip_strategy = "UseIPv4"
		}
	}
	dnsConfig := serverconfig.Data.DNS
	blockList := serverconfig.Data.Block
	outboundList := serverconfig.Data.Outbound

	//default dns
	queryStrategy := "UseIPv4v6"
	if !hasPublicIPv6() {
		queryStrategy = "UseIPv4"
	}
	coreDnsConfig := &coreConf.DNSConfig{
		Servers: []*coreConf.NameServerConfig{
			{
				Address: &coreConf.Address{
					Address: xnet.ParseAddress("localhost"),
				},
			},
		},
		QueryStrategy: queryStrategy,
	}

	//custom dns
	if dnsConfig != nil {
		for _, item := range *dnsConfig {
			var domains []string
			for _, domainitem := range item.Domains {
				data := strings.Split(domainitem, ":")
				if len(data) == 2 {
					switch data[0] {
					case "keyword":
						domains = append(domains, data[1])
					case "suffix":
						domains = append(domains, "domain:"+data[1])
					case "regex":
						domains = append(domains, "regexp:"+data[1])
					default:
						domains = append(domains, data[1])
					}
				} else {
					domains = append(domains, "full:"+domainitem)
				}
			}
			/*switch item.Proto {
			case "udp":
				item.Address = item.Address
			case "tcp":
				item.Address = "tcp://" + item.Address
			case "tls":
				item.Address = "tls://" + item.Address
			case "https":
				item.Address = "https://" + item.Address
			case "quic":
				item.Address = "quic://" + item.Address
			}*/
			server := &coreConf.NameServerConfig{
				Address: &coreConf.Address{
					Address: xnet.ParseAddress(item.Address),
				},
				QueryStrategy: ip_strategy,
				Domains:       domains,
			}
			coreDnsConfig.Servers = append(coreDnsConfig.Servers, server)
		}
	}

	//default outbound
	defaultoutbound, _ := buildDefaultOutbound()
	coreOutboundConfig := append([]*core.OutboundHandlerConfig{}, defaultoutbound)
	block, _ := buildBlockOutbound()
	coreOutboundConfig = append(coreOutboundConfig, block)
	dns, _ := buildDnsOutbound()
	coreOutboundConfig = append(coreOutboundConfig, dns)

	//default route
	domainStrategy := "AsIs"
	dnsRule, _ := json.Marshal(map[string]interface{}{
		"port":        "53",
		"network":     "udp",
		"outboundTag": "dns_out",
	})
	coreRouterConfig := &coreConf.RouterConfig{
		RuleList:       []json.RawMessage{dnsRule},
		DomainStrategy: &domainStrategy,
	}

	//custom block
	if blockList != nil {
		domains := buildRouteDomains(*blockList)
		if len(domains) > 0 {
			rule := map[string]interface{}{
				"domain":      domains,
				"outboundTag": "block",
			}
			rawRule, err := json.Marshal(rule)
			if err == nil {
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
			}
		}
	}

	//custom outbound
	if outboundList != nil {
		for _, outbounditem := range *outboundList {
			protocol, rawSettings, err := buildOutboundSettings(outbounditem)
			if err != nil {
				return nil, nil, nil, err
			}
			if protocol == "" || rawSettings == nil {
				continue
			}
			streamSettings, err := buildOutboundStreamConfig(outbounditem)
			if err != nil {
				return nil, nil, nil, err
			}
			outbound := &coreConf.OutboundDetourConfig{
				Tag:           outbounditem.Name,
				Protocol:      protocol,
				Settings:      rawSettings,
				StreamSetting: streamSettings,
			}
			// Outbound rules
			domains := buildRouteDomains(outbounditem.Rules)
			custom_outbound, err := outbound.Build()
			if err != nil {
				continue
			}
			if len(domains) > 0 {
				rule := map[string]interface{}{
					"domain":      domains,
					"outboundTag": custom_outbound.Tag,
				}
				rawRule, err := json.Marshal(rule)
				if err == nil {
					coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
				}
			}
			if hasOutboundWithTag(coreOutboundConfig, custom_outbound.Tag) {
				continue
			}
			coreOutboundConfig = append(coreOutboundConfig, custom_outbound)
		}
	}
	//build config
	DnsConfig, err := coreDnsConfig.Build()
	if err != nil {
		return nil, nil, nil, err
	}
	RouterConfig, err := coreRouterConfig.Build()
	if err != nil {
		return nil, nil, nil, err
	}
	return DnsConfig, coreOutboundConfig, RouterConfig, nil
}
