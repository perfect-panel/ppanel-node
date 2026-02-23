package core

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
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

// mergeOutboundList merges local outbound configs with server-side outbound configs.
// Local configs take higher priority: if a local outbound has the same Name as a
// server-side one, the local version is used (overrides the server-side).
// Non-conflicting outbounds from both sides are all preserved.
func mergeOutboundList(serverList *[]panel.Outbound, localList []conf.OutboundConfig) []panel.Outbound {
	var merged []panel.Outbound
	seen := make(map[string]bool)

	// Local config outbounds first (higher priority, can override server-side)
	for _, item := range localList {
		merged = append(merged, panel.Outbound{
			Name:             item.Name,
			Protocol:         item.Protocol,
			Address:          item.Address,
			Port:             item.Port,
			User:             item.User,
			Password:         item.Password,
			Method:           item.Method,
			Flow:             item.Flow,
			Security:         item.Security,
			Encryption:       item.Encryption,
			SNI:              item.SNI,
			Insecure:         item.Insecure,
			Fingerprint:      item.Fingerprint,
			RealityPublicKey: item.RealityPublicKey,
			RealityShortId:   item.RealityShortId,
			RealitySpiderX:   item.RealitySpiderX,
			WgSecretKey:      item.WgSecretKey,
			WgPublicKey:      item.WgPublicKey,
			WgPreSharedKey:   item.WgPreSharedKey,
			WgAddress:        item.WgAddress,
			WgMTU:            item.WgMTU,
			WgKeepAlive:      item.WgKeepAlive,
			WgReserved:       item.WgReserved,
			Rules:            item.Rules,
		})
		seen[item.Name] = true
	}

	// Server-side outbounds second (skipped if already defined locally)
	if serverList != nil {
		for _, item := range *serverList {
			if seen[item.Name] {
				continue
			}
			merged = append(merged, item)
			seen[item.Name] = true
		}
	}

	return merged
}

// parseDomainRules converts rule strings (keyword:xxx, suffix:xxx, regex:xxx, geosite:xxx, geoip:xxx, or plain) to Xray domain format.
func parseDomainRules(rules []string) []string {
	var domains []string
	for _, item := range rules {
		data := strings.Split(item, ":")
		if len(data) == 2 {
			switch data[0] {
			case "keyword":
				domains = append(domains, data[1])
			case "suffix":
				domains = append(domains, "domain:"+data[1])
			case "regex":
				domains = append(domains, "regexp:"+data[1])
			case "geosite", "geoip":
				domains = append(domains, item)
			default:
				domains = append(domains, data[1])
			}
		} else {
			domains = append(domains, "full:"+item)
		}
	}
	return domains
}

func GetCustomConfig(serverconfig *panel.ServerConfigResponse, localOutbound []conf.OutboundConfig, defaultOutboundTag string) (*dns.Config, []*core.OutboundHandlerConfig, *router.Config, error) {
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

	// Merge server-side and local outbound lists
	mergedOutboundList := mergeOutboundList(serverconfig.Data.Outbound, localOutbound)

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
			domains := parseDomainRules(item.Domains)
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
	var defaultoutbound *core.OutboundHandlerConfig
	var err error

	// Check if user specified a custom default outbound
	if defaultOutboundTag != "" {
		// User wants to use a custom outbound as default
		// We'll set it later after building all outbounds
		defaultoutbound = nil
	} else {
		// Use standard freedom outbound as default
		defaultoutbound, err = buildDefaultOutbound()
		if err != nil {
			return nil, nil, nil, err
		}
	}

	coreOutboundConfig := []*core.OutboundHandlerConfig{}
	if defaultoutbound != nil {
		coreOutboundConfig = append(coreOutboundConfig, defaultoutbound)
	}
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
		domains := parseDomainRules(*blockList)
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

	//custom outbound (merged: server-side + local config)
	for _, outbounditem := range mergedOutboundList {
		jsonsettings := map[string]interface{}{
			"address": outbounditem.Address,
			"port":    outbounditem.Port,
		}
		streamSettings := &coreConf.StreamConfig{}
		switch outbounditem.Protocol {
		case "http":
			if outbounditem.User != "" {
				jsonsettings["user"] = outbounditem.User
			}
			if outbounditem.Password != "" {
				jsonsettings["pass"] = outbounditem.Password
			}
		case "socks":
			if outbounditem.User != "" {
				jsonsettings["user"] = outbounditem.User
			}
			if outbounditem.Password != "" {
				jsonsettings["pass"] = outbounditem.Password
			}
		case "shadowsocks":
			if outbounditem.Method != "" {
				jsonsettings["method"] = outbounditem.Method
			}
			jsonsettings["password"] = outbounditem.Password
			jsonsettings["uot"] = true
			jsonsettings["uotVersion"] = 2
		case "trojan":
			jsonsettings["password"] = outbounditem.Password
			if outbounditem.Flow != "" {
				jsonsettings["flow"] = outbounditem.Flow
			}
			proto := coreConf.TransportProtocol("tcp")
			streamSettings.Network = &proto
			if outbounditem.Security == "reality" {
				streamSettings.Security = "reality"
				realityConfig := &coreConf.REALITYConfig{}
				if outbounditem.SNI != "" {
					realityConfig.ServerName = outbounditem.SNI
				}
				if outbounditem.RealityPublicKey != "" {
					realityConfig.PublicKey = outbounditem.RealityPublicKey
				}
				if outbounditem.RealityShortId != "" {
					realityConfig.ShortId = outbounditem.RealityShortId
				}
				if outbounditem.RealitySpiderX != "" {
					realityConfig.SpiderX = outbounditem.RealitySpiderX
				}
				if outbounditem.Fingerprint != "" {
					realityConfig.Fingerprint = outbounditem.Fingerprint
				}
				streamSettings.REALITYSettings = realityConfig
			} else {
				streamSettings.Security = "tls"
				tlsConfig := &coreConf.TLSConfig{}
				if outbounditem.SNI != "" {
					tlsConfig.ServerName = outbounditem.SNI
				}
				if outbounditem.Insecure {
					tlsConfig.Insecure = true
				}
				if outbounditem.Fingerprint != "" {
					tlsConfig.Fingerprint = outbounditem.Fingerprint
				}
				streamSettings.TLSSettings = tlsConfig
			}
		case "vmess":
			jsonsettings["id"] = outbounditem.Password
			if outbounditem.Security != "" && outbounditem.Security != "tls" && outbounditem.Security != "reality" {
				jsonsettings["security"] = outbounditem.Security
			}
			proto := coreConf.TransportProtocol("tcp")
			streamSettings.Network = &proto
			if outbounditem.Security == "reality" {
				streamSettings.Security = "reality"
				realityConfig := &coreConf.REALITYConfig{}
				if outbounditem.SNI != "" {
					realityConfig.ServerName = outbounditem.SNI
				}
				if outbounditem.RealityPublicKey != "" {
					realityConfig.PublicKey = outbounditem.RealityPublicKey
				}
				if outbounditem.RealityShortId != "" {
					realityConfig.ShortId = outbounditem.RealityShortId
				}
				if outbounditem.RealitySpiderX != "" {
					realityConfig.SpiderX = outbounditem.RealitySpiderX
				}
				if outbounditem.Fingerprint != "" {
					realityConfig.Fingerprint = outbounditem.Fingerprint
				}
				streamSettings.REALITYSettings = realityConfig
			} else if outbounditem.Security == "tls" {
				streamSettings.Security = "tls"
				tlsConfig := &coreConf.TLSConfig{}
				if outbounditem.SNI != "" {
					tlsConfig.ServerName = outbounditem.SNI
				}
				if outbounditem.Insecure {
					tlsConfig.Insecure = true
				}
				if outbounditem.Fingerprint != "" {
					tlsConfig.Fingerprint = outbounditem.Fingerprint
				}
				streamSettings.TLSSettings = tlsConfig
			}
		case "vless":
			jsonsettings["id"] = outbounditem.Password
			if outbounditem.Encryption != "" {
				jsonsettings["encryption"] = outbounditem.Encryption
			} else {
				jsonsettings["encryption"] = "none"
			}
			if outbounditem.Flow != "" {
				jsonsettings["flow"] = outbounditem.Flow
			}
			proto := coreConf.TransportProtocol("tcp")
			streamSettings.Network = &proto
			if outbounditem.Security == "reality" {
				streamSettings.Security = "reality"
				realityConfig := &coreConf.REALITYConfig{}
				if outbounditem.SNI != "" {
					realityConfig.ServerName = outbounditem.SNI
				}
				if outbounditem.RealityPublicKey != "" {
					realityConfig.PublicKey = outbounditem.RealityPublicKey
				}
				if outbounditem.RealityShortId != "" {
					realityConfig.ShortId = outbounditem.RealityShortId
				}
				if outbounditem.RealitySpiderX != "" {
					realityConfig.SpiderX = outbounditem.RealitySpiderX
				}
				if outbounditem.Fingerprint != "" {
					realityConfig.Fingerprint = outbounditem.Fingerprint
				}
				streamSettings.REALITYSettings = realityConfig
			} else if outbounditem.Security == "tls" {
				streamSettings.Security = "tls"
				tlsConfig := &coreConf.TLSConfig{}
				if outbounditem.SNI != "" {
					tlsConfig.ServerName = outbounditem.SNI
				}
				if outbounditem.Insecure {
					tlsConfig.Insecure = true
				}
				if outbounditem.Fingerprint != "" {
					tlsConfig.Fingerprint = outbounditem.Fingerprint
				}
				streamSettings.TLSSettings = tlsConfig
			}
		case "wireguard":
			// WireGuard doesn't use address/port in jsonsettings
			jsonsettings = map[string]interface{}{}
			if outbounditem.WgSecretKey != "" {
				jsonsettings["secretKey"] = outbounditem.WgSecretKey
			}
			if len(outbounditem.WgAddress) > 0 {
				jsonsettings["address"] = outbounditem.WgAddress
			}
			if outbounditem.WgMTU > 0 {
				jsonsettings["mtu"] = outbounditem.WgMTU
			}
			if len(outbounditem.WgReserved) > 0 {
				// Convert []int to []byte
				reserved := make([]byte, len(outbounditem.WgReserved))
				for i, v := range outbounditem.WgReserved {
					reserved[i] = byte(v)
				}
				jsonsettings["reserved"] = reserved
			}
			// Build peer configuration
			peer := map[string]interface{}{
				"publicKey": outbounditem.WgPublicKey,
				"endpoint":  fmt.Sprintf("%s:%d", outbounditem.Address, outbounditem.Port),
			}
			if outbounditem.WgPreSharedKey != "" {
				peer["preSharedKey"] = outbounditem.WgPreSharedKey
			}
			if outbounditem.WgKeepAlive > 0 {
				peer["keepAlive"] = outbounditem.WgKeepAlive
			}
			jsonsettings["peers"] = []interface{}{peer}
		default:
			continue
		}

		settings, _ := json.Marshal(jsonsettings)
		rawSettings := json.RawMessage(settings)
		outbound := &coreConf.OutboundDetourConfig{
			Tag:           outbounditem.Name,
			Protocol:      outbounditem.Protocol,
			Settings:      &rawSettings,
			StreamSetting: streamSettings,
		}
		// Outbound rules
		domains := parseDomainRules(outbounditem.Rules)
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

	// If user specified a custom default outbound, find it and set as "Default"
	if defaultOutboundTag != "" {
		foundDefault := false
		for _, outbound := range coreOutboundConfig {
			if outbound.Tag == defaultOutboundTag {
				// Change the tag to "Default" so it becomes the default outbound
				outbound.Tag = "Default"
				foundDefault = true
				break
			}
		}

		// If specified default outbound not found, create a freedom outbound as fallback
		if !foundDefault {
			fallbackDefault, err := buildDefaultOutbound()
			if err == nil {
				coreOutboundConfig = append([]*core.OutboundHandlerConfig{fallbackDefault}, coreOutboundConfig...)
			}
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
