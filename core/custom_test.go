package core

import (
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
)

func TestGetCustomConfigSkipsEmptyBlockRules(t *testing.T) {
	dns := []panel.DNSItem{}
	block := []string{}
	outbound := []panel.Outbound{}
	protocols := []panel.Protocol{}

	_, _, routeConfig, err := GetCustomConfig(&panel.ServerConfigResponse{
		Data: &panel.Data{
			IPStrategy: "prefer_ipv4",
			DNS:        &dns,
			Block:      &block,
			Outbound:   &outbound,
			Protocols:  &protocols,
		},
	})
	if err != nil {
		t.Fatalf("GetCustomConfig() error = %v", err)
	}

	if got := len(routeConfig.GetRule()); got != 1 {
		t.Fatalf("route rules len = %d, want only default DNS rule", got)
	}
}

func TestBuildRouteDomainsSanitizesRules(t *testing.T) {
	got := buildRouteDomains([]string{
		" suffix:example.com ",
		"",
		"suffix:example.com",
		"keyword:",
		" keyword:google ",
		"plain.example",
	})
	want := []string{"domain:example.com", "google", "full:plain.example"}

	if len(got) != len(want) {
		t.Fatalf("buildRouteDomains() = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("buildRouteDomains()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestGetCustomConfigBuildsTypedOutbound(t *testing.T) {
	dns := []panel.DNSItem{}
	block := []string{}
	outbound := []panel.Outbound{
		{
			Name:      "proxy",
			Protocol:  "vless",
			Address:   "example.com",
			Port:      443,
			UUID:      "00000000-0000-0000-0000-000000000001",
			Security:  "tls",
			SNI:       "example.com",
			Transport: "websocket",
			Host:      "example.com",
			Path:      "/ws",
			Rules:     []string{"suffix:example.com"},
		},
	}
	protocols := []panel.Protocol{}

	_, outbounds, routeConfig, err := GetCustomConfig(&panel.ServerConfigResponse{
		Data: &panel.Data{
			IPStrategy: "prefer_ipv4",
			DNS:        &dns,
			Block:      &block,
			Outbound:   &outbound,
			Protocols:  &protocols,
		},
	})
	if err != nil {
		t.Fatalf("GetCustomConfig() error = %v", err)
	}

	if got := len(outbounds); got != 4 {
		t.Fatalf("outbounds len = %d, want 4", got)
	}
	if got := len(routeConfig.GetRule()); got != 2 {
		t.Fatalf("route rules len = %d, want default DNS + custom outbound", got)
	}
}

func TestGetCustomConfigUsesRawOutboundSettings(t *testing.T) {
	dns := []panel.DNSItem{}
	block := []string{}
	outbound := []panel.Outbound{
		{
			Name:     "direct-cn",
			Protocol: "direct",
			Settings: `{"domainStrategy":"UseIPv4"}`,
			Rules:    []string{"suffix:cn"},
		},
	}
	protocols := []panel.Protocol{}

	_, outbounds, routeConfig, err := GetCustomConfig(&panel.ServerConfigResponse{
		Data: &panel.Data{
			IPStrategy: "prefer_ipv4",
			DNS:        &dns,
			Block:      &block,
			Outbound:   &outbound,
			Protocols:  &protocols,
		},
	})
	if err != nil {
		t.Fatalf("GetCustomConfig() error = %v", err)
	}

	if got := len(outbounds); got != 4 {
		t.Fatalf("outbounds len = %d, want 4", got)
	}
	if got := outbounds[3].Tag; got != "direct-cn" {
		t.Fatalf("custom outbound tag = %q, want direct-cn", got)
	}
	if got := len(routeConfig.GetRule()); got != 2 {
		t.Fatalf("route rules len = %d, want default DNS + custom outbound", got)
	}
}

func TestGetCustomConfigSkipsUnsupportedOutboundWithoutRawSettings(t *testing.T) {
	dns := []panel.DNSItem{}
	block := []string{}
	outbound := []panel.Outbound{
		{
			Name:     "legacy-naive",
			Protocol: "naive",
			Address:  "example.com",
			Port:     443,
			Rules:    []string{"suffix:example.com"},
		},
	}
	protocols := []panel.Protocol{}

	_, outbounds, routeConfig, err := GetCustomConfig(&panel.ServerConfigResponse{
		Data: &panel.Data{
			IPStrategy: "prefer_ipv4",
			DNS:        &dns,
			Block:      &block,
			Outbound:   &outbound,
			Protocols:  &protocols,
		},
	})
	if err != nil {
		t.Fatalf("GetCustomConfig() error = %v", err)
	}

	if got := len(outbounds); got != 3 {
		t.Fatalf("outbounds len = %d, want only default outbounds", got)
	}
	if got := len(routeConfig.GetRule()); got != 1 {
		t.Fatalf("route rules len = %d, want only default DNS rule", got)
	}
}
