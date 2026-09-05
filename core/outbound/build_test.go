package outbound

import (
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
)

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

func TestBuildBuildsTypedOutbound(t *testing.T) {
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

	result, err := Build(&panel.ServerConfigResponse{
		Data: &panel.Data{
			IPStrategy: "prefer_ipv4",
			DNS:        &dns,
			Block:      &block,
			Outbound:   &outbound,
			Protocols:  &protocols,
		},
	}, false)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if got := len(result.Outbounds); got != 4 {
		t.Fatalf("outbounds len = %d, want 4", got)
	}
	if got := len(result.Router.GetRule()); got != 2 {
		t.Fatalf("route rules len = %d, want default DNS + custom outbound", got)
	}
}

func TestBuildUsesRawOutboundSettings(t *testing.T) {
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

	result, err := Build(&panel.ServerConfigResponse{
		Data: &panel.Data{
			IPStrategy: "prefer_ipv4",
			DNS:        &dns,
			Block:      &block,
			Outbound:   &outbound,
			Protocols:  &protocols,
		},
	}, false)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if got := len(result.Outbounds); got != 4 {
		t.Fatalf("outbounds len = %d, want 4", got)
	}
	if got := result.Outbounds[3].Tag; got != "direct-cn" {
		t.Fatalf("custom outbound tag = %q, want direct-cn", got)
	}
	if got := len(result.Router.GetRule()); got != 2 {
		t.Fatalf("route rules len = %d, want default DNS + custom outbound", got)
	}
}

func TestBuildSkipsUnsupportedOutboundWithoutRawSettings(t *testing.T) {
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

	result, err := Build(&panel.ServerConfigResponse{
		Data: &panel.Data{
			IPStrategy: "prefer_ipv4",
			DNS:        &dns,
			Block:      &block,
			Outbound:   &outbound,
			Protocols:  &protocols,
		},
	}, false)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if got := len(result.Outbounds); got != 3 {
		t.Fatalf("outbounds len = %d, want only default outbounds", got)
	}
	if got := len(result.Router.GetRule()); got != 1 {
		t.Fatalf("route rules len = %d, want only default DNS rule", got)
	}
}

func TestTUICOutboundUsesID(t *testing.T) {
	item := panel.Outbound{Name: "tuic", Protocol: "tuic", Address: "example.com", Port: 443, UUID: "00000000-0000-0000-0000-000000000001", Password: "password"}
	result, err := Build(&panel.ServerConfigResponse{Data: &panel.Data{Protocols: &[]panel.Protocol{}, Outbound: &[]panel.Outbound{item}}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Outbounds) != 4 {
		t.Fatal("TUIC outbound was silently dropped")
	}
}

func TestInvalidOutboundIsNotSilentlyDropped(t *testing.T) {
	item := panel.Outbound{Name: "invalid-tls", Protocol: "vless", Address: "example.com", Port: 443, UUID: "00000000-0000-0000-0000-000000000001", Security: "tls", AllowInsecure: true}
	_, err := Build(&panel.ServerConfigResponse{Data: &panel.Data{Protocols: &[]panel.Protocol{}, Outbound: &[]panel.Outbound{item}}}, false)
	if err == nil {
		t.Fatal("removed allowInsecure setting was silently accepted")
	}
}

func TestHysteria2OutboundUsesTransportAuthentication(t *testing.T) {
	stream, err := buildOutboundStreamConfig(panel.Outbound{Protocol: "hysteria2", UUID: "user-id", Password: "auth-token"})
	if err != nil {
		t.Fatal(err)
	}
	if stream.HysteriaSettings == nil || stream.HysteriaSettings.Version != 2 || stream.HysteriaSettings.Auth != "auth-token" {
		t.Fatalf("Hysteria settings = %+v", stream.HysteriaSettings)
	}
}
