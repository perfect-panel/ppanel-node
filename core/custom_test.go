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
