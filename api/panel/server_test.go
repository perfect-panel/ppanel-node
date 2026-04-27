package panel

import "testing"

func TestSemanticServerConfigHashNormalizesNonSemanticOrder(t *testing.T) {
	first := &ServerConfigResponse{Data: &Data{
		PushInterval: 60,
		PullInterval: 90,
		DNS: &[]DNSItem{
			{Proto: "udp", Address: "1.1.1.1", Domains: []string{"suffix:example.com", "keyword:google"}},
		},
		Block: &[]string{"suffix:b.example", "suffix:a.example"},
		Outbound: &[]Outbound{
			{Name: "proxy", Protocol: "socks", Address: "127.0.0.1", Port: 1080, Rules: []string{"suffix:b.example", "suffix:a.example"}},
		},
		Protocols: &[]Protocol{
			{Type: "hysteria", Port: 443, Security: "tls"},
			{Type: "vless", Port: 8443, Security: "reality", Transport: "tcp"},
		},
		Total: 2,
	}}
	second := &ServerConfigResponse{Data: &Data{
		PushInterval: 60,
		PullInterval: 90,
		DNS: &[]DNSItem{
			{Proto: "udp", Address: "1.1.1.1", Domains: []string{"keyword:google", "suffix:example.com"}},
		},
		Block: &[]string{"suffix:a.example", "suffix:b.example"},
		Outbound: &[]Outbound{
			{Name: "proxy", Protocol: "socks", Address: "127.0.0.1", Port: 1080, Rules: []string{"suffix:a.example", "suffix:b.example"}},
		},
		Protocols: &[]Protocol{
			{Type: "vless", Port: 8443, Security: "reality", Transport: "tcp"},
			{Type: "hysteria", Port: 443, Security: "tls"},
		},
		Total: 2,
	}}

	firstHash, err := semanticServerConfigHash(first)
	if err != nil {
		t.Fatal(err)
	}
	secondHash, err := semanticServerConfigHash(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstHash != secondHash {
		t.Fatalf("expected semantically equal configs to match: %s != %s", firstHash, secondHash)
	}
}

func TestSemanticServerConfigHashKeepsOutboundOrder(t *testing.T) {
	first := &ServerConfigResponse{Data: &Data{
		Outbound: &[]Outbound{
			{Name: "first", Protocol: "socks", Address: "127.0.0.1", Port: 1080},
			{Name: "second", Protocol: "socks", Address: "127.0.0.2", Port: 1081},
		},
		Protocols: &[]Protocol{},
	}}
	second := &ServerConfigResponse{Data: &Data{
		Outbound: &[]Outbound{
			{Name: "second", Protocol: "socks", Address: "127.0.0.2", Port: 1081},
			{Name: "first", Protocol: "socks", Address: "127.0.0.1", Port: 1080},
		},
		Protocols: &[]Protocol{},
	}}

	firstHash, err := semanticServerConfigHash(first)
	if err != nil {
		t.Fatal(err)
	}
	secondHash, err := semanticServerConfigHash(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstHash == secondHash {
		t.Fatal("expected outbound order changes to remain significant")
	}
}

func TestSemanticServerConfigHashTreatsNilSlicesAsEmpty(t *testing.T) {
	firstHash, err := semanticServerConfigHash(&ServerConfigResponse{Data: &Data{Protocols: &[]Protocol{}}})
	if err != nil {
		t.Fatal(err)
	}
	secondHash, err := semanticServerConfigHash(&ServerConfigResponse{Data: &Data{
		DNS:       &[]DNSItem{},
		Block:     &[]string{},
		Outbound:  &[]Outbound{},
		Protocols: &[]Protocol{},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if firstHash != secondHash {
		t.Fatalf("expected nil and empty slices to match: %s != %s", firstHash, secondHash)
	}
}
