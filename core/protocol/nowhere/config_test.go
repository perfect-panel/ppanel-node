package nowhere

import (
	"net/netip"
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
)

func TestValidateNW3PanelContract(t *testing.T) {
	valid := panel.Protocol{Type: "nowhere", Version: 3, Port: 2077, Security: "tls", SNI: "nw.example", CertMode: "self", Network: "mix", ALPN: []string{"nw3"}, Obfs: "morph"}
	if err := ValidateProtocol(valid); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*panel.Protocol){
		"old version":          func(p *panel.Protocol) { p.Version = 1 },
		"old alpn":             func(p *panel.Protocol) { p.ALPN = []string{"now/1"} },
		"no tls":               func(p *panel.Protocol) { p.Security = "none" },
		"no certificate":       func(p *panel.Protocol) { p.CertMode = "none" },
		"unrecognized network": func(p *panel.Protocol) { p.Network = "ws" },
		"unknown morph":        func(p *panel.Protocol) { p.Obfs = "custom" },
		"alternate credential": func(p *panel.Protocol) { p.ServerKey = "key" },
	} {
		t.Run(name, func(t *testing.T) {
			p := valid
			edit(&p)
			if err := ValidateProtocol(p); err == nil {
				t.Fatal("unsupported contract accepted")
			}
		})
	}
	for _, network := range []string{"", "tcp", "udp", "quic", "mix", "mixed", "tcp,udp"} {
		p := valid
		p.Network = network
		p.ALPN = nil
		p.Obfs = "none"
		if err := ValidateProtocol(p); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHandshakeBudgetsAreSharedAndIdempotentlyReleased(t *testing.T) {
	h := &Handler{handshakeIPs: make(map[netip.Addr]int)}
	ip := netip.MustParseAddr("127.0.0.1")
	var releases []func()
	for range 32 {
		release, ok := h.acquireHandshake(ip)
		if !ok {
			t.Fatal("early rejection")
		}
		releases = append(releases, release)
	}
	if release, ok := h.acquireHandshake(ip); ok {
		release()
		t.Fatal("per-source budget exceeded")
	}
	for _, release := range releases {
		release()
		release()
	}
	if h.handshakes != 0 || len(h.handshakeIPs) != 0 {
		t.Fatal("handshake reservations leaked")
	}
}
