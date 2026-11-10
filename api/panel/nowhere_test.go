package panel

import (
	"testing"

	serverv1 "github.com/perfect-panel/ppanel-node/api/server/v1"
)

func TestNowhereProtobufKeepsWireAndCarrierOptions(t *testing.T) {
	message := &serverv1.QueryServerProtocolConfigResponse{Code: 200, Data: &serverv1.QueryServerProtocolConfigData{Protocols: []*serverv1.ServerProtocol{{Type: "nowhere", Port: 2077, Enable: true, Version: 3, Network: "mix", Alpn: []string{"nw3"}, Security: "tls", Sni: "nw.example", CertMode: "self", Obfs: "none"}}}}
	result := serverConfigResponseFromProtobuf(message)
	p := (*result.Data.Protocols)[0]
	if !IsSupportedProtocol(p.Type) || p.Version != 3 || p.Network != "mix" || len(p.ALPN) != 1 || p.ALPN[0] != "nw3" || p.Obfs != "none" {
		t.Fatalf("dropped NW3 fields: %+v", p)
	}
}
