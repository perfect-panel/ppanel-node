package inbound

import (
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

func TestShouldConfigureTLSForNativeProtocols(t *testing.T) {
	tests := []struct {
		name string
		info panel.NodeInfo
		want bool
	}{
		{
			name: "TUIC managed certificate without generic security field",
			info: panel.NodeInfo{Type: "tuic", Protocol: &panel.Protocol{CertMode: "dns"}},
			want: true,
		},
		{
			name: "Hysteria local certificate",
			info: panel.NodeInfo{Type: "hysteria", Protocol: &panel.Protocol{CertMode: "file"}},
			want: true,
		},
		{
			name: "no certificate mode",
			info: panel.NodeInfo{Type: "tuic", Protocol: &panel.Protocol{CertMode: "none"}},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldConfigureTLS(&tt.info); got != tt.want {
				t.Fatalf("shouldConfigureTLS() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestApplyTLSSettingsEnforcesModernTLS(t *testing.T) {
	in := &coreConf.InboundDetourConfig{}
	applyTLSSettings(&panel.NodeInfo{
		Id:       1,
		Type:     "trojan",
		Protocol: &panel.Protocol{Security: "tls", CertMode: "self"},
	}, in)

	tlsSettings := in.StreamSetting.TLSSettings
	if in.StreamSetting.Security != "tls" || tlsSettings == nil {
		t.Fatalf("applyTLSSettings() did not configure TLS: %+v", in.StreamSetting)
	}
	if tlsSettings.MinVersion != "1.3" {
		t.Fatalf("MinVersion = %q, want %q", tlsSettings.MinVersion, "1.3")
	}
	if tlsSettings.CurvePreferences == nil {
		t.Fatal("CurvePreferences is nil, want [X25519MLKEM768 X25519]")
	}
	if curves := *tlsSettings.CurvePreferences; len(curves) != 2 || curves[0] != "X25519MLKEM768" || curves[1] != "X25519" {
		t.Fatalf("CurvePreferences = %v, want [X25519MLKEM768 X25519]", curves)
	}
}

func TestApplyTLSSettingsSetsHysteriaALPN(t *testing.T) {
	in := &coreConf.InboundDetourConfig{}
	applyTLSSettings(&panel.NodeInfo{
		Id:       2,
		Type:     "hysteria2",
		Protocol: &panel.Protocol{CertMode: "dns"},
	}, in)

	alpn := in.StreamSetting.TLSSettings.ALPN
	if alpn == nil || len(*alpn) != 1 || (*alpn)[0] != "h3" {
		t.Fatalf("ALPN = %v, want [h3]", alpn)
	}
}
