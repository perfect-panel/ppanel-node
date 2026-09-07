package inbound

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/transport/internet/reality"
)

func TestBuildRealityOverridesDefaultMinimumClientVersion(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config, err := Build(&panel.NodeInfo{
		Id:   1,
		Type: "vless",
		Protocol: &panel.Protocol{
			Port:              443,
			Transport:         "tcp",
			Security:          "reality",
			SNI:               "example.com",
			RealityServerPort: 443,
			RealityPrivateKey: base64.RawURLEncoding.EncodeToString(key.Bytes()),
			RealityShortID:    "0123456789abcdef",
		},
	}, "reality-test")
	if err != nil {
		t.Fatal(err)
	}
	value, err := config.ReceiverSettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	receiver := value.(*proxyman.ReceiverConfig)
	security, err := receiver.StreamSettings.GetEffectiveSecuritySettings()
	if err != nil {
		t.Fatal(err)
	}
	runtimeConfig := security.(*reality.Config).GetREALITYConfig()
	if !bytes.Equal(runtimeConfig.MinClientVer, []byte{0, 0, 0}) {
		t.Fatalf("runtime MinClientVer = %v, want explicit 0.0.0", runtimeConfig.MinClientVer)
	}
}
