package limiter

import (
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/common/format"
)

const (
	testTag  = "test-node"
	testUUID = "test-user"
	testUID  = 1
	testIP   = "198.51.100.1"
)

func newTestLimiter(nodeType string, deviceLimit int, alive int) *Limiter {
	return NewManager().Add(testTag, []panel.UserInfo{{
		Id:          testUID,
		Uuid:        testUUID,
		DeviceLimit: deviceLimit,
	}}, map[int]int{testUID: alive}, nodeType)
}

func TestLimiter_tracks_online_device_when_transport_requires_tracking(t *testing.T) {
	tests := []struct {
		name        string
		nodeType    string
		noUDPSource bool
		wantTracked bool
	}{
		{name: "AnyTLS TCP", nodeType: "anytls", noUDPSource: true, wantTracked: true},
		{name: "Hysteria2 UDP", nodeType: "hysteria2", noUDPSource: false, wantTracked: true},
		{name: "Hysteria UDP alias", nodeType: "hysteria", noUDPSource: false, wantTracked: true},
		{name: "TUIC UDP", nodeType: "tuic", noUDPSource: false, wantTracked: true},
		{name: "Shadowsocks TCP", nodeType: "shadowsocks", noUDPSource: true, wantTracked: true},
		{name: "Shadowsocks UDP", nodeType: "shadowsocks", noUDPSource: false, wantTracked: true},
		{name: "unknown UDP", nodeType: "unknown", noUDPSource: false, wantTracked: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given
			l := newTestLimiter(tt.nodeType, 0, 0)

			// When
			_, rejected := l.CheckLimit(format.UserTag(testTag, testUUID), testIP, tt.noUDPSource)

			// Then
			if rejected {
				t.Fatal("CheckLimit() rejected a known user")
			}
			onlineDevices, err := l.GetOnlineDevice()
			if err != nil {
				t.Fatalf("GetOnlineDevice() error = %v", err)
			}
			if got := len(*onlineDevices) > 0; got != tt.wantTracked {
				t.Errorf("online device tracked = %t, want %t", got, tt.wantTracked)
				return
			}
			if tt.wantTracked && ((*onlineDevices)[0].UID != testUID || (*onlineDevices)[0].IP != testIP) {
				t.Errorf("online device = %+v, want UID %d and IP %s", (*onlineDevices)[0], testUID, testIP)
			}
		})
	}
}

func TestLimiter_rejects_at_capacity_only_when_transport_requires_tracking(t *testing.T) {
	tests := []struct {
		name        string
		nodeType    string
		noUDPSource bool
		wantReject  bool
		wantTracked bool
	}{
		{name: "AnyTLS TCP", nodeType: "anytls", noUDPSource: true, wantReject: true, wantTracked: false},
		{name: "Hysteria2 UDP", nodeType: "hysteria2", noUDPSource: false, wantReject: true, wantTracked: false},
		{name: "Hysteria UDP alias", nodeType: "hysteria", noUDPSource: false, wantReject: true, wantTracked: false},
		{name: "TUIC UDP", nodeType: "tuic", noUDPSource: false, wantReject: true, wantTracked: false},
		{name: "Shadowsocks TCP", nodeType: "shadowsocks", noUDPSource: true, wantReject: true, wantTracked: false},
		{name: "Shadowsocks UDP", nodeType: "shadowsocks", noUDPSource: false, wantReject: true, wantTracked: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given
			l := newTestLimiter(tt.nodeType, 1, 1)

			// When
			_, rejected := l.CheckLimit(format.UserTag(testTag, testUUID), testIP, tt.noUDPSource)

			// Then
			if rejected != tt.wantReject {
				t.Errorf("CheckLimit() rejected = %t, want %t", rejected, tt.wantReject)
			}
			onlineDevices, err := l.GetOnlineDevice()
			if err != nil {
				t.Fatalf("GetOnlineDevice() error = %v", err)
			}
			if got := len(*onlineDevices) > 0; got != tt.wantTracked {
				t.Errorf("online device tracked = %t, want %t", got, tt.wantTracked)
				return
			}
		})
	}
}
