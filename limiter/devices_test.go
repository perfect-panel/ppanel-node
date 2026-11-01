package limiter

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/common/format"
)

func TestDeviceConnectionsUseOneSlotAndStopHeartbeatsAfterClose(t *testing.T) {
	l := NewManager().Add("test", []panel.UserInfo{{Id: 21, Uuid: "user", DeviceLimit: 1}}, nil, "vless")
	var claims atomic.Int32
	l.SetDeviceAdmission(func(_ context.Context, id int, ip string) (bool, time.Duration, error) {
		claims.Add(1)
		return ip == "127.0.0.1", time.Minute, nil
	})
	tag := format.UserTag("test", "user")
	_, close1, rejected := l.Acquire(t.Context(), tag, "127.0.0.1")
	if rejected {
		t.Fatal("first device rejected")
	}
	_, close2, rejected := l.Acquire(t.Context(), tag, "::ffff:127.0.0.1")
	if rejected || claims.Load() != 1 {
		t.Fatal("same mapped IP used another slot")
	}
	if _, _, rejected := l.Acquire(t.Context(), tag, "127.0.0.2"); !rejected {
		t.Fatal("second device admitted")
	}
	for range 2 {
		online, _ := l.GetOnlineDevice()
		if len(*online) != 1 {
			t.Fatalf("active snapshot: %v", online)
		}
		l.OnlineReportAcknowledged(*online, time.Now())
	}
	close1()
	close1()
	online, _ := l.GetOnlineDevice()
	if len(*online) != 1 {
		t.Fatal("one close removed another active connection")
	}
	close2()
	online, _ = l.GetOnlineDevice()
	if len(*online) != 0 {
		t.Fatal("closed device kept renewing its lease")
	}
}

func TestConcurrentLocalDeviceAdmissionAndUserIsolation(t *testing.T) {
	users := []panel.UserInfo{{Id: 1, Uuid: "one", DeviceLimit: 1}, {Id: 2, Uuid: "two", DeviceLimit: 1}}
	l := NewManager().Add("test", users, nil, "shadowsocks")
	var count atomic.Int32
	var wg sync.WaitGroup
	for _, ip := range []string{"127.0.0.1", "127.0.0.2"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, rejected := l.Acquire(t.Context(), format.UserTag("test", "one"), ip); !rejected {
				count.Add(1)
			}
		}()
	}
	wg.Wait()
	if count.Load() != 1 {
		t.Fatalf("local admission overshot limit: %d", count.Load())
	}
	if _, _, rejected := l.Acquire(t.Context(), format.UserTag("test", "two"), "127.0.0.1"); rejected {
		t.Fatal("another user's IP occupied this user's slot")
	}
}

func TestDevicePanelFailureAndRevocationDuringClaim(t *testing.T) {
	user := panel.UserInfo{Id: 21, Uuid: "user", DeviceLimit: 1}
	l := NewManager().Add("test", []panel.UserInfo{user}, nil, "tuic")
	tag := format.UserTag("test", user.Uuid)
	l.SetDeviceAdmission(func(context.Context, int, string) (bool, time.Duration, error) {
		return false, 0, errors.New("panel down")
	})
	if _, _, rejected := l.Acquire(t.Context(), tag, "127.0.0.1"); !rejected {
		t.Fatal("panel failure admitted new limited device")
	}
	l.SetDeviceAdmission(func(context.Context, int, string) (bool, time.Duration, error) {
		l.UpdateUser("test", nil, []panel.UserInfo{user})
		return true, time.Minute, nil
	})
	if _, _, rejected := l.Acquire(t.Context(), tag, "127.0.0.1"); !rejected {
		t.Fatal("revoked user admitted after in-flight claim")
	}
}

func TestShortConnectionsReportOnceAndCancellationReleases(t *testing.T) {
	l := NewManager().Add("test", []panel.UserInfo{{Id: 1, Uuid: "user"}}, nil, "vless")
	ctx, cancel := context.WithCancel(t.Context())
	_, closeConn, rejected := l.Acquire(ctx, format.UserTag("test", "user"), "127.0.0.1")
	if rejected {
		t.Fatal("unlimited user rejected")
	}
	cancel()
	closeConn()
	online, _ := l.GetOnlineDevice()
	if len(*online) != 1 {
		t.Fatal("short connection was never reported")
	}
	l.OnlineReportAcknowledged(*online, time.Now())
	online, _ = l.GetOnlineDevice()
	if len(*online) != 0 {
		t.Fatal("closed connection remained active")
	}
}

func TestEnablingDeviceLimitRequiresClaimForUnreportedIP(t *testing.T) {
	user := panel.UserInfo{Id: 21, Uuid: "user"}
	l := NewManager().Add("test", []panel.UserInfo{user}, nil, "vless")
	tag := format.UserTag("test", user.Uuid)
	_, closeConn, rejected := l.Acquire(t.Context(), tag, "127.0.0.1")
	if rejected {
		t.Fatal("unlimited user rejected")
	}
	closeConn()
	next := user
	next.DeviceLimit = 1
	l.UpdateUser("test", []panel.UserInfo{next}, []panel.UserInfo{user})
	l.SetDeviceAdmission(func(context.Context, int, string) (bool, time.Duration, error) { return false, time.Minute, nil })
	if _, _, rejected := l.Acquire(t.Context(), tag, "127.0.0.1"); !rejected {
		t.Fatal("previously unlimited, unreported IP bypassed new limit")
	}
}
