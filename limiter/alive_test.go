package limiter

import (
	"sync"
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/common/format"
)

func TestUpdatingDeviceLimitPreservesAliveCount(t *testing.T) {
	old := panel.UserInfo{Id: 1, Uuid: "device-limit-user", DeviceLimit: 2}
	l := NewManager().Add("test", []panel.UserInfo{old}, map[int]int{1: 1}, "vless")
	next := old
	next.DeviceLimit = 1
	l.UpdateUser("test", []panel.UserInfo{next}, []panel.UserInfo{old})
	if _, rejected := l.CheckLimit(format.UserTag("test", next.Uuid), "127.0.0.1", true); !rejected {
		t.Fatal("lowered device limit lost the online count and admitted another device")
	}
}

func TestAliveListOwnsItsSnapshots(t *testing.T) {
	user := panel.UserInfo{Id: 1, Uuid: "snapshot-user", DeviceLimit: 1}
	initial := map[int]int{1: 1}
	l := NewManager().Add("test", []panel.UserInfo{user}, initial, "vless")
	tag := format.UserTag("test", user.Uuid)
	initial[1] = 0
	if _, rejected := l.CheckLimit(tag, "127.0.0.1", true); !rejected {
		t.Fatal("changing the caller's initial map changed the limiter")
	}
	next := map[int]int{1: 0}
	l.UpdateAliveList(next)
	next[1] = 1
	if _, rejected := l.CheckLimit(tag, "127.0.0.2", true); rejected {
		t.Fatal("changing the caller's refreshed map changed the limiter")
	}
	l.UpdateAliveList(map[int]int{1: 1})
	l.UpdateAliveList(nil)
	// Remove the local device as well: an empty remote snapshot must not
	// otherwise let another IP bypass a still-active local device.
	l.UpdateUser("test", nil, []panel.UserInfo{user})
	l.UpdateUser("test", []panel.UserInfo{user}, nil)
	if _, rejected := l.CheckLimit(tag, "127.0.0.3", true); rejected {
		t.Fatal("clearing the online snapshot retained stale counts")
	}
}

func TestRemovedUserDropsAliveCount(t *testing.T) {
	user := panel.UserInfo{Id: 1, Uuid: "removed-user", DeviceLimit: 1}
	l := NewManager().Add("test", []panel.UserInfo{user}, map[int]int{1: 1}, "vless")
	tag := format.UserTag("test", user.Uuid)
	l.UpdateUser("test", nil, []panel.UserInfo{user})
	if _, rejected := l.CheckLimit(tag, "127.0.0.1", true); !rejected {
		t.Fatal("removed user was still accepted")
	}
	l.UpdateUser("test", []panel.UserInfo{user}, nil)
	if _, rejected := l.CheckLimit(tag, "127.0.0.1", true); rejected {
		t.Fatal("re-added user retained the deleted user's online count")
	}
}

func TestAliveListConcurrentRefreshDeletionAndConnections(t *testing.T) {
	user := panel.UserInfo{Id: 1, Uuid: "concurrent-user", DeviceLimit: 1}
	l := NewManager().Add("test", []panel.UserInfo{user}, map[int]int{1: 1}, "vless")
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, run := range []func(){
		func() {
			for i := range 500 {
				l.UpdateAliveList(map[int]int{1: i % 2})
			}
		},
		func() {
			for range 500 {
				l.UpdateUser("test", nil, []panel.UserInfo{user})
				l.UpdateUser("test", []panel.UserInfo{user}, nil)
			}
		},
		func() {
			for range 500 {
				l.CheckLimit(format.UserTag("test", user.Uuid), "127.0.0.1", true)
				l.GetOnlineDevice()
			}
		},
	} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			run()
		}()
	}
	close(start)
	wg.Wait()
}
