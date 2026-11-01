package node

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/common/format"
	"github.com/perfect-panel/ppanel-node/conf"
	"github.com/perfect-panel/ppanel-node/limiter"
)

func TestOnlineHeartbeatRetriesShortConnectionsWithoutTraffic(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "retry", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprint(w, `{"code":200}`)
	}))
	defer server.Close()
	client, _ := panel.NewNodeClient(&conf.NodeApiConfig{APIHost: server.URL, NodeType: "vless"})
	l := limiter.NewManager().Add("test", []panel.UserInfo{{Id: 21, Uuid: "user"}}, nil, "vless")
	c := &Controller{apiClient: client, limiter: l}
	_, closeConn, rejected := l.Acquire(t.Context(), format.UserTag("test", "user"), "127.0.0.1")
	if rejected {
		t.Fatal("connection rejected")
	}
	closeConn()
	if err := c.reportOnline(t.Context()); err == nil {
		t.Fatal("failed heartbeat reported success")
	}
	online, _ := l.GetOnlineDevice()
	if len(*online) != 1 {
		t.Fatal("failed heartbeat discarded device")
	}
	fail.Store(false)
	if err := c.reportOnline(t.Context()); err != nil {
		t.Fatal(err)
	}
	online, _ = l.GetOnlineDevice()
	if len(*online) != 0 {
		t.Fatal("closed acknowledged device kept renewing")
	}
}

func TestOnlineHeartbeatBatchesAllDevices(t *testing.T) {
	var calls, total atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body panel.UserOnlineBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if len(body.Users) == 0 || len(body.Users) > 10000 {
			t.Errorf("invalid batch size: %d", len(body.Users))
		}
		calls.Add(1)
		total.Add(int32(len(body.Users)))
		fmt.Fprint(w, `{"code":200}`)
	}))
	defer server.Close()
	client, _ := panel.NewNodeClient(&conf.NodeApiConfig{APIHost: server.URL, NodeType: "vless"})
	l := limiter.NewManager().Add("test", []panel.UserInfo{{Id: 21, Uuid: "user"}}, nil, "vless")
	for i := range 10001 {
		_, closeConn, rejected := l.Acquire(t.Context(), format.UserTag("test", "user"), fmt.Sprintf("10.0.%d.%d", i/256, i%256))
		if rejected {
			t.Fatal("unlimited device rejected")
		}
		closeConn()
	}
	if err := (&Controller{apiClient: client, limiter: l}).reportOnline(t.Context()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || total.Load() != 10001 {
		t.Fatalf("reported %d devices in %d batches", total.Load(), calls.Load())
	}
}

func TestCountFailureKeepsPreviousSnapshot(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/server/user" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	client, _ := panel.NewNodeClient(&conf.NodeApiConfig{APIHost: server.URL, NodeType: "vless"})
	l := limiter.NewManager().Add("test", []panel.UserInfo{{Id: 21, Uuid: "user", DeviceLimit: 1}}, map[int]int{21: 1}, "vless")
	c := &Controller{apiClient: client, limiter: l}
	c.userListMonitor(t.Context())
	if _, _, rejected := l.Acquire(t.Context(), format.UserTag("test", "user"), "127.0.0.1"); !rejected {
		t.Fatal("count failure cleared the previous full snapshot")
	}
}
