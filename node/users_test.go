package node

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/common/format"
	"github.com/perfect-panel/ppanel-node/conf"
	"github.com/perfect-panel/ppanel-node/core"
	"github.com/perfect-panel/ppanel-node/limiter"
)

func TestUserSyncRevokesLastUserAndAllowsEmptyStartup(t *testing.T) {
	var empty atomic.Bool
	var aliveUnavailable atomic.Bool
	var deviceLimit atomic.Int64
	deviceLimit.Store(1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/server/alivelist" {
			if aliveUnavailable.Load() {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			fmt.Fprint(w, `{"alive":{}}`)
			return
		}
		if empty.Load() {
			fmt.Fprint(w, `{"code":200,"data":{"users":[]}}`)
			return
		}
		fmt.Fprintf(w, `{"code":200,"data":{"users":[{"id":1,"uuid":"00000000-0000-0000-0000-000000000001","device_limit":%d}]}}`, deviceLimit.Load())
	}))
	defer server.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	protocols := []panel.Protocol{{Type: "vless", Enable: true, Port: port, Transport: "tcp"}}
	config := &panel.ServerConfigResponse{Data: &panel.Data{Protocols: &protocols, PullInterval: 3600, PushInterval: 3600}}
	cfg := conf.New()
	cfg.ApiConfig.ApiHost = server.URL
	xcore := core.New(cfg, panel.NewServerClient(&cfg.ApiConfig))
	if err := xcore.Start(config); err != nil {
		t.Fatal(err)
	}
	defer xcore.Close()
	n, err := New(xcore, cfg, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	c := n.controllers[0]
	manager, err := xcore.GetUserManager(c.tag)
	if err != nil {
		t.Fatal(err)
	}
	if manager.GetUsersCount(context.Background()) != 1 {
		t.Fatal("initial user missing")
	}
	for _, limit := range []int{2, 1, 0, 3} {
		// An unavailable count endpoint must not discard a fetched user list
		// or stop revocations and limit changes from reaching the core.
		aliveUnavailable.Store(true)
		deviceLimit.Store(int64(limit))
		if err := c.userListMonitor(context.Background()); err != nil {
			t.Fatal(err)
		}
		value, ok := c.limiter.UserLimitInfo.Load(format.UserTag(c.tag, "00000000-0000-0000-0000-000000000001"))
		if !ok {
			t.Fatal("user disappeared from limiter after device limit update")
		}
		if got := value.(*limiter.UserLimitInfo).DeviceLimit; got != limit {
			t.Errorf("synced device limit = %d, want %d", got, limit)
		}
		if manager.GetUsersCount(context.Background()) != 1 {
			t.Fatal("device limit update changed the number of core users")
		}
	}
	empty.Store(true)
	if err := c.userListMonitor(context.Background()); err != nil {
		t.Fatal(err)
	}
	if manager.GetUsersCount(context.Background()) != 0 {
		t.Fatal("last user was not revoked")
	}
	n.Close()
	aliveUnavailable.Store(false)
	next, err := New(xcore, cfg, config)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if err := next.Start(); err != nil {
		t.Fatalf("empty startup: %v", err)
	}
}

func TestUserSyncRefreshesAliveListDuringConnections(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/server/alivelist" {
			fmt.Fprint(w, `{"alive":{}}`)
			return
		}
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()
	client, err := panel.NewNodeClient(&conf.NodeApiConfig{APIHost: server.URL, NodeType: "vless"})
	if err != nil {
		t.Fatal(err)
	}
	const tag, uuid = "sync-test", "sync-user"
	l := limiter.NewManager().Add(tag, []panel.UserInfo{{Id: 1, Uuid: uuid, DeviceLimit: 1}}, map[int]int{}, "vless")
	c := &Controller{apiClient: client, limiter: l}
	started, done := make(chan struct{}), make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		close(started)
		for {
			select {
			case <-done:
				return
			default:
				l.CheckLimit(format.UserTag(tag, uuid), "127.0.0.1", true)
			}
		}
	}()
	defer func() {
		close(done)
		wg.Wait()
	}()
	<-started
	for range 32 {
		if err := c.userListMonitor(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}
