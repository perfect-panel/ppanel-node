package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
	"github.com/perfect-panel/ppanel-node/core"
	"github.com/perfect-panel/ppanel-node/node"
)

func TestReloadPreservesServiceAndRollsBackWithoutPanel(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	oldPort := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	var port atomic.Int32
	port.Store(int32(oldPort))
	var failUsers, failAfterFetch atomic.Bool
	var requests atomic.Int32
	configForPort := func() *panel.ServerConfigResponse {
		protocols := []panel.Protocol{{Type: "vless", Enable: true, Port: int(port.Load()), Transport: "tcp"}}
		return &panel.ServerConfigResponse{Code: 200, Data: &panel.Data{Protocols: &protocols, PullInterval: 3600, PushInterval: 3600}}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/server/7":
			json.NewEncoder(w).Encode(configForPort())
		case "/v1/server/user":
			requests.Add(1)
			if failUsers.Load() {
				http.Error(w, "unavailable", 503)
				return
			}
			fmt.Fprint(w, `{"code":200,"data":{"users":[{"id":1,"uuid":"00000000-0000-0000-0000-000000000001"}]}}`)
			if failAfterFetch.Load() {
				failUsers.Store(true)
			}
		default:
			fmt.Fprint(w, `{"code":200}`)
		}
	}))
	defer server.Close()
	cfg := conf.New()
	cfg.LogConfig.Level = "error"
	cfg.ApiConfig = conf.ServerApiConfig{ApiHost: server.URL, ServerId: 7, Timeout: 1}
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf("Log:\n  Level: error\nApi:\n  ApiHost: %q\n  ServerID: 7\n  Timeout: 1\n", server.URL)), 0600); err != nil {
		t.Fatal(err)
	}
	xcore := core.New(cfg, panel.NewServerClient(&cfg.ApiConfig))
	reloadCh := make(chan struct{}, 1)
	xcore.ReloadCh = reloadCh
	initial := configForPort()
	if err := xcore.Start(initial); err != nil {
		t.Fatal(err)
	}
	nodes, err := node.New(xcore, cfg, initial)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { nodes.Close(); xcore.Close() }()
	if err := nodes.Start(); err != nil {
		t.Fatal(err)
	}
	assertAvailable := func() {
		t.Helper()
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", oldPort), time.Second)
		if err != nil {
			t.Fatalf("old listener unavailable: %v", err)
		}
		conn.Close()
		manager, err := xcore.GetUserManager(fmt.Sprintf("[%s]-vless:7", server.URL))
		if err != nil {
			t.Fatal(err)
		}
		if manager.GetUsersCount(context.Background()) != 1 {
			t.Fatal("cached user was not restored")
		}
	}
	oldNodes, oldCore := nodes, xcore
	failUsers.Store(true)
	if _, err := reload(path, &nodes, &xcore, nil); err == nil {
		t.Fatal("expected preparation failure")
	}
	if nodes != oldNodes || xcore != oldCore {
		t.Fatal("failed preparation replaced current instance")
	}
	assertAvailable()

	blocker, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	port.Store(int32(blocker.Addr().(*net.TCPAddr).Port))
	failUsers.Store(false)
	failAfterFetch.Store(true)
	before := requests.Load()
	if _, err := reload(path, &nodes, &xcore, nil); err == nil {
		t.Fatal("expected listener conflict")
	}
	if requests.Load() != before+1 {
		t.Fatal("rollback fetched users from unavailable panel")
	}
	if nodes != oldNodes || xcore != oldCore {
		t.Fatal("failed switch lost old instance")
	}
	assertAvailable()

	failUsers.Store(false)
	failAfterFetch.Store(false)
	port.Store(int32(oldPort))
	handle, err := reload(path, &nodes, &xcore, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	if xcore == oldCore || nodes == oldNodes || xcore.ReloadCh != reloadCh {
		t.Fatal("successful reload did not replace instances and retain reload channel")
	}
	assertAvailable()
}
