package node

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
)

func TestTrafficRetriesAndSurvivesRemovedNode(t *testing.T) {
	var mu sync.Mutex
	var requests []panel.ServerPushUserTrafficRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body panel.ServerPushUserTrafficRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		mu.Lock()
		requests = append(requests, body)
		count := len(requests)
		mu.Unlock()
		if count == 1 {
			w.WriteHeader(503)
			return
		}
		fmt.Fprint(w, `{"code":200}`)
	}))
	defer server.Close()
	client, err := panel.NewNodeClient(&conf.NodeApiConfig{APIHost: server.URL, NodeType: "vless", NodeID: 1})
	if err != nil {
		t.Fatal(err)
	}
	old := &Node{traffic: newTrafficQueue()}
	old.traffic.add(client, []panel.UserTraffic{{UID: 7, Upload: 10, Download: 20}})
	if old.traffic.report(context.Background()) == nil {
		t.Fatal("expected failed report")
	}
	old.traffic.add(client, []panel.UserTraffic{{UID: 7, Upload: 5, Download: 7}})
	next := &Node{} // The protocol was removed in the new configuration.
	next.InheritTraffic(old)
	if err := next.report(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := next.report(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 2 {
		t.Fatalf("reports = %d", len(requests))
	}
	got := requests[1].Traffic
	if len(got) != 1 || got[0].Upload != 15 || got[0].Download != 27 {
		t.Fatalf("retry = %+v", got)
	}
}
