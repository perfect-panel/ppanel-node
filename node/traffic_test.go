package node

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
)

func TestTrafficRetriesAndSurvivesRemovedNode(t *testing.T) {
	var mu sync.Mutex
	var requests []panel.ServerPushUserTrafficRequest
	var ids []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body panel.ServerPushUserTrafficRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		mu.Lock()
		requests = append(requests, body)
		ids = append(ids, r.Header.Get("Idempotency-Key"))
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
	if len(requests) != 3 {
		t.Fatalf("reports = %d", len(requests))
	}
	if ids[0] == "" || ids[0] != ids[1] || ids[2] == "" || ids[1] == ids[2] {
		t.Fatalf("report IDs: %v", ids)
	}
	if !slices.Equal(requests[0].Traffic, requests[1].Traffic) {
		t.Fatal("retry changed the batch payload")
	}
	got := requests[2].Traffic
	if len(got) != 1 || got[0].Upload != 5 || got[0].Download != 7 {
		t.Fatalf("retry = %+v", got)
	}
}

func TestTrafficQueueSplitsOversizedDelta(t *testing.T) {
	var batches int
	var upload, download int64
	ids := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b panel.ServerPushUserTrafficRequest
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			t.Error(err)
			return
		}
		id := r.Header.Get("Idempotency-Key")
		if id == "" || ids[id] || len(b.Traffic) != 1 {
			t.Error("invalid split batch")
			return
		}
		ids[id] = true
		batches++
		v := b.Traffic[0]
		if v.Upload+v.Download > maxTrafficReportBytes {
			t.Error("exceeded panel limit")
		}
		upload += v.Upload
		download += v.Download
		_, _ = fmt.Fprint(w, `{"code":200}`)
	}))
	defer server.Close()
	c, err := panel.NewNodeClient(&conf.NodeApiConfig{APIHost: server.URL, NodeType: "vless", NodeID: 1})
	if err != nil {
		t.Fatal(err)
	}
	q := newTrafficQueue()
	q.add(c, []panel.UserTraffic{{UID: 7, Upload: maxTrafficReportBytes + 1, Download: 2}})
	if err := q.report(t.Context()); err != nil {
		t.Fatal(err)
	}
	if batches != 2 || upload != maxTrafficReportBytes+1 || download != 2 {
		t.Fatal("lost traffic across split")
	}
}
