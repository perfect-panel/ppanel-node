package panel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	serverv1 "github.com/perfect-panel/ppanel-node/api/server/v1"
	"github.com/perfect-panel/ppanel-node/conf"
	"google.golang.org/protobuf/proto"
)

func TestDeviceAPIJSONAndProtobuf(t *testing.T) {
	for _, binary := range []bool{false, true} {
		t.Run(map[bool]string{false: "JSON", true: "Protobuf"}[binary], func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("server_id") != "7" || r.URL.Query().Get("protocol") != "vless" || r.URL.Query().Get("secret_key") != "device-test" {
					t.Error("missing node identity")
				}
				if binary && r.Header.Get("Accept") != protobufContentType {
					t.Error("missing protobuf negotiation")
				}
				if r.URL.Path == "/v1/server/alivelist" {
					if binary {
						writeProtobuf(t, w, &serverv1.GetServerAliveListResponse{Code: 200, Data: &serverv1.ServerAliveListData{Alive: map[int64]int64{21: 2}}})
					} else {
						w.Write([]byte(`{"alive":{"21":2}}`))
					}
					return
				}
				if r.URL.Path != "/v1/server/device" || r.Method != http.MethodPost {
					t.Errorf("unexpected device request: %s %s", r.Method, r.URL.Path)
				}
				var id int64
				var ip string
				if binary {
					var msg serverv1.ClaimServerDeviceRequest
					if err := proto.Unmarshal(readRequestBody(t, r), &msg); err != nil {
						t.Error(err)
					}
					id, ip = msg.UserId, msg.Ip
				} else {
					var msg struct {
						ID int64  `json:"uid"`
						IP string `json:"ip"`
					}
					if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
						t.Error(err)
					}
					id, ip = msg.ID, msg.IP
				}
				if id != 21 {
					t.Errorf("wrong subscription ID: %d", id)
				}
				allowed := ip == "127.0.0.1"
				if binary {
					writeProtobuf(t, w, &serverv1.ClaimServerDeviceResponse{Code: 200, Data: &serverv1.ServerDeviceClaimData{Allowed: allowed, TtlSeconds: 300}})
				} else {
					json.NewEncoder(w).Encode(map[string]any{"allowed": allowed, "ttl_seconds": 300})
				}
			}))
			defer server.Close()
			client, err := NewNodeClient(&conf.NodeApiConfig{APIHost: server.URL, NodeID: 7, NodeType: "vless", SecretKey: "device-test", UseProtobuf: binary})
			if err != nil {
				t.Fatal(err)
			}
			alive, err := client.GetUserAlive(t.Context())
			if err != nil || alive[21] != 2 {
				t.Fatalf("alive: %v, %v", alive, err)
			}
			for _, ip := range []string{"127.0.0.1", "127.0.0.2"} {
				allowed, ttl, err := client.ClaimDevice(t.Context(), 21, ip)
				if err != nil || allowed != (ip == "127.0.0.1") || ttl != 5*time.Minute {
					t.Fatalf("claim: %v, %v, %v", allowed, ttl, err)
				}
			}
		})
	}
}

func TestDeviceAPIDoesNotTurnErrorsIntoEmptyCountsOrAdmission(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"missing endpoint", `{}`, 404}, {"unavailable", `{}`, 503},
		{"panel error", `{"code":500,"alive":{},"allowed":true,"ttl_seconds":300}`, 200},
		{"missing data", `{}`, 200}, {"null", `null`, 200}, {"bad JSON", `{`, 200},
		{"negative count", `{"alive":{"21":-1}}`, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); w.Write([]byte(tc.body)) }))
			defer server.Close()
			client, _ := NewNodeClient(&conf.NodeApiConfig{APIHost: server.URL, NodeType: "vless"})
			if _, err := client.GetUserAlive(t.Context()); err == nil {
				t.Fatal("invalid count response accepted")
			}
			if allowed, _, err := client.ClaimDevice(t.Context(), 21, "127.0.0.1"); err == nil || allowed {
				t.Fatal("invalid claim response admitted device")
			}
		})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	client, _ := NewNodeClient(&conf.NodeApiConfig{APIHost: server.URL, NodeType: "vless"})
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if _, err := client.GetUserAlive(ctx); err == nil {
		t.Fatal("cancellation ignored")
	}
}

func TestOnlineReportUsesBackendJSONFieldNames(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string][]map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if len(body["users"]) != 1 || string(body["users"][0]["uid"]) != "21" || string(body["users"][0]["ip"]) != `"127.0.0.1"` {
			t.Errorf("incorrect online JSON: %v", body)
		}
		w.Write([]byte(`{"code":200}`))
	}))
	defer server.Close()
	client, _ := NewNodeClient(&conf.NodeApiConfig{APIHost: server.URL, NodeType: "vless"})
	users := []OnlineUser{{UID: 21, IP: "127.0.0.1"}}
	if err := client.ReportNodeOnlineUsers(t.Context(), &users); err != nil {
		t.Fatal(err)
	}
}
