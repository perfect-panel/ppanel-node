package panel

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"

	serverv1 "github.com/perfect-panel/ppanel-node/api/server/v1"
	"github.com/perfect-panel/ppanel-node/conf"
)

func TestEmptyUserListIsDifferentFromNotModified(t *testing.T) {
	for _, protobuf := range []bool{false, true} {
		t.Run(fmt.Sprint(protobuf), func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 2 {
					if r.Header.Get("If-None-Match") != "empty" {
						t.Error("missing empty-list ETag")
					}
					w.WriteHeader(http.StatusNotModified)
					return
				}
				w.Header().Set("ETag", "empty")
				if protobuf {
					writeProtobuf(t, w, &serverv1.GetServerUserListResponse{Code: 200, Data: &serverv1.ServerUserListData{}})
				} else {
					fmt.Fprint(w, `{"code":200,"data":{"users":[]}}`)
				}
			}))
			httpClient := server.Client()
			client, err := NewNodeClient(&conf.NodeApiConfig{APIHost: server.URL, NodeType: "vless", UseProtobuf: protobuf})
			if err != nil {
				t.Fatal(err)
			}
			client.Client.SetTransport(httpClient.Transport)
			users, err := client.GetUserList(context.Background())
			if err != nil || users == nil || len(users) != 0 {
				t.Fatalf("empty list = %#v, %v", users, err)
			}
			users, err = client.GetUserList(context.Background())
			if err != nil || users != nil {
				t.Fatalf("304 = %#v, %v", users, err)
			}
		})
	}
}

func TestDecodeUserListStream(t *testing.T) {
	tests := []struct {
		name, body string
		count      int
		invalid    bool
	}{
		{name: "nested", body: `{"code":200,"data":{"users":[{"id":7,"uuid":"user","speed_limit":100,"device_limit":3}]}}`, count: 1},
		{name: "direct", body: `{"users":[{"id":7,"uuid":"user","speed_limit":100,"device_limit":3}]}`, count: 1},
		{name: "empty", body: `{"data":{"users":[]}}`},
		{name: "null is not an array", body: `{"users":null}`, invalid: true},
		{name: "object is not an array", body: `{"users":{}}`, invalid: true},
		{name: "truncated user", body: `{"users":[{"id":7`, invalid: true},
		{name: "truncated array", body: `{"users":[{"id":7}`, invalid: true},
		{name: "invalid field type", body: `{"users":[{"id":"invalid"}]}`, invalid: true},
		{name: "duplicate field", body: `{"users":[{"id":7,"id":8}]}`, invalid: true},
		{name: "missing users", body: `{"data":{}}`, invalid: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			users, err := decodeUserList(iotest.OneByteReader(strings.NewReader(test.body)))
			if test.invalid {
				if err == nil {
					t.Fatal("invalid JSON accepted")
				}
				return
			}
			if err != nil || users == nil || len(users) != test.count {
				t.Fatalf("users = %+v, err = %v", users, err)
			}
			if test.count == 1 && users[0] != (UserInfo{Id: 7, Uuid: "user", SpeedLimit: 100, DeviceLimit: 3}) {
				t.Fatalf("user fields = %+v", users[0])
			}
		})
	}
}

func TestMalformedUserListDoesNotAdvanceETag(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") != "previous" {
			t.Error("ETag advanced before successful decode")
		}
		w.Header().Set("ETag", "next")
		if calls.Add(1) == 1 {
			fmt.Fprint(w, `{"users":[{"id":`)
			return
		}
		fmt.Fprint(w, `{"users":[]}`)
	}))
	httpClient := server.Client()
	client, err := NewNodeClient(&conf.NodeApiConfig{APIHost: server.URL, NodeType: "vless"})
	if err != nil {
		t.Fatal(err)
	}
	client.Client.SetTransport(httpClient.Transport)
	client.userEtag = "previous"
	if _, err := client.GetUserList(t.Context()); err == nil {
		t.Fatal("malformed user list accepted")
	}
	if _, err := client.GetUserList(t.Context()); err != nil {
		t.Fatal(err)
	}
	if client.userEtag != "next" {
		t.Fatal("successful decode did not update ETag")
	}
}
