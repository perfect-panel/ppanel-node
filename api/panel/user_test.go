package panel

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	serverv1 "github.com/perfect-panel/ppanel-node/api/server/v1"
	"github.com/perfect-panel/ppanel-node/conf"
)

func TestEmptyUserListIsDifferentFromNotModified(t *testing.T) {
	for _, protobuf := range []bool{false, true} {
		t.Run(fmt.Sprint(protobuf), func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			defer server.Close()
			client, err := NewNodeClient(&conf.NodeApiConfig{APIHost: server.URL, NodeType: "vless", UseProtobuf: protobuf})
			if err != nil {
				t.Fatal(err)
			}
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
