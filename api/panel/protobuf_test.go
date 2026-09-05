package panel

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	serverv1 "github.com/perfect-panel/ppanel-node/api/server/v1"
	"github.com/perfect-panel/ppanel-node/conf"
	"google.golang.org/protobuf/proto"
)

func readRequestBody(t *testing.T, request *http.Request) []byte {
	t.Helper()
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatalf("read request body: %v", err)
	}
	return body
}

func writeProtobuf(t *testing.T, writer http.ResponseWriter, message proto.Message) {
	t.Helper()
	body, err := proto.Marshal(message)
	if err != nil {
		t.Fatalf("proto.Marshal() error = %v", err)
	}
	writer.Header().Set("Content-Type", protobufContentType)
	_, _ = writer.Write(body)
}

func TestServerClientUsesProtobuf(t *testing.T) {
	server := httptest.NewTestServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v2/server/7" {
			t.Fatalf("path = %q", request.URL.Path)
		}
		if got := request.Header.Get("Accept"); got != protobufContentType {
			t.Fatalf("Accept = %q, want %q", got, protobufContentType)
		}
		writer.Header().Set("ETag", `"protobuf-config"`)
		writeProtobuf(t, writer, &serverv1.QueryServerProtocolConfigResponse{
			Code:    http.StatusOK,
			Message: "success",
			Data: &serverv1.QueryServerProtocolConfigData{
				PushInterval: 60,
				Protocols: []*serverv1.ServerProtocol{{
					Type: "vless", Port: 443, Enable: true, Transport: "tcp",
				}},
			},
		})
	}))
	httpClient := server.Client()

	client := NewServerClient(&conf.ServerApiConfig{
		ApiHost: server.URL, ServerId: 7,
	})
	client.Client.SetTransport(httpClient.Transport)
	response, err := GetServerConfig(t.Context(), client)
	if err != nil {
		t.Fatalf("GetServerConfig() error = %v", err)
	}
	if response.Data.PushInterval != 60 || len(*response.Data.Protocols) != 1 || (*response.Data.Protocols)[0].Port != 443 {
		t.Fatalf("response data = %+v, want converted protobuf configuration", response.Data)
	}
	if client.ServerConfigEtag != `"protobuf-config"` {
		t.Fatalf("ETag = %q", client.ServerConfigEtag)
	}
	if !response.UseProtobuf || !client.UseProtobuf {
		t.Fatalf("protobuf negotiation = response:%v client:%v, want true", response.UseProtobuf, client.UseProtobuf)
	}
}

func TestServerClientFallsBackToJSON(t *testing.T) {
	server := httptest.NewTestServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Accept"); got != protobufContentType {
			t.Fatalf("Accept = %q, want Protobuf preference", got)
		}
		_ = json.NewEncoder(writer).Encode(&ServerConfigResponse{
			Code: http.StatusOK,
			Msg:  "success",
			Data: &Data{Protocols: &[]Protocol{{Type: "vless", Port: 443, Enable: true, Transport: "tcp"}}},
		})
	}))
	httpClient := server.Client()

	client := NewServerClient(&conf.ServerApiConfig{ApiHost: server.URL, ServerId: 7})
	client.Client.SetTransport(httpClient.Transport)
	response, err := GetServerConfig(t.Context(), client)
	if err != nil {
		t.Fatalf("GetServerConfig() error = %v", err)
	}
	if response.UseProtobuf {
		t.Fatal("UseProtobuf = true, want JSON fallback")
	}
}

func TestNodeClientUsesProtobuf(t *testing.T) {
	const certificateSHA256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	server := httptest.NewTestServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get(CertificateSHA256Header); got != certificateSHA256 {
			t.Fatalf("%s = %q, want %q", CertificateSHA256Header, got, certificateSHA256)
		}
		if got := request.Header.Get("Accept"); got != protobufContentType {
			t.Fatalf("Accept = %q, want %q", got, protobufContentType)
		}
		if request.Method == http.MethodPost && request.Header.Get("Content-Type") != protobufContentType {
			t.Fatalf("Content-Type = %q, want %q", request.Header.Get("Content-Type"), protobufContentType)
		}
		switch request.URL.Path {
		case "/v1/server/user":
			writeProtobuf(t, writer, &serverv1.GetServerUserListResponse{
				Code: http.StatusOK, Message: "success",
				Data: &serverv1.ServerUserListData{Users: []*serverv1.ServerUser{{
					Id: 1, Uuid: "user-1", SpeedLimit: 10, DeviceLimit: 2,
				}}},
			})
		case "/v1/server/online":
			message := &serverv1.PushOnlineUsersRequest{}
			if err := proto.Unmarshal(readRequestBody(t, request), message); err != nil {
				t.Fatalf("online request: %v", err)
			}
			if len(message.Users) != 1 || message.Users[0].UserId != 1 {
				t.Fatalf("online users = %+v", message.Users)
			}
			writeProtobuf(t, writer, &serverv1.Result{Code: http.StatusOK, Message: "success"})
		case "/v1/server/push":
			message := &serverv1.PushUserTrafficRequest{}
			if err := proto.Unmarshal(readRequestBody(t, request), message); err != nil {
				t.Fatalf("traffic request: %v", err)
			}
			if len(message.Traffic) != 1 || message.Traffic[0].Download != 20 {
				t.Fatalf("traffic = %+v", message.Traffic)
			}
			writeProtobuf(t, writer, &serverv1.Result{Code: http.StatusOK, Message: "success"})
		case "/v1/server/status":
			message := &serverv1.PushServerStatusRequest{}
			if err := proto.Unmarshal(readRequestBody(t, request), message); err != nil {
				t.Fatalf("status request: %v", err)
			}
			if message.Cpu != 0.5 {
				t.Fatalf("status = %+v", message)
			}
			writeProtobuf(t, writer, &serverv1.Result{Code: http.StatusOK, Message: "success"})
		default:
			t.Fatalf("unexpected path %q", request.URL.Path)
		}
	}))
	httpClient := server.Client()

	client, err := NewNodeClient(&conf.NodeApiConfig{
		APIHost: server.URL, NodeID: 7, NodeType: "vless", UseProtobuf: true,
	})
	if err != nil {
		t.Fatalf("NewNodeClient() error = %v", err)
	}
	client.Client.SetTransport(httpClient.Transport)
	client.SetCertificateSHA256(strings.ToUpper(certificateSHA256))
	users, err := client.GetUserList(context.Background())
	if err != nil || len(users) != 1 || users[0].Uuid != "user-1" {
		t.Fatalf("GetUserList() = %+v, %v", users, err)
	}
	if err := client.ReportNodeOnlineUsers(context.Background(), &[]OnlineUser{{UID: 1, IP: "203.0.113.1"}}); err != nil {
		t.Fatalf("ReportNodeOnlineUsers() error = %v", err)
	}
	if err := client.ReportUserTraffic(context.Background(), &[]UserTraffic{{UID: 1, Upload: 10, Download: 20}}); err != nil {
		t.Fatalf("ReportUserTraffic() error = %v", err)
	}
	if err := client.ReportNodeStatus(&NodeStatus{CPU: 0.5, Mem: 0.6, Disk: 0.7}); err != nil {
		t.Fatalf("ReportNodeStatus() error = %v", err)
	}
}
