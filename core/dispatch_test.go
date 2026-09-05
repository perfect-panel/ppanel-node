package core

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/vless/encoding"
)

func TestVlessDispatchAccountsTraffic(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	echoCtx, cancelEcho := context.WithCancel(context.Background())
	defer cancelEcho()
	go func() {
		conn, err := echo.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		data := make([]byte, 64)
		n, _ := conn.Read(data)
		conn.Write(data[:n])
		<-echoCtx.Done()
	}()
	reservation, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	reservation.Close()
	cfg := conf.New()
	cfg.LogConfig.Level = "error"
	c := New(cfg, nil)
	config := &panel.ServerConfigResponse{Data: &panel.Data{Protocols: &[]panel.Protocol{}, PullInterval: 3600}}
	if err := c.Start(config); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	allowLoopbackForTest(t, c)
	info := &panel.NodeInfo{Id: 1, Type: "vless", Protocol: &panel.Protocol{Port: port, Transport: "tcp", Encryption: "none"}}
	user := panel.UserInfo{Id: 1, Uuid: "00000000-0000-0000-0000-000000000001"}
	c.LimiterManager.Add("test", []panel.UserInfo{user}, nil, "vless")
	if err := c.AddNode("test", info); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AddUsers(&AddUsersParams{Tag: "test", Users: []panel.UserInfo{user}, NodeInfo: info}); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	memoryUser, err := buildVlessUser("test", &user, "").ToMemoryUser()
	if err != nil {
		t.Fatal(err)
	}
	request := &protocol.RequestHeader{Version: 0, Command: protocol.RequestCommandTCP, Address: xnet.ParseAddress("127.0.0.1"), Port: xnet.Port(echo.Addr().(*net.TCPAddr).Port), User: memoryUser}
	if err := encoding.EncodeRequestHeader(conn, request, &encoding.Addons{}); err != nil {
		t.Fatal(err)
	}
	payload := []byte("ppnode traffic regression")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if _, err := encoding.DecodeResponseHeader(conn, request); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo = %q", got)
	}
	traffic, err := c.GetUserTrafficSlice("test", 0)
	if err != nil || len(traffic) != 1 || traffic[0].Upload != int64(len(payload)) || traffic[0].Download != int64(len(payload)) {
		t.Fatalf("traffic = %+v, %v", traffic, err)
	}
	conn.Close()
	cancelEcho()
}
