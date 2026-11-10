package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	nw "github.com/perfect-panel/nowhere"
	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
	adapter "github.com/perfect-panel/ppanel-node/core/protocol/nowhere"
	"github.com/sagernet/quic-go"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/xtls/xray-core/app/proxyman"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	xray "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy"
)

const nowhereTestKey = "0123456789abcdef0123456789abcdef"
const nowhereTestTag = "nowhere-test"

func newNowhereTestCore(t *testing.T, morph bool) (*XrayCore, *adapter.Handler, *tls.Config, *panel.NodeInfo, panel.UserInfo, string) {
	t.Helper()
	cert := protocolCertificate(t)
	dir := t.TempDir()
	certificateFile, keyFile := filepath.Join(dir, "server.cer"), filepath.Join(dir, "server.key")
	certPEM := []byte(strings.Join(cert.Certs[0].CertStr, "\n"))
	if err := os.WriteFile(certificateFile, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte(strings.Join(cert.Certs[0].KeyStr, "\n")), 0600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	block, _ := pem.Decode(certPEM)
	digest := sha256.Sum256(block.Bytes)
	pin := hex.EncodeToString(digest[:])
	cfg := conf.New()
	cfg.LogConfig.Level = "error"
	c := New(cfg, nil)
	if err := c.Start(&panel.ServerConfigResponse{Data: &panel.Data{Protocols: &[]panel.Protocol{}, PullInterval: 3600}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	allowLoopbackForTest(t, c)
	user := panel.UserInfo{Id: 42, Uuid: nowhereTestKey, DeviceLimit: 1}
	info := &panel.NodeInfo{Id: 1, Type: "nowhere", Protocol: &panel.Protocol{Type: "nowhere", Version: 3, Network: "mix", Security: "tls", SNI: "localhost", CertMode: "file"}}
	limit := c.LimiterManager.Add(nowhereTestTag, []panel.UserInfo{user}, nil, "nowhere")
	limit.SetDeviceAdmission(func(context.Context, int, string) (bool, time.Duration, error) { return true, time.Minute, nil })
	config := &xray.InboundHandlerConfig{Tag: nowhereTestTag,
		ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{Listen: xnet.NewIPOrDomain(xnet.LocalHostIP)}),
		ProxySettings:    serial.ToTypedMessage(&adapter.Config{Listen: "127.0.0.1:0", Network: adapter.NetworkMixed, CertificateFile: certificateFile, KeyFile: keyFile, Morph: morph, Alpn: adapter.ALPN})}
	if err := c.AddNodeConfig(config); err != nil {
		t.Fatal(err)
	}
	if n, err := c.AddUsers(&AddUsersParams{Tag: nowhereTestTag, NodeInfo: info, Users: []panel.UserInfo{user}}); err != nil || n != 1 {
		t.Fatalf("add users: %d %v", n, err)
	}
	h, err := c.ihm.GetHandler(t.Context(), nowhereTestTag)
	if err != nil {
		t.Fatal(err)
	}
	return c, h.(proxy.GetInbound).GetInbound().(*adapter.Handler), &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13, NextProtos: []string{adapter.ALPN}}, info, user, pin
}

func nowhereEcho(t *testing.T, network string) string {
	t.Helper()
	if network == "tcp" {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		go func() {
			for {
				c, err := listener.Accept()
				if err != nil {
					return
				}
				go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
			}
		}()
		return listener.Addr().String()
	}
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packet.Close() })
	go func() {
		data := make([]byte, 65535)
		for {
			n, addr, err := packet.ReadFrom(data)
			if err != nil {
				return
			}
			_, _ = packet.WriteTo(data[:n], addr)
		}
	}()
	return packet.LocalAddr().String()
}

func writeNowhereAuth(t *testing.T, writer io.Writer, state tls.ConnectionState, transport nw.AuthTransport) {
	t.Helper()
	export, err := state.ExportKeyingMaterial(nw.AuthExporterLabel, []byte{}, nw.TLSExporterLen)
	if err != nil {
		t.Fatal(err)
	}
	key, err := nw.DeriveAuthKey([]byte(nowhereTestKey))
	if err != nil {
		t.Fatal(err)
	}
	var exporter nw.TLSExporter
	copy(exporter[:], export)
	frame, err := nw.EncodeAuthFrame(key, transport, exporter)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Write(frame[:]); err != nil {
		t.Fatal(err)
	}
}

func writeNowhereTarget(t *testing.T, writer io.Writer, kind nw.FlowKind, target string) {
	t.Helper()
	header, err := nw.EncodeFlowHeader(nw.FlowHeader{Kind: kind})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Write(header[:]); err != nil {
		t.Fatal(err)
	}
	var wire [nw.TargetMaxEncodedLen]byte
	n, err := nw.EncodeTarget(M.ParseSocksaddr(target), wire[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Write(wire[:n]); err != nil {
		t.Fatal(err)
	}
}

func dialNowhereTLS(t *testing.T, h *adapter.Handler, config *tls.Config) *tls.Conn {
	t.Helper()
	conn, err := tls.Dial("tcp", h.Addr("tcp").String(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	writeNowhereAuth(t, conn, conn.ConnectionState(), nw.AuthTransportTLSTCP)
	return conn
}

func TestNowhereTLSRelaysTCPAndUDPAndBillsUser(t *testing.T) {
	c, h, config, _, _, _ := newNowhereTestCore(t, false)
	for _, kind := range []nw.FlowKind{nw.FlowKindTCP, nw.FlowKindUDP} {
		network := "tcp"
		if kind == nw.FlowKindUDP {
			network = "udp"
		}
		conn := dialNowhereTLS(t, h, config)
		writeNowhereTarget(t, conn, kind, nowhereEcho(t, network))
		result, err := nw.ReadSetupResult(conn)
		if err != nil || result != nw.SetupReady {
			t.Fatalf("%s setup: %d %v", network, result, err)
		}
		payload := bytes.Repeat([]byte("nw3"), 1200)
		if kind == nw.FlowKindTCP {
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			response := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, response); err != nil || !bytes.Equal(response, payload) {
				t.Fatalf("TCP relay: %v", err)
			}
		} else {
			if err := nw.WriteUOTPacket(conn, payload); err != nil {
				t.Fatal(err)
			}
			response := make([]byte, 65535)
			n, err := nw.ReadUOTPacket(conn, response)
			if err != nil || !bytes.Equal(response[:n], payload) {
				t.Fatalf("UDP relay: n=%d %v", n, err)
			}
		}
		_ = conn.Close()
	}
	traffic, err := c.GetUserTrafficSlice(nowhereTestTag, 0)
	if err != nil || len(traffic) != 1 || traffic[0].UID != 42 || traffic[0].Upload < 7200 || traffic[0].Download < 7200 {
		t.Fatalf("unbilled traffic: %+v %v", traffic, err)
	}
}

func TestNowhereQUICRelaysTCPAndFragmentedUDP(t *testing.T) {
	_, h, config, _, _, _ := newNowhereTestCore(t, false)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, h.Addr("udp").String(), config, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
	writeNowhereAuth(t, stream, conn.ConnectionState().TLS, nw.AuthTransportQUIC)
	writeNowhereTarget(t, stream, nw.FlowKindTCP, nowhereEcho(t, "tcp"))
	if code, err := nw.ReadSetupResult(stream); err != nil || code != nw.SetupReady {
		t.Fatalf("TCP setup: %d %v", code, err)
	}
	_, _ = stream.Write([]byte("ping"))
	response := make([]byte, 4)
	if _, err := io.ReadFull(stream, response); err != nil || string(response) != "ping" {
		t.Fatalf("TCP echo: %q %v", response, err)
	}
	_ = stream.Close()
	control, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = control.SetDeadline(time.Now().Add(10 * time.Second))
	writeNowhereTarget(t, control, nw.FlowKindUDP, nowhereEcho(t, "udp"))
	if code, err := nw.ReadSetupResult(control); err != nil || code != nw.SetupReady {
		t.Fatalf("UDP setup: %d %v", code, err)
	}
	id, err := nw.UDPFlowID(uint64(control.StreamID()))
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("packet"), 600)
	fragments, err := nw.EncodeUDPFragments(id, 1, payload, 1100)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range fragments {
		if err := conn.SendDatagram(fragment); err != nil {
			t.Fatal(err)
		}
	}
	reassembly, err := nw.NewDatagramReassembler(nw.DefaultReassemblyConfig())
	if err != nil {
		t.Fatal(err)
	}
	for {
		data, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			t.Fatal(err)
		}
		frame, err := nw.DecodeUDPFrame(data)
		if err != nil {
			t.Fatal(err)
		}
		if frame.Type == nw.UDPFrameData {
			if !bytes.Equal(frame.Payload, payload) {
				t.Fatal("UDP changed payload")
			}
			break
		}
		packet, done, err := reassembly.Push(frame, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if done {
			if !bytes.Equal(packet, payload) {
				t.Fatal("UDP fragments changed payload")
			}
			break
		}
	}
}

func TestNowhereAdmissionRejectsBeforeReady(t *testing.T) {
	c, h, config, _, _, _ := newNowhereTestCore(t, false)
	limit, _ := c.LimiterManager.Get(nowhereTestTag)
	limit.SetDeviceAdmission(func(context.Context, int, string) (bool, time.Duration, error) { return false, time.Minute, nil })
	conn := dialNowhereTLS(t, h, config)
	writeNowhereTarget(t, conn, nw.FlowKindTCP, nowhereEcho(t, "tcp"))
	if code, err := nw.ReadSetupResult(conn); err != nil || code != nw.SetupFlowLimit {
		t.Fatalf("denial became ready: %d %v", code, err)
	}
	online, _ := limit.GetOnlineDevice()
	if len(*online) != 0 {
		t.Fatal("denied flow became online")
	}
}

func TestNowhereRevocationClosesCarriers(t *testing.T) {
	c, h, config, info, user, _ := newNowhereTestCore(t, false)
	conn := dialNowhereTLS(t, h, config)
	writeNowhereTarget(t, conn, nw.FlowKindTCP, nowhereEcho(t, "tcp"))
	if code, err := nw.ReadSetupResult(conn); err != nil || code != nw.SetupReady {
		t.Fatalf("setup: %d %v", code, err)
	}
	if err := c.DelUsers([]panel.UserInfo{user}, nowhereTestTag, info); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var output [1]byte
	if _, err := conn.Read(output[:]); err == nil {
		t.Fatal("revoked carrier still readable")
	}
	if h.GetUsersCount(t.Context()) != 0 {
		t.Fatal("revoked credentials retained")
	}
}

func TestNowhereBatchUserPublicationIsAtomic(t *testing.T) {
	c, h, _, info, _, _ := newNowhereTestCore(t, false)
	users := make([]panel.UserInfo, 1000)
	for i := range users {
		users[i] = panel.UserInfo{Id: 100 + i, Uuid: fmt.Sprintf("%032x", i+100)}
	}
	if n, err := c.AddUsers(&AddUsersParams{Tag: nowhereTestTag, NodeInfo: info, Users: users}); err != nil || n != len(users) {
		t.Fatalf("batch users: %d %v", n, err)
	}
	if got := h.GetUsersCount(t.Context()); got != 1001 {
		t.Fatalf("users=%d", got)
	}
	bad := []panel.UserInfo{{Id: 9999, Uuid: fmt.Sprintf("%032x", 9999)}, {Id: 10000, Uuid: "not-a-key"}}
	if _, err := c.AddUsers(&AddUsersParams{Tag: nowhereTestTag, NodeInfo: info, Users: bad}); err == nil {
		t.Fatal("invalid credential batch accepted")
	}
	if h.GetUsersCount(t.Context()) != 1001 {
		t.Fatal("failed batch partially published")
	}
	if _, err := c.AddUsers(&AddUsersParams{Tag: nowhereTestTag, NodeInfo: info, Users: []panel.UserInfo{{Id: 0, Uuid: fmt.Sprintf("%032x", 99999)}}}); err == nil {
		t.Fatal("credential without a billable subscription ID accepted")
	}
	if err := c.DelUsers(users, nowhereTestTag, info); err != nil {
		t.Fatal(err)
	}
	if h.GetUsersCount(t.Context()) != 1 {
		t.Fatal("batch deletion left users behind")
	}
}

func TestNowhereDialFailureDoesNotReturnReady(t *testing.T) {
	_, h, config, _, _, _ := newNowhereTestCore(t, false)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	conn := dialNowhereTLS(t, h, config)
	writeNowhereTarget(t, conn, nw.FlowKindTCP, address)
	if code, err := nw.ReadSetupResult(conn); err != nil || code != nw.SetupDialFailed {
		t.Fatalf("failed dial setup: %d %v", code, err)
	}
}

func TestNowhereUploadUsesSubscriptionSpeedLimit(t *testing.T) {
	c, h, config, info, user, _ := newNowhereTestCore(t, false)
	limit, _ := c.LimiterManager.Get(nowhereTestTag)
	next := user
	next.SpeedLimit = 1
	limit.UpdateUser(nowhereTestTag, []panel.UserInfo{next}, []panel.UserInfo{user})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var received atomic.Int64
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		p := make([]byte, 8192)
		for {
			n, err := conn.Read(p)
			received.Add(int64(n))
			if err != nil {
				return
			}
		}
	}()
	conn := dialNowhereTLS(t, h, config)
	writeNowhereTarget(t, conn, nw.FlowKindTCP, listener.Addr().String())
	if code, err := nw.ReadSetupResult(conn); err != nil || code != nw.SetupReady {
		t.Fatalf("setup: %d %v", code, err)
	}
	started := time.Now()
	writeDone := make(chan struct{})
	go func() { defer close(writeDone); _, _ = conn.Write(make([]byte, 4<<20)) }()
	time.Sleep(150 * time.Millisecond)
	// One initial burst plus refill over elapsed time, with a buffer margin.
	maxBytes := int64(125000) + int64(time.Since(started).Seconds()*125000) + 8192
	if got := received.Load(); got == 0 || got > maxBytes {
		t.Errorf("upload bypassed 1 Mbps bucket: %d > %d", got, maxBytes)
	}
	// A TCP FIN can follow already-buffered payload. Explicit revocation must
	// instead interrupt the shared rate wait immediately, without draining it.
	if err := c.DelUsers([]panel.UserInfo{user}, nowhereTestTag, info); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	<-writeDone
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("rate-limited flow did not cancel")
	}
}
