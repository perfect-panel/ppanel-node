package core

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	quic "github.com/apernet/quic-go"
	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
	inboundbuilder "github.com/perfect-panel/ppanel-node/core/inbound"
	outboundbuilder "github.com/perfect-panel/ppanel-node/core/outbound"
	"github.com/xtls/xray-core/app/proxyman"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	xray "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	coreConf "github.com/xtls/xray-core/infra/conf"
	tuictransport "github.com/xtls/xray-core/transport/internet/tuic"
)

const protocolTestUUID = "00000000-0000-0000-0000-000000000001"

func protocolCertificate(t *testing.T) *coreConf.TLSConfig {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	return &coreConf.TLSConfig{MinVersion: "1.3", Certs: []*coreConf.TLSCertConfig{{CertStr: strings.Split(string(certPEM), "\n"), KeyStr: strings.Split(string(keyPEM), "\n")}}}
}

func protocolServer(t *testing.T, name string) (*XrayCore, int, *panel.NodeInfo, panel.UserInfo, string) {
	t.Helper()
	var port int
	if name == "tuic" || name == "hysteria2" {
		listener, err := net.ListenPacket("udp", "0.0.0.0:0")
		if err != nil {
			t.Fatal(err)
		}
		port = listener.LocalAddr().(*net.UDPAddr).Port
		listener.Close()
	} else {
		listener, err := net.Listen("tcp", "0.0.0.0:0")
		if err != nil {
			t.Fatal(err)
		}
		port = listener.Addr().(*net.TCPAddr).Port
		listener.Close()
	}
	cfg := conf.New()
	cfg.LogConfig.Level = "error"
	c := New(cfg, nil)
	if err := c.Start(&panel.ServerConfigResponse{Data: &panel.Data{Protocols: &[]panel.Protocol{}, PullInterval: 3600}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	allowLoopbackForTest(t, c)
	info := &panel.NodeInfo{Id: 1, Type: name, Protocol: &panel.Protocol{Port: port, Transport: "tcp", Cipher: "aes-128-gcm", Encryption: "none"}}
	inbound, err := inboundbuilder.Build(info, "protocol-test")
	if err != nil {
		t.Fatal(err)
	}
	var pin string
	if name == "trojan" || name == "anytls" || name == "tuic" || name == "hysteria2" {
		value, err := inbound.ReceiverSettings.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		receiver := value.(*proxyman.ReceiverConfig)
		certificate := protocolCertificate(t)
		leaf, _ := pem.Decode([]byte(strings.Join(certificate.Certs[0].CertStr, "\n")))
		digest := sha256.Sum256(leaf.Bytes)
		pin = hex.EncodeToString(digest[:])
		tlsSettings, err := certificate.Build()
		if err != nil {
			t.Fatal(err)
		}
		receiver.StreamSettings.SecurityType = serial.GetMessageType(tlsSettings)
		receiver.StreamSettings.SecuritySettings = []*serial.TypedMessage{serial.ToTypedMessage(tlsSettings)}
		inbound.ReceiverSettings = serial.ToTypedMessage(receiver)
	}
	user := panel.UserInfo{Id: 1, Uuid: protocolTestUUID}
	c.LimiterManager.Add("protocol-test", []panel.UserInfo{user}, nil, name)
	if err := c.AddNodeConfig(inbound); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AddUsers(&AddUsersParams{Tag: "protocol-test", Users: []panel.UserInfo{user}, NodeInfo: info}); err != nil {
		t.Fatal(err)
	}
	manager, err := c.GetUserManager("protocol-test")
	if err != nil {
		t.Fatal(err)
	}
	waitProtocolUser(t, func() bool { return manager.GetUser(context.Background(), "protocol-test|"+user.Uuid) != nil })
	return c, port, info, user, pin
}

func protocolClient(t *testing.T, name string, port int, pin string) *xray.Instance {
	t.Helper()
	item := panel.Outbound{Name: "test-client", Protocol: name, Address: "127.0.0.1", Port: port, UUID: protocolTestUUID, Password: protocolTestUUID}
	if name == "hysteria2" {
		item.Protocol = "hysteria"
	}
	if name == "shadowsocks" {
		item.Cipher = "aes-128-gcm"
	}
	if name == "trojan" || name == "anytls" || name == "hysteria2" {
		item.Security = "tls"
		item.SNI = "localhost"
		network := "tcp"
		if name == "hysteria2" {
			network = "hysteria"
		}
		stream := map[string]any{"network": network, "security": "tls", "tlsSettings": map[string]any{"serverName": "localhost", "pinnedPeerCertSha256": pin}}
		if name == "hysteria2" {
			stream["hysteriaSettings"] = map[string]any{"version": 2, "auth": protocolTestUUID}
		}
		raw, _ := json.Marshal(stream)
		item.StreamSettings = string(raw)
	}
	built, err := outboundbuilder.Build(&panel.ServerConfigResponse{Data: &panel.Data{Outbound: &[]panel.Outbound{item}, Protocols: &[]panel.Protocol{}}}, false)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := (&coreConf.Config{LogConfig: &coreConf.LogConfig{LogLevel: "error"}}).Build()
	if err != nil {
		t.Fatal(err)
	}
	for _, outbound := range built.Outbounds {
		if outbound.Tag == item.Name {
			cfg.Outbound = []*xray.OutboundHandlerConfig{outbound}
		}
	}
	if len(cfg.Outbound) != 1 {
		t.Fatal("test client outbound missing")
	}
	client, err := xray.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

func TestUpgradedProtocolsRelayAndTrackUsers(t *testing.T) {
	for _, name := range []string{"vless", "vmess", "shadowsocks", "trojan", "anytls", "hysteria2", "tuic"} {
		t.Run(name, func(t *testing.T) {
			server, port, info, user, pin := protocolServer(t, name)
			echo, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer echo.Close()
			payload := []byte("ppnode protocol upgrade")
			go func() {
				conn, err := echo.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(8 * time.Second))
				body := make([]byte, len(payload))
				if _, err := io.ReadFull(conn, body); err == nil {
					conn.Write(body)
				}
			}()
			target := xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(echo.Addr().(*net.TCPAddr).Port))
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			var conn io.ReadWriteCloser
			if name == "tuic" {
				conn = dialTUIC(t, ctx, port, target)
			} else {
				stream, err := xray.Dial(ctx, protocolClient(t, name, port, pin), target)
				if err != nil {
					t.Fatal(err)
				}
				conn = stream
			}
			defer conn.Close()
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Fatal(err)
			}
			if string(got) != string(payload) {
				t.Fatalf("echo = %q", got)
			}
			traffic, err := server.GetUserTrafficSlice("protocol-test", 0)
			if err != nil || len(traffic) != 1 || traffic[0].Upload < int64(len(payload)) || traffic[0].Download < int64(len(payload)) {
				t.Fatalf("traffic = %+v, %v", traffic, err)
			}
			limit, _ := server.LimiterManager.Get("protocol-test")
			online, _ := limit.GetOnlineDevice()
			if len(*online) != 1 {
				t.Fatalf("online = %+v", online)
			}
			conn.Close()
			if err := server.DelUsers([]panel.UserInfo{user}, "protocol-test", info); err != nil {
				t.Fatal(err)
			}
			manager, _ := server.GetUserManager("protocol-test")
			waitProtocolUser(t, func() bool { return manager.GetUser(context.Background(), "protocol-test|"+user.Uuid) == nil })
		})
	}
}

// The fork's TUIC outbound is not implemented. Exercise its new native inbound
// with a minimal TUIC v5 client using the protocol's actual authentication frame.
func dialTUIC(t *testing.T, ctx context.Context, port int, target xnet.Destination) io.ReadWriteCloser {
	t.Helper()
	conn, err := quic.DialAddr(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), &tls.Config{InsecureSkipVerify: true, ServerName: "localhost", NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.CloseWithError(0, "") })
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stream.SetDeadline(time.Now().Add(8 * time.Second))
	frame := []byte{tuictransport.TUICVersion, tuictransport.TUICCommandConnect, 1}
	frame = append(frame, target.Address.IP().To4()...)
	frame = append(frame, byte(target.Port>>8), byte(target.Port))
	if _, err := stream.Write(frame); err != nil {
		t.Fatal(err)
	}
	authenticateTUIC(t, ctx, conn)
	return stream
}

func waitProtocolUser(t *testing.T, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !ready() {
		if time.Now().After(deadline) {
			t.Fatal("protocol user update did not become visible")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Xray now blocks private destinations by default. Tests explicitly route only
// loopback to this test-only outbound, retaining production's security defaults.
func allowLoopbackForTest(t *testing.T, c *XrayCore) {
	t.Helper()
	settings := json.RawMessage(`{"finalRules":[{"action":"allow","ip":["127.0.0.0/8"]}]}`)
	cfg, err := (&coreConf.OutboundDetourConfig{Tag: "test-loopback", Protocol: "freedom", Settings: &settings}).Build()
	if err != nil {
		t.Fatal(err)
	}
	handler, err := xray.CreateObject(c.Server, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.ohm.AddHandler(context.Background(), handler.(outbound.Handler)); err != nil {
		t.Fatal(err)
	}
	rule := json.RawMessage(`{"type":"field","ip":["127.0.0.0/8"],"outboundTag":"test-loopback"}`)
	routes, err := (&coreConf.RouterConfig{RuleList: []json.RawMessage{rule}}).Build()
	if err != nil {
		t.Fatal(err)
	}
	router := c.Server.GetFeature(routing.RouterType()).(routing.Router)
	if err := router.AddRule(serial.ToTypedMessage(routes), true); err != nil {
		t.Fatal(err)
	}
}

func authenticateTUIC(t *testing.T, ctx context.Context, conn *quic.Conn) {
	t.Helper()
	id, err := uuid.ParseString(protocolTestUUID)
	if err != nil {
		t.Fatal(err)
	}
	state := conn.ConnectionState().TLS
	token, err := state.ExportKeyingMaterial(string(id[:]), []byte(protocolTestUUID), 32)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := conn.OpenUniStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	frame := []byte{tuictransport.TUICVersion, tuictransport.TUICCommandAuthenticate}
	frame = append(frame, id[:]...)
	frame = append(frame, token...)
	if _, err := auth.Write(frame); err != nil {
		t.Fatal(err)
	}
	auth.Close()
}

func TestTUICUDPBeforeAuthentication(t *testing.T) {
	for _, overStream := range []bool{false, true} {
		t.Run(strconv.FormatBool(overStream), func(t *testing.T) {
			server, port, _, _, _ := protocolServer(t, "tuic")
			echo, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer echo.Close()
			go func() {
				data := make([]byte, 1500)
				n, addr, err := echo.ReadFrom(data)
				if err == nil {
					echo.WriteTo(data[:n], addr)
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := quic.DialAddr(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.CloseWithError(0, "")
			payload := []byte("TUIC UDP regression")
			frame := []byte{5, 2, 0, 1, 0, 1, 1, 0, 0, byte(len(payload)), 1, 127, 0, 0, 1}
			targetPort := echo.LocalAddr().(*net.UDPAddr).Port
			frame = append(frame, byte(targetPort>>8), byte(targetPort))
			frame = append(frame, payload...)
			if overStream {
				stream, err := conn.OpenUniStreamSync(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := stream.Write(frame); err != nil {
					t.Fatal(err)
				}
				stream.Close()
			} else if err := conn.SendDatagram(frame); err != nil {
				t.Fatal(err)
			}
			authenticateTUIC(t, ctx, conn)
			var reply []byte
			if overStream {
				stream, err := conn.AcceptUniStream(ctx)
				if err != nil {
					t.Fatal(err)
				}
				reply, err = io.ReadAll(stream)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				reply, err = conn.ReceiveDatagram(ctx)
				if err != nil {
					t.Fatal(err)
				}
			}
			if len(reply) < 10 || reply[0] != 5 || reply[1] != 2 {
				t.Fatalf("bad UDP reply: %x", reply)
			}
			reader := bytes.NewReader(reply[10:])
			if _, err := tuictransport.ReadDestination(reader, xnet.Network_UDP); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, int(binary.BigEndian.Uint16(reply[8:10])))
			if _, err := io.ReadFull(reader, got); err != nil {
				t.Fatal(err)
			}
			if string(got) != string(payload) {
				t.Fatalf("UDP echo = %q", got)
			}
			traffic, _ := server.GetUserTrafficSlice("protocol-test", 0)
			if len(traffic) != 1 || traffic[0].Upload < int64(len(payload)) || traffic[0].Download < int64(len(payload)) {
				t.Fatalf("UDP traffic = %+v", traffic)
			}
		})
	}
}
