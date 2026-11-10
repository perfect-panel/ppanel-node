// Copyright (C) 2026 PPanel contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package nowhere

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	nw "github.com/perfect-panel/nowhere"
	"github.com/perfect-panel/ppanel-node/common/logx"
	"github.com/sagernet/quic-go"
	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	xray "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Handler is a workerless Xray inbound: Morph must see raw TCP/UDP before TLS
// and QUIC, so the portal owns both listeners rather than using Xray transports.
type Handler struct {
	ctx             context.Context
	cancel          context.CancelFunc
	config          *Config
	tag             string
	tls             *tls.Config
	dispatcher      routing.Dispatcher
	auth            *nw.Authenticator
	registry        *nw.FlowRegistry
	portal          *nw.Portal
	usersMu         sync.RWMutex
	userUpdateMu    sync.Mutex
	users           map[string]*protocol.MemoryUser
	mu              sync.Mutex
	started, closed bool
	tcp             net.Listener
	packet          net.PacketConn
	transport       *quic.Transport
	quic            *quic.Listener
	wg              sync.WaitGroup
	handshakeMu     sync.Mutex
	handshakes      int
	handshakeIPs    map[netip.Addr]int
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		h, err := newHandler(ctx, cfg.(*Config))
		if err != nil {
			return nil, err
		}
		if err = xray.RequireFeatures(ctx, func(d routing.Dispatcher) { h.dispatcher = d }); err != nil {
			_ = h.Close()
			return nil, err
		}
		return h, nil
	}))
}

func newHandler(ctx context.Context, cfg *Config) (*Handler, error) {
	tlsConfig, err := loadTLS(cfg)
	if err != nil {
		return nil, err
	}
	registry, err := nw.NewFlowRegistry(nw.DefaultRegistryConfig())
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	h := &Handler{ctx: ctx, cancel: cancel, config: cfg, tls: tlsConfig, auth: nw.NewAuthenticator(), registry: registry,
		users: make(map[string]*protocol.MemoryUser), handshakeIPs: make(map[netip.Addr]int)}
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		h.tag = inbound.Tag
	}
	h.portal, err = nw.NewPortal(nw.PortalOptions{Handler: h, Authenticator: h.auth, Registry: registry, Morph: cfg.Morph, ErrorHandler: func(_ context.Context, err error) {
		logx.Component("nowhere").WithError(err).Debug("Nowhere session ended")
	}})
	if err != nil {
		cancel()
		_ = registry.Close()
		return nil, err
	}
	return h, nil
}

func (*Handler) Network() []xnet.Network { return nil }
func (*Handler) Process(context.Context, xnet.Network, stat.Connection, routing.Dispatcher) error {
	return errors.New("nowhere owns its carrier listeners")
}

func (h *Handler) Start() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return net.ErrClosed
	}
	if h.started {
		return nil
	}
	if h.dispatcher == nil || h.tag == "" {
		return errors.New("nowhere: missing dispatcher or inbound tag")
	}
	lc := net.ListenConfig{}
	var err error
	if h.config.Network&NetworkTCP != 0 {
		h.tcp, err = lc.Listen(h.ctx, "tcp", h.config.Listen)
		if err != nil {
			return err
		}
	}
	if h.config.Network&NetworkQUIC != 0 {
		address := h.config.Listen
		if _, port, _ := net.SplitHostPort(address); port == "0" && h.tcp != nil {
			address = h.tcp.Addr().String()
		}
		h.packet, err = lc.ListenPacket(h.ctx, "udp", address)
		if err != nil {
			h.closeSockets()
			return err
		}
		if socket, ok := h.packet.(*net.UDPConn); ok {
			_ = socket.SetReadBuffer(4 << 20)
			_ = socket.SetWriteBuffer(4 << 20)
		}
		h.transport = &quic.Transport{Conn: h.packet, VerifySourceAddress: func(net.Addr) bool { return true }, ConnContext: h.quicContext}
		cfg := h.portal.ConfigureQUICTransport(h.transport, &quic.Config{
			HandshakeIdleTimeout: nw.DefaultHandshakeTimeout, MaxIdleTimeout: nw.DefaultUDPIdleTimeout, KeepAlivePeriod: 10 * time.Second,
			InitialStreamReceiveWindow: 8 << 20, MaxStreamReceiveWindow: 8 << 20,
			InitialConnectionReceiveWindow: 64 << 10, MaxConnectionReceiveWindow: 16 << 20,
			MaxIncomingStreams: nw.DefaultSessionTCPFlows + nw.DefaultSessionUDPFlows, MaxIncomingUniStreams: -1, EnableDatagrams: true,
		})
		h.packet = h.transport.Conn
		h.quic, err = h.transport.Listen(h.tls, cfg)
		if err != nil {
			h.closeSockets()
			return err
		}
	}
	h.started = true
	if h.tcp != nil {
		h.wg.Add(1)
		go h.acceptTCP()
	}
	if h.quic != nil {
		h.wg.Add(1)
		go h.acceptQUIC()
	}
	return nil
}

// Addr is the bound carrier address, useful when port zero was requested.
func (h *Handler) Addr(network string) net.Addr {
	h.mu.Lock()
	defer h.mu.Unlock()
	if network == "tcp" && h.tcp != nil {
		return h.tcp.Addr()
	}
	if network == "udp" && h.packet != nil {
		return h.packet.LocalAddr()
	}
	return nil
}

func (h *Handler) Close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	h.cancel()
	h.closeSockets()
	h.mu.Unlock()
	err := h.registry.Close()
	h.wg.Wait()
	return err
}

func (h *Handler) closeSockets() {
	if h.tcp != nil {
		_ = h.tcp.Close()
	}
	if h.quic != nil {
		_ = h.quic.Close()
	}
	if h.transport != nil {
		_ = h.transport.Close()
	}
	if h.packet != nil {
		_ = h.packet.Close()
	}
}

func (h *Handler) acquireHandshake(ip netip.Addr) (func(), bool) {
	ip = ip.Unmap()
	if !ip.IsValid() {
		return nil, false
	}
	h.handshakeMu.Lock()
	defer h.handshakeMu.Unlock()
	if h.handshakes >= 256 || h.handshakeIPs[ip] >= 32 {
		return nil, false
	}
	h.handshakes++
	h.handshakeIPs[ip]++
	return sync.OnceFunc(func() {
		h.handshakeMu.Lock()
		defer h.handshakeMu.Unlock()
		h.handshakes--
		h.handshakeIPs[ip]--
		if h.handshakeIPs[ip] == 0 {
			delete(h.handshakeIPs, ip)
		}
	}), true
}

func sourceIP(address net.Addr) netip.Addr {
	switch a := address.(type) {
	case *net.TCPAddr:
		return a.AddrPort().Addr().Unmap()
	case *net.UDPAddr:
		return a.AddrPort().Addr().Unmap()
	}
	return netip.Addr{}
}

func (h *Handler) acceptTCP() {
	defer h.wg.Done()
	for {
		conn, err := h.tcp.Accept()
		if err != nil {
			return
		}
		release, ok := h.acquireHandshake(sourceIP(conn.RemoteAddr()))
		if !ok {
			_ = conn.Close()
			continue
		}
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			defer release()
			h.portal.HandleTLSWithOptions(h.ctx, conn, h.tls, ALPN, nw.CarrierOptions{OnAuthenticated: release})
		}()
	}
}

type quicAdmissionKey struct{}
type quicAdmission struct{ release func() }

func (h *Handler) quicContext(ctx context.Context, client *quic.ClientInfo) (context.Context, error) {
	release, ok := h.acquireHandshake(sourceIP(client.RemoteAddr))
	if !ok {
		return ctx, errors.New("nowhere: handshake limit")
	}
	stop := context.AfterFunc(ctx, release)
	return context.WithValue(ctx, quicAdmissionKey{}, quicAdmission{func() { stop(); release() }}), nil
}

func (h *Handler) acceptQUIC() {
	defer h.wg.Done()
	for {
		conn, err := h.quic.Accept(h.ctx)
		if err != nil {
			return
		}
		admission, ok := conn.Context().Value(quicAdmissionKey{}).(quicAdmission)
		if !ok {
			_ = conn.CloseWithError(nw.QUICApplicationError, "missing handshake admission")
			continue
		}
		nw.ConfigureQUICCongestion(conn)
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			defer admission.release()
			h.portal.HandleQUICWithOptions(h.ctx, conn, ALPN, nw.CarrierOptions{OnAuthenticated: admission.release})
		}()
	}
}

var _ proxy.Inbound = (*Handler)(nil)
var _ common.Runnable = (*Handler)(nil)

func (h *Handler) String() string { return fmt.Sprintf("nowhere(%s)", h.tag) }
