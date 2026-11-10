// Copyright (C) 2026 PPanel contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package nowhere

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"

	nw "github.com/perfect-panel/nowhere"
	ppdispatcher "github.com/perfect-panel/ppanel-node/core/app/dispatcher"
	"github.com/sagernet/sing/common/auth"
	sbuf "github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
)

func (h *Handler) flowContext(ctx context.Context, source M.Socksaddr) (context.Context, error) {
	identity, ok := auth.UserFromContext[string](ctx)
	if !ok || !source.Addr.IsValid() {
		return nil, errors.New("nowhere: missing authenticated user or source IP")
	}
	user := h.GetUser(ctx, identity)
	if user == nil {
		return nil, errors.New("nowhere: user was revoked")
	}
	return session.ContextWithInbound(ctx, &session.Inbound{Tag: h.tag, Name: "nowhere", User: user,
		Source: xnet.TCPDestination(xnet.IPAddress(source.Addr.AsSlice()), xnet.Port(source.Port)), CanSpliceCopy: 3}), nil
}

func destination(addr M.Socksaddr, network xnet.Network) (xnet.Destination, error) {
	if !addr.IsValid() || addr.Port == 0 {
		return xnet.Destination{}, nw.ErrInvalidTarget
	}
	d := xnet.Destination{Network: network, Port: xnet.Port(addr.Port)}
	if addr.IsFqdn() {
		d.Address = xnet.DomainAddress(addr.Fqdn)
	} else {
		d.Address = xnet.IPAddress(addr.Addr.AsSlice())
	}
	return d, nil
}

// Xray's dispatcher performs admission before invoking the outbound. Confirm
// NW3 setup only when that outbound starts consuming or producing payload,
// so a quota rejection or a dial failure cannot become an optimistic Ready.
type flowSetup struct {
	conn  io.Closer
	once  sync.Once
	err   error
	ready atomic.Bool
}

func (s *flowSetup) confirm() error {
	s.once.Do(func() {
		if handshake, ok := s.conn.(N.HandshakeSuccess); ok {
			s.err = handshake.HandshakeSuccess()
		} else {
			s.err = errors.New("nowhere: missing setup reporter")
		}
		if s.err == nil {
			s.ready.Store(true)
		}
	})
	return s.err
}
func (s *flowSetup) fail(err error) {
	if err == nil {
		err = errors.New("outbound closed before setup")
	}
	code := nw.SetupDialFailed
	if errors.Is(err, ppdispatcher.ErrAdmissionRejected) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		code = nw.SetupFlowLimit
	}
	s.once.Do(func() { s.err = N.ReportHandshakeFailure(s.conn, nw.NewSetupError(code, err)) })
}
func (s *flowSetup) interrupt() {
	// Before Ready, leave the carrier open until DispatchLink returns its
	// rejection so the adapter can send the appropriate setup result.
	if s.ready.Load() {
		_ = s.conn.Close()
	}
}

func (h *Handler) NewConnectionEx(ctx context.Context, conn net.Conn, source, target M.Socksaddr, onClose N.CloseHandlerFunc) {
	setup := &flowSetup{conn: conn}
	var result error
	defer func() {
		setup.fail(result)
		_ = conn.Close()
		if onClose != nil {
			onClose(result)
		}
	}()
	ctx, result = h.flowContext(ctx, source)
	if result != nil {
		return
	}
	dest, err := destination(target, xnet.Network_TCP)
	if err != nil {
		result = err
		return
	}
	result = h.dispatcher.DispatchLink(ctx, dest, &transport.Link{Reader: &tcpReader{setup: setup, reader: buf.NewReader(conn)}, Writer: &tcpWriter{setup: setup, writer: buf.NewWriter(conn)}})
}

type tcpReader struct {
	setup  *flowSetup
	reader buf.Reader
}

func (r *tcpReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if err := r.setup.confirm(); err != nil {
		return nil, err
	}
	return r.reader.ReadMultiBuffer()
}
func (r *tcpReader) Interrupt() { r.setup.interrupt() }

type tcpWriter struct {
	setup  *flowSetup
	writer buf.Writer
}

func (w *tcpWriter) WriteMultiBuffer(data buf.MultiBuffer) error {
	if err := w.setup.confirm(); err != nil {
		buf.ReleaseMulti(data)
		return err
	}
	return w.writer.WriteMultiBuffer(data)
}
func (w *tcpWriter) Close() error {
	if !w.setup.ready.Load() {
		return nil
	}
	if half, ok := w.setup.conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}

func (h *Handler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source, target M.Socksaddr, onClose N.CloseHandlerFunc) {
	setup := &flowSetup{conn: conn}
	var result error
	defer func() {
		setup.fail(result)
		_ = conn.Close()
		if onClose != nil {
			onClose(result)
		}
	}()
	ctx, result = h.flowContext(ctx, source)
	if result != nil {
		return
	}
	dest, err := destination(target, xnet.Network_UDP)
	if err != nil {
		result = err
		return
	}
	result = h.dispatcher.DispatchLink(ctx, dest, &transport.Link{Reader: &packetReader{setup: setup, conn: conn}, Writer: &packetWriter{setup: setup, conn: conn, target: target}})
}

type packetReader struct {
	setup *flowSetup
	conn  N.PacketConn
}

func (r *packetReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if err := r.setup.confirm(); err != nil {
		return nil, err
	}
	data := sbuf.NewSize(nw.UDPPacketMax)
	defer data.Release()
	if _, err := r.conn.ReadPacket(data); err != nil {
		return nil, err
	}
	if data.Len() == 0 {
		return nil, nil
	} // Xray's buffer copier does not forward empty datagrams.
	packet := buf.NewWithSize(int32(data.Len()))
	_, _ = packet.Write(data.Bytes())
	return buf.MultiBuffer{packet}, nil
}
func (r *packetReader) Interrupt() { r.setup.interrupt() }

type packetWriter struct {
	setup  *flowSetup
	conn   N.PacketConn
	target M.Socksaddr
}

func (w *packetWriter) WriteMultiBuffer(packets buf.MultiBuffer) error {
	defer buf.ReleaseMulti(packets)
	if err := w.setup.confirm(); err != nil {
		return err
	}
	for _, packet := range packets {
		if packet.Len() > nw.UDPPacketMax {
			return nw.ErrInvalidUDPFrame
		}
		data := sbuf.NewSize(int(packet.Len()))
		_, _ = data.Write(packet.Bytes())
		// sing's PacketConn owns and releases the passed buffer on all paths.
		if err := w.conn.WritePacket(data, w.target); err != nil {
			return err
		}
	}
	return nil
}
func (w *packetWriter) Close() error {
	if w.setup.ready.Load() {
		return w.conn.Close()
	}
	return nil
}

var _ nw.ServerHandler = (*Handler)(nil)
