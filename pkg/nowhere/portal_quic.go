// Copyright (C) 2026 PPanel contributors <https://github.com/perfect-panel>
// SPDX-License-Identifier: GPL-3.0-or-later

package nowhere

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/sagernet/quic-go"
	M "github.com/sagernet/sing/common/metadata"
	"io"
	"net"
	"sync"
	"time"
)

const QUICApplicationError quic.ApplicationErrorCode = 1

func (p *Portal) HandleQUIC(ctx context.Context, c *quic.Conn, alpn string) {
	p.HandleQUICWithOptions(ctx, c, alpn, CarrierOptions{})
}
func (p *Portal) HandleQUICWithOptions(ctx context.Context, c *quic.Conn, alpn string, options CarrierOptions) {
	if c == nil {
		return
	}
	state := c.ConnectionState()
	if alpn != DefaultALPN || state.TLS.Version != tls.VersionTLS13 || state.TLS.NegotiatedProtocol != DefaultALPN {
		_ = c.CloseWithError(QUICApplicationError, "invalid transport")
		return
	}
	exported, err := state.TLS.ExportKeyingMaterial(AuthExporterLabel, []byte{}, TLSExporterLen)
	if err != nil {
		_ = c.CloseWithError(QUICApplicationError, "exporter failed")
		return
	}
	var exporter TLSExporter
	copy(exporter[:], exported)
	deadline := time.Now().Add(p.handshakeTimeout)
	authCtx, cancel := context.WithDeadline(ctx, deadline)
	first, err := c.AcceptStream(authCtx)
	cancel()
	if err != nil || first.StreamID() != 0 {
		_ = c.CloseWithError(QUICApplicationError, "invalid authentication stream")
		return
	}
	_ = first.SetDeadline(deadline)
	frame, err := ReadAuthFrame(first)
	var authentication Authentication
	if err == nil {
		if p.morph {
			selected, ok := morphQUICSelection(c.Context())
			if !ok {
				err = ErrAuthentication
			} else {
				authentication, err = p.authenticator.authenticateSelected(frame, AuthTransportQUIC, exporter, remoteIP(c.RemoteAddr()), selected)
			}
		} else {
			authentication, err = p.authenticator.AuthenticateConnection(frame, AuthTransportQUIC, exporter, remoteIP(c.RemoteAddr()))
		}
	}
	if err != nil || time.Now().After(deadline) {
		waitUntil(ctx, deadline)
		_ = c.CloseWithError(QUICApplicationError, "authentication failed")
		p.report(ctx, err)
		return
	}
	connection, err := p.registry.Register(c.Context(), p.authenticator, authentication, func() { _ = c.CloseWithError(QUICApplicationError, "connection closed") })
	if err != nil {
		_ = c.CloseWithError(QUICApplicationError, "connection limit")
		return
	}
	defer connection.Close()
	if options.OnAuthenticated != nil {
		options.OnAuthenticated()
	}
	_ = first.SetDeadline(time.Time{})
	session, err := newQUICSession(connection.ctx, p, c)
	if err != nil {
		return
	}
	session.link = connection
	defer session.Close()
	go session.datagramLoop()
	var workers sync.WaitGroup
	defer workers.Wait()
	defer connection.Close()
	go func() {
		select {
		case <-ctx.Done():
			connection.Close()
		case <-connection.ctx.Done():
		}
	}()
	workers.Go(func() { p.handleFirstQUICStream(connection.ctx, session, first) })
	for {
		stream, err := c.AcceptStream(connection.ctx)
		if err != nil {
			return
		}
		if uint64(stream.StreamID())&3 != 0 {
			_ = c.CloseWithError(QUICApplicationError, "invalid flow initiator")
			return
		}
		lease, err := connection.Acquire(FlowKindTCP)
		if err != nil {
			_ = stream.SetWriteDeadline(time.Now().Add(p.handshakeTimeout))
			_ = WriteSetupResult(stream, SetupFlowLimit)
			stream.CancelRead(0)
			_ = stream.Close()
			continue
		}
		workers.Go(func() { p.processQUICStream(connection.ctx, session, stream, lease) })
	}
}
func (p *Portal) handleFirstQUICStream(ctx context.Context, s *quicSession, stream *quic.Stream) {
	_ = stream.SetReadDeadline(time.Now().Add(p.flowSetupTimeout))
	var first [1]byte
	n, err := stream.Peek(first[:])
	_ = stream.SetReadDeadline(time.Time{})
	if n == 0 && errors.Is(err, io.EOF) {
		_ = stream.Close()
		return
	}
	if err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return
	}
	lease, err := s.link.Acquire(FlowKindTCP)
	if err != nil {
		_ = WriteSetupResult(stream, SetupFlowLimit)
		stream.CancelRead(0)
		_ = stream.Close()
		return
	}
	p.processQUICStream(ctx, s, stream, lease)
}
func (p *Portal) processQUICStream(ctx context.Context, s *quicSession, stream *quic.Stream, lease *FlowLease) {
	lane := newQUICStreamConn(s.conn, stream)
	header, target, deadline, err := p.readFlow(lane)
	if err != nil {
		_ = WriteSetupResult(lane, SetupInvalidRequest)
		_ = lane.Close()
		lease.Close()
		p.report(ctx, fmt.Errorf("nowhere: flow setup: %w", err))
		return
	}
	writer := &lockedWriter{writer: lane}
	if header.Kind == FlowKindTCP {
		p.dispatchTCP(ctx, &TCPFlow{setupDeadline: deadline, Authentication: s.link.Authentication, Target: target, Reader: lane, Writer: writer, Result: func(code SetupResult) error { return WriteSetupResult(writer, code) }, Lease: lease, close: lane.closeFunc(), LocalAddr: lane.LocalAddr(), RemoteAddr: lane.RemoteAddr()})
		return
	}
	id, err := UDPFlowID(uint64(stream.StreamID()))
	if err != nil {
		_ = WriteSetupResult(lane, SetupFlowLimit)
		_ = lane.Close()
		lease.Close()
		s.link.Close()
		return
	}
	state := s.conn.ConnectionState()
	if !state.SupportsDatagrams.Local || !state.SupportsDatagrams.Remote {
		_ = WriteSetupResult(lane, SetupInvalidRequest)
		_ = lane.Close()
		lease.Close()
		return
	}
	p.submitQUICUDP(ctx, lane, s, id, target, lease, deadline)
}
func (p *Portal) submitQUICUDP(ctx context.Context, lane *quicStreamConn, s *quicSession, id FlowID, target M.Socksaddr, lease *FlowLease, deadline time.Time) {
	uplink, err := s.installUDPFlow(id)
	if err != nil {
		_ = WriteSetupResult(lane, SetupFlowLimit)
		_ = lane.Close()
		lease.Close()
		return
	}
	flowCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	closeFlow := sync.OnceFunc(func() {
		cancel()
		close(done)
		if s.flowReady(id) {
			s.sendClose(id)
		}
		s.removeUDPFlow(id)
		lease.Close()
		_ = lane.Close()
	})
	s.setUDPCloser(id, closeFlow)
	writer := &lockedWriter{writer: lane}
	flow := &UDPFlow{setupDeadline: deadline, Authentication: s.link.Authentication, Target: target, Reader: uplink, Writer: &quicPacketSink{session: s, flowID: id}, Lease: lease, close: closeFlow, LocalAddr: lane.LocalAddr(), RemoteAddr: lane.RemoteAddr(),
		Result: func(code SetupResult) error {
			if code == SetupReady {
				if err := s.prepareUDPFlow(id); err != nil {
					return err
				}
			}
			if err := WriteSetupResult(writer, code); err != nil {
				return err
			}
			if code == SetupReady {
				s.activateUDPFlow(id)
			}
			return nil
		}}
	go func() { var b [1]byte; _, _ = lane.Read(b[:]); closeFlow() }()
	go func() {
		select {
		case <-lane.stream.Context().Done():
			closeFlow()
		case <-done:
		}
	}()
	p.dispatchUDP(flowCtx, flow)
}

type quicStreamConn struct {
	stream *quic.Stream
	conn   *quic.Conn
	once   sync.Once
}

func newQUICStreamConn(conn *quic.Conn, stream *quic.Stream) *quicStreamConn {
	return &quicStreamConn{conn: conn, stream: stream}
}

func (conn *quicStreamConn) Read(output []byte) (int, error)   { return conn.stream.Read(output) }
func (conn *quicStreamConn) Write(input []byte) (int, error)   { return conn.stream.Write(input) }
func (conn *quicStreamConn) LocalAddr() net.Addr               { return conn.conn.LocalAddr() }
func (conn *quicStreamConn) RemoteAddr() net.Addr              { return conn.conn.RemoteAddr() }
func (conn *quicStreamConn) SetDeadline(value time.Time) error { return conn.stream.SetDeadline(value) }
func (conn *quicStreamConn) SetReadDeadline(value time.Time) error {
	return conn.stream.SetReadDeadline(value)
}
func (conn *quicStreamConn) SetWriteDeadline(value time.Time) error {
	return conn.stream.SetWriteDeadline(value)
}
func (conn *quicStreamConn) CloseRead() error {
	conn.stream.CancelRead(0)
	return nil
}
func (conn *quicStreamConn) CloseWrite() error { return conn.stream.Close() }
func (conn *quicStreamConn) Close() error {
	var closeErr error
	conn.once.Do(func() {
		conn.stream.CancelRead(0)
		closeErr = conn.stream.Close()
	})
	return closeErr
}
func (conn *quicStreamConn) closeFunc() func() {
	return sync.OnceFunc(func() { _ = conn.Close() })
}

var _ net.Conn = (*quicStreamConn)(nil)
