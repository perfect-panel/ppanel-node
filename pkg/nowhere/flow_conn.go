// Copyright (C) 2026 PPanel contributors <https://github.com/perfect-panel>
// SPDX-License-Identifier: GPL-3.0-or-later

package nowhere

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var ErrSetupRejected = errors.New("nowhere: flow setup was rejected")

type tcpFlowConn struct {
	flow       *TCPFlow
	closeOnce  sync.Once
	resultOnce sync.Once
	resultErr  error
	resultCode SetupResult
	ready      atomic.Bool
	closed     chan struct{}
	setupDone  chan struct{}
}

func newTCPFlowConn(flow *TCPFlow) *tcpFlowConn {
	conn := &tcpFlowConn{flow: flow, closed: make(chan struct{}), setupDone: make(chan struct{})}
	if flow.Lease != nil || !flow.setupDeadline.IsZero() {
		go conn.monitorLease()
	}
	return conn
}

func (conn *tcpFlowConn) Read(output []byte) (int, error) {
	if !conn.ready.Load() {
		return 0, ErrSetupPending
	}
	return conn.flow.Reader.Read(output)
}
func (conn *tcpFlowConn) Write(input []byte) (int, error) {
	if !conn.ready.Load() {
		return 0, ErrSetupPending
	}
	return conn.flow.Writer.Write(input)
}

func (conn *tcpFlowConn) HandshakeSuccess() error { return conn.writeResult(SetupReady) }

func (conn *tcpFlowConn) HandshakeFailure(err error) error {
	return conn.writeResult(SetupResultFromError(err))
}

func (conn *tcpFlowConn) Reject(result SetupResult) error { return conn.writeResult(result) }

func (conn *tcpFlowConn) writeResult(result SetupResult) error {
	conn.resultOnce.Do(func() {
		defer close(conn.setupDone)
		select {
		case <-conn.closed:
			conn.resultErr = net.ErrClosed
			return
		default:
		}
		conn.resultCode = result
		if conn.flow.Result != nil {
			conn.resultErr = conn.flow.Result(result)
		}
		if conn.resultErr == nil && result == SetupReady {
			conn.ready.Store(true)
		}
	})
	if conn.resultErr != nil {
		return conn.resultErr
	}
	if conn.resultCode != result {
		return ErrSetupRejected
	}
	return nil
}

func (conn *tcpFlowConn) Close() error {
	conn.closeOnce.Do(func() {
		close(conn.closed)
		conn.flow.Close()
	})
	return nil
}

func (conn *tcpFlowConn) CloseRead() error {
	if closer, exists := conn.flow.Reader.(interface{ CloseRead() error }); exists {
		return closer.CloseRead()
	}
	return nil
}

func (conn *tcpFlowConn) CloseWrite() error {
	if closer, exists := conn.flow.Writer.(interface{ CloseWrite() error }); exists {
		return closer.CloseWrite()
	}
	return nil
}

func (conn *tcpFlowConn) LocalAddr() net.Addr {
	if conn.flow.LocalAddr != nil {
		return conn.flow.LocalAddr
	}
	return &net.TCPAddr{}
}

func (conn *tcpFlowConn) RemoteAddr() net.Addr {
	if conn.flow.RemoteAddr != nil {
		return conn.flow.RemoteAddr
	}
	return &net.TCPAddr{}
}

func (conn *tcpFlowConn) SetDeadline(deadline time.Time) error {
	readErr := conn.SetReadDeadline(deadline)
	writeErr := conn.SetWriteDeadline(deadline)
	if readErr != nil {
		return readErr
	}
	return writeErr
}

func (conn *tcpFlowConn) SetReadDeadline(deadline time.Time) error {
	if setter, exists := conn.flow.Reader.(interface{ SetReadDeadline(time.Time) error }); exists {
		return setter.SetReadDeadline(deadline)
	}
	return nil
}

func (conn *tcpFlowConn) SetWriteDeadline(deadline time.Time) error {
	if setter, exists := conn.flow.Writer.(interface{ SetWriteDeadline(time.Time) error }); exists {
		return setter.SetWriteDeadline(deadline)
	}
	return nil
}

func (conn *tcpFlowConn) monitorLease() {
	monitorFlow(conn.flow.Lease, conn.closed, conn.setupDone, conn.flow.setupDeadline, func() { _ = conn.Close() })
}

type packetFlowConn struct {
	flow        *UDPFlow
	closeOnce   sync.Once
	resultOnce  sync.Once
	resultErr   error
	resultCode  SetupResult
	ready       atomic.Bool
	closed      chan struct{}
	setupDone   chan struct{}
	optionsMu   sync.Mutex
	options     N.ReadWaitOptions
	idleMu      sync.Mutex
	idle        *time.Timer
	idleTimeout time.Duration
	lastActive  atomic.Int64
}

func newPacketFlowConn(flow *UDPFlow, idleTimeout time.Duration) *packetFlowConn {
	conn := &packetFlowConn{flow: flow, closed: make(chan struct{}), setupDone: make(chan struct{}), idleTimeout: idleTimeout}
	if idleTimeout > 0 {
		conn.lastActive.Store(time.Now().UnixNano())
		conn.idleMu.Lock()
		conn.idle = time.AfterFunc(idleTimeout, conn.expireIdle)
		conn.idleMu.Unlock()
	}
	if flow.Lease != nil || !flow.setupDeadline.IsZero() {
		go conn.monitorLease()
	}
	return conn
}

func (conn *packetFlowConn) HandshakeSuccess() error { return conn.writeResult(SetupReady) }

func (conn *packetFlowConn) HandshakeFailure(err error) error {
	return conn.writeResult(SetupResultFromError(err))
}

func (conn *packetFlowConn) Reject(result SetupResult) error { return conn.writeResult(result) }

func (conn *packetFlowConn) writeResult(result SetupResult) error {
	conn.resultOnce.Do(func() {
		defer close(conn.setupDone)
		select {
		case <-conn.closed:
			conn.resultErr = net.ErrClosed
			return
		default:
		}
		conn.resultCode = result
		if conn.flow.Result != nil {
			conn.resultErr = conn.flow.Result(result)
		}
		if conn.resultErr == nil && result == SetupReady {
			conn.ready.Store(true)
		}
	})
	if conn.resultErr != nil {
		return conn.resultErr
	}
	if conn.resultCode != result {
		return ErrSetupRejected
	}
	return nil
}

func (conn *packetFlowConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if !conn.ready.Load() {
		return M.Socksaddr{}, ErrSetupPending
	}
	n, err := conn.flow.Reader.ReadPacket(buffer.FreeBytes())
	if n > 0 {
		buffer.Extend(n)
	}
	if err != nil {
		return M.Socksaddr{}, err
	}
	conn.touchIdle()
	return conn.flow.Target, nil
}

func (conn *packetFlowConn) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	defer buffer.Release()
	if !conn.ready.Load() {
		return ErrSetupPending
	}
	err := conn.flow.Writer.WritePacket(buffer.Bytes())
	if err == nil {
		conn.touchIdle()
	}
	return err
}

func (conn *packetFlowConn) InitializeReadWaiter(options N.ReadWaitOptions) bool {
	conn.optionsMu.Lock()
	conn.options = options
	conn.optionsMu.Unlock()
	return false
}

func (conn *packetFlowConn) WaitReadPacket() (*buf.Buffer, M.Socksaddr, error) {
	if !conn.ready.Load() {
		return nil, M.Socksaddr{}, ErrSetupPending
	}
	conn.optionsMu.Lock()
	options := conn.options
	conn.optionsMu.Unlock()
	buffer := options.NewBufferSize(UDPPacketMax)
	n, err := conn.flow.Reader.ReadPacket(buffer.FreeBytes())
	if n > 0 {
		buffer.Extend(n)
	}
	if err != nil {
		buffer.Release()
		return nil, M.Socksaddr{}, err
	}
	conn.touchIdle()
	options.PostReturn(buffer)
	return buffer, conn.flow.Target, nil
}

func (conn *packetFlowConn) Close() error {
	conn.closeOnce.Do(func() {
		close(conn.closed)
		conn.idleMu.Lock()
		if conn.idle != nil {
			conn.idle.Stop()
		}
		conn.idleMu.Unlock()
		conn.flow.Close()
	})
	return nil
}

func (conn *packetFlowConn) touchIdle() {
	if conn.idleTimeout <= 0 {
		return
	}
	conn.lastActive.Store(time.Now().UnixNano())
	// The timer is rescheduled only when it fires. This keeps the UDP packet
	// fast path to one atomic store instead of Timer.Reset's global timer-heap
	// synchronization on every datagram.
}

func (conn *packetFlowConn) expireIdle() {
	for {
		select {
		case <-conn.closed:
			return
		default:
		}
		last := conn.lastActive.Load()
		remaining := conn.idleTimeout - time.Since(time.Unix(0, last))
		if remaining > 0 {
			conn.idleMu.Lock()
			select {
			case <-conn.closed:
				conn.idleMu.Unlock()
				return
			default:
				conn.idle.Reset(remaining)
				conn.idleMu.Unlock()
				return
			}
		}
		if conn.lastActive.Load() != last {
			continue
		}
		_ = conn.Close()
		return
	}
}

func (conn *packetFlowConn) LocalAddr() net.Addr {
	if conn.flow.LocalAddr != nil {
		return conn.flow.LocalAddr
	}
	return &net.UDPAddr{}
}

func (*packetFlowConn) SetDeadline(time.Time) error      { return nil }
func (*packetFlowConn) SetReadDeadline(time.Time) error  { return nil }
func (*packetFlowConn) SetWriteDeadline(time.Time) error { return nil }

func (conn *packetFlowConn) monitorLease() {
	monitorFlow(conn.flow.Lease, conn.closed, conn.setupDone, conn.flow.setupDeadline, func() { _ = conn.Close() })
}

var (
	_ net.Conn           = (*tcpFlowConn)(nil)
	_ N.HandshakeFailure = (*tcpFlowConn)(nil)
	_ N.PacketConn       = (*packetFlowConn)(nil)
	_ N.PacketReadWaiter = (*packetFlowConn)(nil)
	_ N.HandshakeFailure = (*packetFlowConn)(nil)
)

func monitorFlow(lease *FlowLease, closed, setupDone <-chan struct{}, deadline time.Time, closeFlow func()) {
	var leaseDone <-chan struct{}
	if lease != nil {
		leaseDone = lease.Done()
	}
	var timer *time.Timer
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		timer = time.NewTimer(time.Until(deadline))
		timeout = timer.C
		defer timer.Stop()
	}
	for {
		select {
		case <-closed:
			return
		case <-leaseDone:
			closeFlow()
			return
		case <-timeout:
			select {
			case <-setupDone:
				timeout = nil
				setupDone = nil
			default:
				closeFlow()
				return
			}
		case <-setupDone:
			if timer != nil {
				timer.Stop()
			}
			timeout = nil
			setupDone = nil
		}
	}
}
