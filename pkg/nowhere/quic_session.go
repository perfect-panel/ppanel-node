// Copyright (C) 2026 PPanel contributors <https://github.com/perfect-panel>
// SPDX-License-Identifier: GPL-3.0-or-later

package nowhere

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
)

const (
	defaultQUICUDPFlowQueue  = 64
	defaultQUICUDPQueueBytes = 4 << 20
	datagramDrainQuiet       = 200 * time.Microsecond
)

var ErrQUICSessionClosed = errors.New("nowhere: QUIC session is closed")

type quicActivation struct {
	flowID FlowID
	ack    chan error
}

type quicUDPFlow struct {
	session  *quicSession
	flowID   FlowID
	incoming chan []byte
	ready    atomic.Bool
	close    func()
}

type quicSession struct {
	portal *Portal
	conn   *quic.Conn
	ctx    context.Context
	cancel context.CancelFunc
	link   *Connection

	mu          sync.Mutex
	flows       map[FlowID]*quicUDPFlow
	queuedBytes int
	closed      bool

	reassembler *DatagramReassembler
	activation  chan quicActivation
	receiveMu   sync.Mutex
	receiveStop context.CancelFunc
	packetID    atomic.Uint32
	closeOnce   sync.Once
}

func newQUICSession(parent context.Context, portal *Portal, conn *quic.Conn) (*quicSession, error) {
	ctx, cancel := context.WithCancel(parent)
	reassemblyConfig := DefaultReassemblyConfig()
	reassemblyConfig.MaxBytes = defaultQUICUDPQueueBytes
	reassembler, err := NewDatagramReassembler(reassemblyConfig)
	if err != nil {
		cancel()
		return nil, err
	}
	return &quicSession{
		portal: portal, conn: conn, ctx: ctx, cancel: cancel,
		flows: make(map[FlowID]*quicUDPFlow), reassembler: reassembler,
		activation: make(chan quicActivation, DefaultSessionUDPFlows),
	}, nil
}

func (session *quicSession) installUDPFlow(flowID FlowID) (*quicUDPFlow, error) {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed || session.flows[flowID] != nil {
		return nil, ErrQUICSessionClosed
	}
	flow := &quicUDPFlow{
		session: session, flowID: flowID,
		incoming: make(chan []byte, defaultQUICUDPFlowQueue),
	}
	session.flows[flowID] = flow
	return flow, nil
}

func (session *quicSession) prepareUDPFlow(flowID FlowID) error {
	request := quicActivation{flowID: flowID, ack: make(chan error, 1)}
	select {
	case session.activation <- request:
		session.interruptReceive()
	case <-session.ctx.Done():
		return ErrQUICSessionClosed
	}
	select {
	case err := <-request.ack:
		return err
	case <-session.ctx.Done():
		return ErrQUICSessionClosed
	}
}

func (session *quicSession) activateUDPFlow(flowID FlowID) {
	session.mu.Lock()
	if flow := session.flows[flowID]; !session.closed && flow != nil {
		flow.ready.Store(true)
	}
	session.mu.Unlock()
}

func (session *quicSession) interruptReceive() {
	session.receiveMu.Lock()
	if session.receiveStop != nil {
		session.receiveStop()
	}
	session.receiveMu.Unlock()
}

func (session *quicSession) datagramLoop() {
	for {
		select {
		case request := <-session.activation:
			session.commitActivation(request)
			continue
		default:
		}
		receiveCtx, cancel := context.WithCancel(session.ctx)
		session.receiveMu.Lock()
		session.receiveStop = cancel
		session.receiveMu.Unlock()
		select {
		case request := <-session.activation:
			session.clearReceiveStop()
			cancel()
			session.commitActivation(request)
			continue
		default:
		}
		data, err := session.conn.ReceiveDatagram(receiveCtx)
		session.clearReceiveStop()
		cancel()
		if err != nil {
			if session.ctx.Err() != nil {
				return
			}
			continue
		}
		session.handleDatagram(data)
	}
}

func (session *quicSession) clearReceiveStop() {
	session.receiveMu.Lock()
	// There is at most one receive in flight, so clearing the published
	// cancellation function cannot erase a newer operation.
	session.receiveStop = nil
	session.receiveMu.Unlock()
}

func (session *quicSession) commitActivation(request quicActivation) {
	deadline := time.Now().Add(session.portal.handshakeTimeout)
	drained := false
	for time.Now().Before(deadline) {
		drainCtx, cancel := context.WithTimeout(session.ctx, datagramDrainQuiet)
		data, err := session.conn.ReceiveDatagram(drainCtx)
		cancel()
		if err != nil {
			if session.ctx.Err() != nil || session.conn.Context().Err() != nil {
				request.ack <- ErrQUICSessionClosed
				return
			}
			drained = true
			break
		}
		// The flow is deliberately still not READY while the pre-activation
		// backlog is drained. Existing READY flows continue normally.
		session.handleDatagram(data)
	}
	if !drained {
		request.ack <- context.DeadlineExceeded
		return
	}
	session.mu.Lock()
	flowExists := !session.closed && session.flows[request.flowID] != nil
	session.mu.Unlock()
	if !flowExists {
		request.ack <- ErrQUICSessionClosed
		return
	}
	request.ack <- nil
}

func (session *quicSession) handleDatagram(data []byte) {
	frame, err := DecodeUDPFrame(data)
	if err != nil {
		return
	}
	switch frame.Type {
	case UDPFrameData:
		session.enqueuePacket(frame.FlowID, frame.Payload)
	case UDPFrameFragment:
		if !session.flowReady(frame.FlowID) {
			return
		}
		available := session.availableUDPBytes()
		payload, complete, pushErr := session.reassembler.PushWithLimit(frame, time.Now(), available)
		if pushErr == nil && complete {
			session.enqueuePacket(frame.FlowID, payload)
		}
	case UDPFrameClose:
		if session.flowReady(frame.FlowID) {
			session.closeUDPFlow(frame.FlowID)
		}
	}
}

func (session *quicSession) flowReady(flowID FlowID) bool {
	session.mu.Lock()
	flow := session.flows[flowID]
	ready := flow != nil && flow.ready.Load()
	session.mu.Unlock()
	return ready
}

func (session *quicSession) availableUDPBytes() int {
	session.mu.Lock()
	available := defaultQUICUDPQueueBytes - session.queuedBytes
	session.mu.Unlock()
	return max(0, available)
}

func (session *quicSession) enqueuePacket(flowID FlowID, payload []byte) {
	session.mu.Lock()
	defer session.mu.Unlock()
	flow := session.flows[flowID]
	if session.closed || flow == nil || !flow.ready.Load() ||
		session.queuedBytes+max(1, len(payload))+session.reassembler.ReservedBytes() > defaultQUICUDPQueueBytes {
		return
	}
	// DecodeUDPFrame returns a view over the uniquely owned datagram. Retaining
	// that view avoids a second copy; fragmented packets are already assembled
	// into their own allocation.
	select {
	case flow.incoming <- payload:
		session.queuedBytes += max(1, len(payload))
	default:
	}
}

func (session *quicSession) releaseQueued(length int) {
	session.mu.Lock()
	session.queuedBytes = max(0, session.queuedBytes-max(1, length))
	session.mu.Unlock()
}

func (session *quicSession) removeUDPFlow(flowID FlowID) {
	session.mu.Lock()
	flow := session.flows[flowID]
	if flow != nil {
		delete(session.flows, flowID)
		flow.ready.Store(false)
		for {
			select {
			case payload := <-flow.incoming:
				session.queuedBytes = max(0, session.queuedBytes-max(1, len(payload)))
			default:
				close(flow.incoming)
				session.mu.Unlock()
				session.reassembler.RemoveFlow(flowID)
				return
			}
		}
	}
	session.mu.Unlock()
	session.reassembler.RemoveFlow(flowID)
}

func (session *quicSession) sendPacket(flowID FlowID, payload []byte) error {
	frame, err := EncodeUDPData(flowID, payload)
	if err != nil {
		return err
	}
	err = session.conn.SendDatagram(frame)
	var tooLarge *quic.DatagramTooLargeError
	if !errors.As(err, &tooLarge) {
		return err
	}
	packetID := session.packetID.Add(1)
	if packetID == 0 {
		packetID = session.packetID.Add(1)
	}
	fragments, err := EncodeUDPFragments(flowID, packetID, payload, int(tooLarge.MaxDatagramPayloadSize))
	if err != nil {
		return err
	}
	for _, fragment := range fragments {
		if err = session.conn.SendDatagram(fragment); err != nil {
			return err
		}
	}
	return nil
}

func (session *quicSession) sendClose(flowID FlowID) {
	frame, err := EncodeUDPClose(flowID)
	if err == nil {
		_ = session.conn.SendDatagram(frame[:])
	}
}

func (session *quicSession) Close() {
	session.closeOnce.Do(func() {
		session.cancel()
		session.interruptReceive()
		session.mu.Lock()
		session.closed = true
		flowIDs := make([]FlowID, 0, len(session.flows))
		for flowID := range session.flows {
			flowIDs = append(flowIDs, flowID)
		}
		session.mu.Unlock()
		for _, flowID := range flowIDs {
			session.closeUDPFlow(flowID)
		}
		session.reassembler.Clear()
	})
}

func (flow *quicUDPFlow) ReadPacket(output []byte) (int, error) {
	select {
	case payload, open := <-flow.incoming:
		if !open {
			return 0, io.EOF
		}
		flow.session.releaseQueued(len(payload))
		if len(output) < len(payload) {
			return 0, io.ErrShortBuffer
		}
		return copy(output, payload), nil
	case <-flow.session.ctx.Done():
		return 0, io.EOF
	}
}

type quicPacketSink struct {
	session *quicSession
	flowID  FlowID
}

func (sink *quicPacketSink) WritePacket(payload []byte) error {
	return sink.session.sendPacket(sink.flowID, payload)
}

func (s *quicSession) setUDPCloser(id FlowID, closeFlow func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if flow := s.flows[id]; flow != nil {
		flow.close = closeFlow
	}
}
func (s *quicSession) closeUDPFlow(id FlowID) {
	s.mu.Lock()
	flow := s.flows[id]
	var closeFlow func()
	if flow != nil {
		closeFlow = flow.close
	}
	s.mu.Unlock()
	if closeFlow != nil {
		closeFlow()
	} else {
		s.removeUDPFlow(id)
	}
}
