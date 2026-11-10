// Copyright (C) 2026 PPanel contributors <https://github.com/perfect-panel>
// SPDX-License-Identifier: GPL-3.0-or-later

package nowhere

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"time"

	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	DefaultHandshakeTimeout = 10 * time.Second
	DefaultUDPIdleTimeout   = 2 * time.Minute
	DefaultFlowSetupTimeout = 10 * time.Second
)

var ErrInvalidPortalOptions = errors.New("nowhere: invalid portal options")
var ErrSetupPending = errors.New("nowhere: flow is not ready")

type ServerHandler interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}
type ErrorHandler func(context.Context, error)
type CarrierOptions struct{ OnAuthenticated func() }
type PortalOptions struct {
	Handler          ServerHandler
	ErrorHandler     ErrorHandler
	Authenticator    *Authenticator
	Registry         *FlowRegistry
	HandshakeTimeout time.Duration
	FlowSetupTimeout time.Duration
	UDPIdleTimeout   time.Duration
	Morph            bool
}
type Portal struct {
	handler          ServerHandler
	errorHandler     ErrorHandler
	authenticator    *Authenticator
	registry         *FlowRegistry
	handshakeTimeout time.Duration
	flowSetupTimeout time.Duration
	udpIdleTimeout   time.Duration
	morph            bool
	prelude          *preludeReplay
}

func NewPortal(options PortalOptions) (*Portal, error) {
	if isNilInterface(options.Handler) || options.ErrorHandler == nil || options.Authenticator == nil || options.Registry == nil {
		return nil, ErrInvalidPortalOptions
	}
	if options.HandshakeTimeout == 0 {
		options.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if options.FlowSetupTimeout == 0 {
		options.FlowSetupTimeout = DefaultFlowSetupTimeout
	}
	if options.UDPIdleTimeout == 0 {
		options.UDPIdleTimeout = DefaultUDPIdleTimeout
	}
	if options.HandshakeTimeout < 0 || options.FlowSetupTimeout < 0 || options.UDPIdleTimeout < 0 {
		return nil, ErrInvalidPortalOptions
	}
	var prelude *preludeReplay
	if options.Morph {
		prelude = newPreludeReplay(16384)
	}
	return &Portal{handler: options.Handler, errorHandler: options.ErrorHandler, authenticator: options.Authenticator, registry: options.Registry,
		handshakeTimeout: options.HandshakeTimeout, flowSetupTimeout: options.FlowSetupTimeout, udpIdleTimeout: options.UDPIdleTimeout, morph: options.Morph, prelude: prelude}, nil
}
func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}
func (portal *Portal) Authenticator() *Authenticator { return portal.authenticator }
func (portal *Portal) Registry() *FlowRegistry       { return portal.registry }
func (portal *Portal) readFlow(lane net.Conn) (FlowHeader, M.Socksaddr, time.Time, error) {
	deadline := time.Now().Add(portal.flowSetupTimeout)
	_ = lane.SetDeadline(deadline)
	header, err := ReadFlowHeader(lane)
	if err != nil {
		return header, M.Socksaddr{}, deadline, err
	}
	target, err := ReadTarget(lane)
	if err != nil {
		return header, M.Socksaddr{}, deadline, err
	}
	_ = lane.SetDeadline(time.Time{})
	return header, target, deadline, nil
}
func (portal *Portal) serveTLSFlow(ctx context.Context, lane net.Conn, connection *Connection) {
	lease, err := connection.Acquire(FlowKindTCP)
	if err != nil {
		_ = WriteSetupResult(lane, SetupFlowLimit)
		connection.Close()
		return
	}
	header, target, deadline, err := portal.readFlow(lane)
	if err != nil {
		_ = WriteSetupResult(lane, SetupInvalidRequest)
		lease.Close()
		connection.Close()
		portal.report(ctx, fmt.Errorf("nowhere: read flow: %w", err))
		return
	}
	writer := &lockedWriter{writer: lane}
	result := func(code SetupResult) error { return WriteSetupResult(writer, code) }
	if header.Kind == FlowKindTCP {
		portal.dispatchTCP(ctx, &TCPFlow{setupDeadline: deadline, Authentication: connection.Authentication, Target: target, Reader: lane, Writer: writer, Result: result, Lease: lease, close: connection.Close, LocalAddr: lane.LocalAddr(), RemoteAddr: lane.RemoteAddr()})
	} else {
		portal.dispatchUDP(ctx, &UDPFlow{setupDeadline: deadline, Authentication: connection.Authentication, Target: target, Reader: &uotPacketSource{reader: lane}, Writer: &uotPacketSink{writer: writer}, Result: result, Lease: lease, close: connection.Close, LocalAddr: lane.LocalAddr(), RemoteAddr: lane.RemoteAddr()})
	}
}
func (portal *Portal) dispatchTCP(ctx context.Context, flow *TCPFlow) {
	if flow.Lease != nil {
		ctx = flow.Lease.ctx
	}
	conn := newTCPFlowConn(flow)
	flowCtx := auth.ContextWithUser(ctx, flow.Authentication.Identity)
	portal.handler.NewConnectionEx(flowCtx, conn, M.SocksaddrFromNet(flow.RemoteAddr).Unwrap(), flow.Target, nil)
}
func (portal *Portal) dispatchUDP(ctx context.Context, flow *UDPFlow) {
	if flow.Lease != nil {
		ctx = flow.Lease.ctx
	}
	conn := newPacketFlowConn(flow, portal.udpIdleTimeout)
	flowCtx := auth.ContextWithUser(ctx, flow.Authentication.Identity)
	portal.handler.NewPacketConnectionEx(flowCtx, conn, M.SocksaddrFromNet(flow.RemoteAddr).Unwrap(), flow.Target, nil)
}
func (portal *Portal) report(ctx context.Context, err error) {
	if err != nil {
		portal.errorHandler(ctx, err)
	}
}
