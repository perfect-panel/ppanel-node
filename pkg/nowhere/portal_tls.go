// Copyright (C) 2026 PPanel contributors <https://github.com/perfect-panel>
// SPDX-License-Identifier: GPL-3.0-or-later

package nowhere

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

var (
	ErrTLSHandshake = errors.New("nowhere: TLS handshake failed")
	ErrTLSALPN      = errors.New("nowhere: nw3 ALPN was not negotiated")
)

func (portal *Portal) HandleTLS(ctx context.Context, raw net.Conn, tlsConfig *tls.Config, alpn string) {
	portal.HandleTLSWithOptions(ctx, raw, tlsConfig, alpn, CarrierOptions{})
}
func (portal *Portal) HandleTLSWithOptions(ctx context.Context, raw net.Conn, tlsConfig *tls.Config, alpn string, options CarrierOptions) {
	if raw == nil || tlsConfig == nil || alpn != DefaultALPN {
		if raw != nil {
			_ = raw.Close()
		}
		portal.report(ctx, ErrTLSHandshake)
		return
	}
	deadline := time.Now().Add(portal.handshakeTimeout)
	_ = raw.SetDeadline(deadline)
	stopOnCancel := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stopOnCancel()
	// Morph wrapping is installed before TLS so the exporter remains bound to
	// the actual TLS handshake and is never replaced by outer metadata.
	var masked *morphTCPConn
	if portal.morph {
		if err := setCarrierLinger(raw, 0); err != nil {
			_ = raw.Close()
			portal.report(ctx, err)
			return
		}
		var err error
		masked, tlsConfig, err = portal.acceptMorphTCP(raw, tlsConfig, deadline)
		if err != nil {
			waitUntil(ctx, deadline)
			_ = raw.Close()
			portal.report(ctx, err)
			return
		}
	}
	carrier := raw
	if masked != nil {
		carrier = masked
	}
	secure := tls.Server(carrier, tlsConfig)
	handshakeCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if err := secure.HandshakeContext(handshakeCtx); err != nil {
		if portal.morph {
			waitUntil(ctx, deadline)
		}
		_ = raw.Close()
		portal.report(ctx, fmt.Errorf("%w: %v", ErrTLSHandshake, err))
		return
	}
	state := secure.ConnectionState()
	if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != DefaultALPN {
		_ = raw.Close()
		portal.report(ctx, ErrTLSALPN)
		return
	}
	exported, err := state.ExportKeyingMaterial(AuthExporterLabel, []byte{}, TLSExporterLen)
	if err != nil {
		_ = raw.Close()
		portal.report(ctx, err)
		return
	}
	var exporter TLSExporter
	copy(exporter[:], exported)
	frame, err := ReadAuthFrame(secure)
	var authentication Authentication
	if err == nil {
		if masked != nil {
			authentication, err = portal.authenticator.authenticateSelected(frame, AuthTransportTLSTCP, exporter, physicalRemoteIP(raw), masked.authentication)
		} else {
			authentication, err = portal.authenticator.AuthenticateConnection(frame, AuthTransportTLSTCP, exporter, physicalRemoteIP(raw))
		}
	}
	if err == nil && time.Now().After(deadline) {
		err = context.DeadlineExceeded
	}
	if err != nil {
		waitUntil(ctx, deadline)
		_ = raw.Close()
		portal.report(ctx, fmt.Errorf("nowhere: TLS authentication: %w", err))
		return
	}
	connection, err := portal.registry.Register(ctx, portal.authenticator, authentication, func() { _ = secure.Close() })
	if err != nil {
		_ = raw.Close()
		return
	}
	if portal.morph {
		if time.Now().After(deadline) || handshakeCtx.Err() != nil {
			connection.Close()
			return
		}
		if err = setCarrierLinger(raw, -1); err != nil {
			connection.Close()
			return
		}
		if time.Now().After(deadline) || handshakeCtx.Err() != nil {
			_ = setCarrierLinger(raw, 0)
			connection.Close()
			return
		}
	}
	if options.OnAuthenticated != nil {
		options.OnAuthenticated()
	}
	_ = secure.SetDeadline(time.Time{})
	portal.serveTLSFlow(connection.ctx, secure, connection)
}
func remoteIP(address net.Addr) netip.Addr {
	switch value := address.(type) {
	case *net.TCPAddr:
		return value.AddrPort().Addr().Unmap()
	case *net.UDPAddr:
		return value.AddrPort().Addr().Unmap()
	default:
		return netip.Addr{}
	}
}
func waitUntil(ctx context.Context, deadline time.Time) {
	duration := time.Until(deadline)
	if duration <= 0 {
		return
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}
