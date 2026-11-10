// Copyright (C) 2026 PPanel contributors <https://github.com/perfect-panel>
// SPDX-License-Identifier: GPL-3.0-or-later

package nowhere

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestPortalDispatchUsesSingAuthenticatedUserContext(t *testing.T) {
	handler := &recordingServerHandler{}
	portal := testHandlerPortal(t, handler)
	result := make(chan SetupResult, 1)
	portal.dispatchTCP(t.Context(), &TCPFlow{
		Authentication: Authentication{Identity: "alice"},
		Target:         M.ParseSocksaddr("example.com:443"),
		Reader:         bytes.NewReader(nil),
		Writer:         io.Discard,
		Result: func(value SetupResult) error {
			result <- value
			return nil
		},
	})
	if handler.tcpUser != "alice" {
		t.Fatalf("authenticated user = %q", handler.tcpUser)
	}
	select {
	case value := <-result:
		if value != SetupReady {
			t.Fatalf("setup result = %d", value)
		}
	case <-time.After(time.Second):
		t.Fatal("missing setup result")
	}
}

func TestPortalDispatchPreservesExplicitSetupFailure(t *testing.T) {
	handler := &recordingServerHandler{failure: NewSetupError(SetupFlowLimit, errors.New("full"))}
	portal := testHandlerPortal(t, handler)
	result := make(chan SetupResult, 1)
	portal.dispatchUDP(t.Context(), &UDPFlow{
		Authentication: Authentication{Identity: "bob"},
		Target:         M.ParseSocksaddr("192.0.2.53:53"),
		Reader:         emptyPacketSource{},
		Writer:         discardPacketSink{},
		Result: func(value SetupResult) error {
			result <- value
			return nil
		},
	})
	if handler.udpUser != "bob" {
		t.Fatalf("authenticated user = %q", handler.udpUser)
	}
	select {
	case value := <-result:
		if value != SetupFlowLimit {
			t.Fatalf("setup result = %d", value)
		}
	case <-time.After(time.Second):
		t.Fatal("missing setup result")
	}
}

func testHandlerPortal(t *testing.T, handler ServerHandler) *Portal {
	t.Helper()
	pairing, err := NewFlowRegistry(DefaultRegistryConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pairing.Close() })
	portal, err := NewPortal(PortalOptions{
		Handler: handler, ErrorHandler: func(context.Context, error) {},
		Authenticator: NewAuthenticator(), Registry: pairing,
	})
	if err != nil {
		t.Fatal(err)
	}
	return portal
}

type recordingServerHandler struct {
	tcpUser string
	udpUser string
	failure error
}

func (handler *recordingServerHandler) NewConnectionEx(
	ctx context.Context,
	conn net.Conn,
	_, _ M.Socksaddr,
	onClose N.CloseHandlerFunc,
) {
	handler.tcpUser, _ = auth.UserFromContext[string](ctx)
	if handler.failure != nil {
		_ = N.ReportHandshakeFailure(conn, handler.failure)
	} else {
		_ = N.ReportConnHandshakeSuccess(conn, conn)
	}
	_ = conn.Close()
	if onClose != nil {
		onClose(handler.failure)
	}
}

func (handler *recordingServerHandler) NewPacketConnectionEx(
	ctx context.Context,
	conn N.PacketConn,
	_, _ M.Socksaddr,
	onClose N.CloseHandlerFunc,
) {
	handler.udpUser, _ = auth.UserFromContext[string](ctx)
	if handler.failure != nil {
		_ = N.ReportHandshakeFailure(conn, handler.failure)
	} else {
		_ = N.ReportPacketConnHandshakeSuccess(conn, nil)
	}
	_ = conn.Close()
	if onClose != nil {
		onClose(handler.failure)
	}
}

var _ ServerHandler = (*recordingServerHandler)(nil)
