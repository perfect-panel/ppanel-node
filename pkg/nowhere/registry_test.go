// Copyright (C) 2026 PPanel contributors <https://github.com/perfect-panel>
// SPDX-License-Identifier: GPL-3.0-or-later

package nowhere

import (
	"bytes"
	"context"
	"errors"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func registryAuthentication(t *testing.T, a *Authenticator) Authentication {
	t.Helper()
	update, err := PrepareAuthUpdate([]User{{Name: "alice", Key: []byte(testSharedKey)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Commit(update); err != nil {
		t.Fatal(err)
	}
	key, _ := DeriveAuthKey([]byte(testSharedKey))
	return a.users.Load().credential(key).authentication()
}
func TestRegistryLimitsAndStalePublication(t *testing.T) {
	a := NewAuthenticator()
	authentication := registryAuthentication(t, a)
	r, err := NewFlowRegistry(RegistryConfig{MaxConnections: 2, MaxConnectionsPerUser: 1, MaxFlowsPerConnection: 2, MaxFlows: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	closed := make(chan struct{})
	c, err := r.Register(t.Context(), a, authentication, func() { close(closed) })
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Register(t.Context(), a, authentication, nil); !errors.Is(err, ErrFlowLimit) {
		t.Fatalf("connection limit=%v", err)
	}
	leases := make([]*FlowLease, 2)
	for i := range leases {
		leases[i], err = c.Acquire(FlowKindUDP)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err = c.Acquire(FlowKindTCP); !errors.Is(err, ErrFlowLimit) {
		t.Fatalf("flow limit=%v", err)
	}
	update, err := PrepareAuthUpdate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Commit(update); err != nil {
		t.Fatal(err)
	}
	// Publication must stop new admission even before the caller sweeps old
	// carriers; this is the cancellation-after-commit boundary.
	if _, err = r.Register(t.Context(), a, authentication, nil); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("stale registration=%v", err)
	}
	if _, err = c.Acquire(FlowKindTCP); err == nil {
		t.Fatal("stale connection acquired flow")
	}
	r.CloseStale(a)
	<-closed
	for _, lease := range leases {
		select {
		case <-lease.Done():
		default:
			t.Fatal("lease survived revocation")
		}
	}
	if connections, flows := r.Counts(); connections != 0 || flows != 0 {
		t.Fatalf("leaked %d/%d", connections, flows)
	}
}
func TestRegistryConcurrentLeaseAndConnectionClose(t *testing.T) {
	a := NewAuthenticator()
	authentication := registryAuthentication(t, a)
	r, _ := NewFlowRegistry(RegistryConfig{})
	defer r.Close()
	for range 100 {
		ctx, cancel := context.WithCancel(t.Context())
		c, err := r.Register(ctx, a, authentication, nil)
		if err != nil {
			t.Fatal(err)
		}
		var workers sync.WaitGroup
		for range 8 {
			workers.Go(func() {
				if lease, err := c.Acquire(FlowKindTCP); err == nil {
					lease.Close()
					lease.Close()
				}
			})
		}
		workers.Go(cancel)
		workers.Go(c.Close)
		workers.Wait()
		c.Close()
	}
	if connections, flows := r.Counts(); connections != 0 || flows != 0 {
		t.Fatalf("leaked %d/%d", connections, flows)
	}
}

func TestFlowSetupTimeoutCancelsHandlerWithoutClosingCarrier(t *testing.T) {
	a := NewAuthenticator()
	authentication := registryAuthentication(t, a)
	r, _ := NewFlowRegistry(RegistryConfig{})
	defer r.Close()
	connection, err := r.Register(t.Context(), a, authentication, nil)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := connection.Acquire(FlowKindTCP)
	if err != nil {
		t.Fatal(err)
	}
	handler := &setupCancellationHandler{done: make(chan struct{})}
	p, err := NewPortal(PortalOptions{Handler: handler, ErrorHandler: func(context.Context, error) {}, Authenticator: a, Registry: r})
	if err != nil {
		t.Fatal(err)
	}
	go p.dispatchTCP(t.Context(), &TCPFlow{Lease: lease, Authentication: authentication, setupDeadline: time.Now().Add(20 * time.Millisecond), Reader: bytes.NewReader(nil), Writer: io.Discard})
	select {
	case <-handler.done:
	case <-time.After(time.Second):
		t.Fatal("setup timeout did not cancel pending handler")
	}
	if connection.ctx.Err() != nil {
		t.Fatal("one flow timeout closed carrier")
	}
	if _, err = connection.Acquire(FlowKindTCP); err != nil {
		t.Fatalf("carrier cannot admit later flow: %v", err)
	}
}

type setupCancellationHandler struct {
	recordingServerHandler
	done chan struct{}
}

func (h *setupCancellationHandler) NewConnectionEx(ctx context.Context, conn net.Conn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	<-ctx.Done()
	_ = conn.Close()
	close(h.done)
}
