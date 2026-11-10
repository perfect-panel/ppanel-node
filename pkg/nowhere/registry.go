// Copyright (C) 2026 PPanel contributors <https://github.com/perfect-panel>
// SPDX-License-Identifier: GPL-3.0-or-later

package nowhere

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

const (
	DefaultSessionTCPFlows = 1024
	DefaultSessionUDPFlows = 256
)

var ErrRegistryClosed = errors.New("nowhere: connection registry closed")
var ErrFlowLimit = errors.New("nowhere: flow limit")

type RegistryConfig struct {
	MaxConnections        int
	MaxConnectionsPerUser int
	MaxFlowsPerConnection int
	MaxFlows              int
}

func DefaultRegistryConfig() RegistryConfig {
	return RegistryConfig{MaxConnections: 4096, MaxConnectionsPerUser: 1024,
		MaxFlowsPerConnection: DefaultSessionTCPFlows + DefaultSessionUDPFlows, MaxFlows: 16384}
}

type FlowRegistry struct {
	mu          sync.Mutex
	config      RegistryConfig
	closed      bool
	connections map[*Connection]struct{}
	users       map[string]int
	flows       int
}

func NewFlowRegistry(config RegistryConfig) (*FlowRegistry, error) {
	if config == (RegistryConfig{}) {
		config = DefaultRegistryConfig()
	}
	if config.MaxConnections <= 0 || config.MaxConnectionsPerUser <= 0 || config.MaxFlowsPerConnection <= 0 || config.MaxFlows <= 0 {
		return nil, ErrInvalidPortalOptions
	}
	return &FlowRegistry{config: config, connections: make(map[*Connection]struct{}), users: make(map[string]int)}, nil
}

type Connection struct {
	registry       *FlowRegistry
	authenticator  *Authenticator
	Authentication Authentication
	closeCarrier   func()
	closed         bool
	leases         map[*FlowLease]struct{}
	ctx            context.Context
	cancel         context.CancelFunc
	stop           func() bool
}

func (registry *FlowRegistry) Register(ctx context.Context, authenticator *Authenticator, authentication Authentication, closeCarrier func()) (*Connection, error) {
	authenticator.updateMu.RLock()
	defer authenticator.updateMu.RUnlock()
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.closed {
		return nil, ErrRegistryClosed
	}
	if !authenticator.IsCurrent(authentication) {
		return nil, ErrAuthentication
	}
	if len(registry.connections) >= registry.config.MaxConnections || registry.users[authentication.Identity] >= registry.config.MaxConnectionsPerUser {
		return nil, ErrFlowLimit
	}
	ctx, cancel := context.WithCancel(ctx)
	connection := &Connection{ctx: ctx, cancel: cancel, registry: registry, authenticator: authenticator, Authentication: authentication, closeCarrier: closeCarrier, leases: make(map[*FlowLease]struct{})}
	registry.connections[connection] = struct{}{}
	registry.users[authentication.Identity]++
	connection.stop = context.AfterFunc(ctx, connection.Close)
	return connection, nil
}

func (connection *Connection) Acquire(kind FlowKind) (*FlowLease, error) {
	connection.authenticator.updateMu.RLock()
	defer connection.authenticator.updateMu.RUnlock()
	registry := connection.registry
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.closed || connection.closed || !connection.authenticator.IsCurrent(connection.Authentication) {
		return nil, ErrRegistryClosed
	}
	if kind > FlowKindUDP {
		return nil, ErrInvalidFlowHeader
	}
	if registry.flows >= registry.config.MaxFlows || len(connection.leases) >= registry.config.MaxFlowsPerConnection {
		return nil, ErrFlowLimit
	}
	ctx, cancel := context.WithCancel(connection.ctx)
	lease := &FlowLease{connection: connection, kind: kind, done: make(chan struct{}), ctx: ctx, cancel: cancel}
	connection.leases[lease] = struct{}{}
	registry.flows++
	return lease, nil
}

func (connection *Connection) Close() {
	registry := connection.registry
	registry.mu.Lock()
	if connection.closed {
		registry.mu.Unlock()
		return
	}
	connection.closed = true
	delete(registry.connections, connection)
	registry.users[connection.Authentication.Identity]--
	if registry.users[connection.Authentication.Identity] == 0 {
		delete(registry.users, connection.Authentication.Identity)
	}
	leases := make([]*FlowLease, 0, len(connection.leases))
	for lease := range connection.leases {
		leases = append(leases, lease)
	}
	registry.mu.Unlock()
	if connection.stop != nil {
		connection.stop()
	}
	connection.cancel()
	if connection.closeCarrier != nil {
		connection.closeCarrier()
	}
	for _, lease := range leases {
		lease.Close()
	}
}

func (registry *FlowRegistry) CloseStale(authenticator *Authenticator) {
	registry.mu.Lock()
	var stale []*Connection
	for connection := range registry.connections {
		if !authenticator.IsCurrent(connection.Authentication) {
			stale = append(stale, connection)
		}
	}
	registry.mu.Unlock()
	for _, connection := range stale {
		connection.Close()
	}
}
func (registry *FlowRegistry) Close() error {
	registry.mu.Lock()
	registry.closed = true
	connections := make([]*Connection, 0, len(registry.connections))
	for connection := range registry.connections {
		connections = append(connections, connection)
	}
	registry.mu.Unlock()
	for _, connection := range connections {
		connection.Close()
	}
	return nil
}
func (registry *FlowRegistry) Counts() (connections, flows int) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	return len(registry.connections), registry.flows
}

type FlowLease struct {
	ctx        context.Context
	cancel     context.CancelFunc
	connection *Connection
	kind       FlowKind
	done       chan struct{}
	once       sync.Once
}

func (lease *FlowLease) Done() <-chan struct{} { return lease.done }
func (lease *FlowLease) Close() {
	if lease == nil {
		return
	}
	lease.once.Do(func() {
		connection := lease.connection
		registry := connection.registry
		registry.mu.Lock()
		delete(connection.leases, lease)
		registry.flows--
		lease.cancel()
		close(lease.done)
		registry.mu.Unlock()
	})
}

type PacketSource interface{ ReadPacket([]byte) (int, error) }
type PacketSink interface{ WritePacket([]byte) error }
type TCPFlow struct {
	setupDeadline         time.Time
	Authentication        Authentication
	Target                M.Socksaddr
	Reader                io.Reader
	Writer                io.Writer
	Result                func(SetupResult) error
	Lease                 *FlowLease
	close                 func()
	LocalAddr, RemoteAddr net.Addr
}

func (flow *TCPFlow) Close() {
	if flow == nil {
		return
	}
	if flow.close != nil {
		flow.close()
	}
	flow.Lease.Close()
}

type UDPFlow struct {
	setupDeadline         time.Time
	Authentication        Authentication
	Target                M.Socksaddr
	Reader                PacketSource
	Writer                PacketSink
	Result                func(SetupResult) error
	Lease                 *FlowLease
	close                 func()
	LocalAddr, RemoteAddr net.Addr
}

func (flow *UDPFlow) Close() {
	if flow == nil {
		return
	}
	if flow.close != nil {
		flow.close()
	}
	flow.Lease.Close()
}
