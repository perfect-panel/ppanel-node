// Copyright (C) 2026 PPanel contributors <https://github.com/perfect-panel>
// SPDX-License-Identifier: GPL-3.0-or-later

package nowhere

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/qlog"
	"github.com/sagernet/quic-go/qlogwriter"
)

type morphQUICContextKey struct{}
type morphQUICBinding struct {
	peer  netip.AddrPort
	route atomic.Pointer[morphUDPRoute]
}

// ConfigureQUICTransport wraps UDP and binds its selected Morph key to NW3
// authentication. Call before Listen, with the application's private transport.
// The returned configuration owns its copy; the input is not mutated.
func (p *Portal) ConfigureQUICTransport(transport *quic.Transport, config *quic.Config) *quic.Config {
	if config == nil {
		config = &quic.Config{}
	} else {
		config = config.Clone()
	}
	if !p.morph {
		return config
	}
	packet := newMorphPacketConn(transport.Conn, p.authenticator)
	transport.Conn = packet
	transport.ConnectionIDLength = 8
	originalContext := transport.ConnContext
	transport.ConnContext = func(ctx context.Context, info *quic.ClientInfo) (context.Context, error) {
		peer, ok := packetPeer(info.RemoteAddr)
		if !ok {
			return nil, ErrMorph
		}
		ctx = context.WithValue(ctx, morphQUICContextKey{}, &morphQUICBinding{peer: peer})
		if originalContext != nil {
			return originalContext(ctx, info)
		}
		return ctx, nil
	}
	originalTracer := config.Tracer
	config.Versions = []quic.Version{quic.Version1}
	config.InitialPacketSize = 1200
	config.DisablePathMTUDiscovery = true
	config.Tracer = func(ctx context.Context, client bool, id quic.ConnectionID) qlogwriter.Trace {
		var other qlogwriter.Trace
		if originalTracer != nil {
			other = originalTracer(ctx, client, id)
		}
		binding, _ := ctx.Value(morphQUICContextKey{}).(*morphQUICBinding)
		if binding == nil || client {
			return other
		}
		packet.mu.Lock()
		var route *morphUDPRoute
		for candidate := range packet.peers[binding.peer] {
			if _, ok := candidate.serverIDs[string(id.Bytes())]; ok {
				if route != nil {
					route = nil
					break
				}
				route = candidate
			}
		}
		if route != nil {
			route.active = true
			binding.route.Store(route)
		}
		packet.mu.Unlock()
		return &morphTrace{packet: packet, route: route, other: other}
	}
	return config
}
func morphQUICSelection(ctx context.Context) (Authentication, bool) {
	binding, _ := ctx.Value(morphQUICContextKey{}).(*morphQUICBinding)
	if binding == nil {
		return Authentication{}, false
	}
	route := binding.route.Load()
	if route == nil {
		return Authentication{}, false
	}
	return route.authentication, true
}

type morphTrace struct {
	packet    *morphPacketConn
	route     *morphUDPRoute
	mu        sync.Mutex
	producers int
	other     qlogwriter.Trace
}

func (t *morphTrace) SupportsSchemas(schema string) bool {
	return schema == qlog.EventSchema || (t.other != nil && t.other.SupportsSchemas(schema))
}
func (t *morphTrace) AddProducer() qlogwriter.Recorder {
	t.mu.Lock()
	t.producers++
	t.mu.Unlock()
	var other qlogwriter.Recorder
	if t.other != nil {
		other = t.other.AddProducer()
	}
	return &morphRecorder{trace: t, other: other}
}

type morphRecorder struct {
	trace *morphTrace
	other qlogwriter.Recorder
	once  sync.Once
}

func (r *morphRecorder) Close() error {
	var err error
	r.once.Do(func() {
		if r.other != nil {
			err = r.other.Close()
		}
		t := r.trace
		t.mu.Lock()
		t.producers--
		last := t.producers == 0
		t.mu.Unlock()
		if last && t.route != nil {
			t.packet.mu.Lock()
			t.packet.removeLocked(t.route)
			t.packet.mu.Unlock()
		}
	})
	return err
}
func (r *morphRecorder) RecordEvent(event qlogwriter.Event) {
	if r.other != nil {
		r.other.RecordEvent(event)
	}
	t := r.trace
	if t.route == nil {
		return
	}
	var frames []qlog.Frame
	var sent bool
	switch value := event.(type) {
	case qlog.PacketSent:
		frames = value.Frames
		sent = true
	case qlog.PacketReceived:
		frames = value.Frames
	default:
		return
	}
	t.packet.mu.Lock()
	defer t.packet.mu.Unlock()
	if t.route.removed {
		return
	}

	for _, wrapped := range frames {
		frame, ok := wrapped.Frame.(*qlog.NewConnectionIDFrame)
		if !ok {
			continue
		}
		// Keep a bounded tail of retired IDs for reordered packets and writes
		// already queued by QUIC. Removing at RETIRE frame logging is too early:
		// the packet containing that frame may still use the previous destination.
		id := string(frame.ConnectionID.Bytes())
		if sent {
			t.packet.addServerCIDLocked(t.route, id, frame.SequenceNumber)
		} else {
			addMorphCID(t.route.clientIDs, id, frame.SequenceNumber)
		}
	}
}
func addMorphCID(ids map[string]uint64, id string, sequence uint64) (evicted string) {
	if _, exists := ids[id]; !exists && len(ids) >= morphCIDLimit {
		var oldest string
		var minimum uint64 = ^uint64(0)
		for key, value := range ids {
			if value < minimum {
				oldest = key
				minimum = value
			}
		}
		if sequence < minimum {
			return id
		}
		delete(ids, oldest)
		evicted = oldest
	}
	ids[id] = sequence
	return
}
