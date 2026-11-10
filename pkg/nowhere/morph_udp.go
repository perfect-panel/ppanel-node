// Copyright (C) 2026 PPanel contributors <https://github.com/perfect-panel>
// SPDX-License-Identifier: GPL-3.0-or-later

package nowhere

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

const morphRouteLimit = 4096
const morphPeerLimit = 64
const morphCIDLimit = 32
const morphAliasLimit = 8

type morphUDPRoute struct {
	credential           authCredential
	authentication       Authentication
	peers                map[netip.AddrPort]struct{}
	serverIDs, clientIDs map[string]uint64
	expires              time.Time
	active               bool
	removed              bool
}
type morphCIDKey struct {
	key AuthKey
	cid string
}

type morphPacketConn struct {
	net.PacketConn
	auth      *Authenticator
	mu        sync.Mutex
	peers     map[netip.AddrPort]map[*morphUDPRoute]struct{}
	routes    map[*morphUDPRoute]struct{}
	index     map[morphCIDKey]*morphUDPRoute
	nextSweep time.Time
}

func newMorphPacketConn(raw net.PacketConn, auth *Authenticator) *morphPacketConn {
	return &morphPacketConn{PacketConn: raw, auth: auth, peers: make(map[netip.AddrPort]map[*morphUDPRoute]struct{}), routes: make(map[*morphUDPRoute]struct{}), index: make(map[morphCIDKey]*morphUDPRoute)}
}
func packetPeer(address net.Addr) (netip.AddrPort, bool) {
	peer, ok := address.(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}, false
	}
	a := peer.AddrPort()
	return netip.AddrPortFrom(a.Addr().Unmap(), a.Port()), true
}
func matchesCID(packet []byte, ids map[string]uint64) bool {
	if len(packet) == 0 {
		return false
	}
	if packet[0]&0x80 != 0 {
		dest, _, _, ok := quicLongIDs(packet)
		if !ok {
			return false
		}
		_, ok = ids[string(dest)]
		return ok
	}
	if packet[0]&0x40 == 0 {
		return false
	}
	for id := range ids {
		if len(packet) >= 1+len(id) && bytes.Equal(packet[1:1+len(id)], []byte(id)) {
			return true
		}
	}
	return false
}
func (c *morphPacketConn) removeLocked(route *morphUDPRoute) {
	for id := range route.serverIDs {
		delete(c.index, morphCIDKey{route.credential.key, id})
	}
	route.removed = true
	delete(c.routes, route)
	for peer := range route.peers {
		delete(c.peers[peer], route)
		if len(c.peers[peer]) == 0 {
			delete(c.peers, peer)
		}
	}
}
func (c *morphPacketConn) sweepLocked(now time.Time) {
	if now.Before(c.nextSweep) {
		return
	}
	c.nextSweep = now.Add(time.Second)
	for route := range c.routes {
		if (!route.active && now.After(route.expires)) || !c.auth.IsCurrent(route.authentication) {
			c.removeLocked(route)
		}
	}
}
func (c *morphPacketConn) addPeerLocked(route *morphUDPRoute, peer netip.AddrPort) bool {
	if _, ok := route.peers[peer]; ok {
		return true
	}
	if len(route.peers) >= morphAliasLimit || len(c.peers[peer]) >= morphPeerLimit {
		return false
	}
	if c.peers[peer] == nil {
		c.peers[peer] = make(map[*morphUDPRoute]struct{})
	}
	c.peers[peer][route] = struct{}{}
	route.peers[peer] = struct{}{}
	return true
}
func (c *morphPacketConn) ReadFrom(output []byte) (int, net.Addr, error) {
	// Do not expose UDPConn/OOB interfaces: one nonce belongs to one datagram,
	// including on platforms with GRO/GSO. Retain space for the outer nonce.
	var wire [65535]byte
	for {
		n, address, err := c.PacketConn.ReadFrom(wire[:])
		if err != nil {
			return 0, address, err
		}
		if n <= 12 {
			continue
		}
		peer, ok := packetPeer(address)
		if !ok {
			continue
		}
		var nonce [12]byte
		copy(nonce[:], wire[:12])
		masked := wire[12:n]
		plain := make([]byte, len(masked))
		c.mu.Lock()
		c.sweepLocked(time.Now())
		var route *morphUDPRoute
		for candidate := range c.peers[peer] {
			if !c.auth.IsCurrent(candidate.authentication) {
				continue
			}
			_ = morphXOR(plain, masked, candidate.credential.morph.UDPC2S, nonce, 0)
			if matchesCID(plain, candidate.serverIDs) {
				route = candidate
				break
			}
		}
		c.mu.Unlock()
		if route == nil {
			// Unknown peers may be a first Initial or a QUIC path migration. Both
			// selection and source work budgets are scoped to the physical sender.
			var initial bool
			credential, matchErr := c.auth.matchMorph(peer.Addr(), max(16, len(masked)/16), func(candidate authCredential) bool {
				route = nil
				initial = false
				_ = morphXOR(plain, masked, candidate.morph.UDPC2S, nonce, 0)
				c.mu.Lock()
				var id []byte
				if len(plain) > 0 && plain[0]&0x80 != 0 {
					id, _, _, _ = quicLongIDs(plain)
				} else if len(plain) >= 9 && plain[0]&0x40 != 0 {
					id = plain[1:9]
				}
				if id != nil {
					existing := c.index[morphCIDKey{candidate.key, string(id)}]
					if existing != nil && existing.authentication.Identity == candidate.identity && c.auth.IsCurrent(existing.authentication) {
						route = existing
					}
				}

				c.mu.Unlock()
				if route != nil {
					return true
				}
				initial = validClientInitial(plain)
				return initial
			})
			if matchErr != nil {
				continue
			}
			c.mu.Lock()
			if route == nil && initial && len(c.routes) < morphRouteLimit && len(c.peers[peer]) < morphPeerLimit {
				dcid, scid, _, _ := quicLongIDs(plain)
				route = &morphUDPRoute{credential: credential, authentication: Authentication{Identity: credential.identity, key: credential.key}, peers: make(map[netip.AddrPort]struct{}), serverIDs: map[string]uint64{string(dcid): 0}, clientIDs: map[string]uint64{string(scid): 0}, expires: time.Now().Add(30 * time.Second)}
				c.routes[route] = struct{}{}
				c.index[morphCIDKey{credential.key, string(dcid)}] = route
			}
			allowed := route != nil && !route.removed && c.auth.IsCurrent(route.authentication) && c.addPeerLocked(route, peer)
			c.mu.Unlock()
			if !allowed {
				continue
			}
		}
		if len(plain) > len(output) {
			continue
		}
		return copy(output, plain), address, nil
	}
}
func (c *morphPacketConn) WriteTo(packet []byte, address net.Addr) (int, error) {
	peer, ok := packetPeer(address)
	if !ok {
		return 0, ErrMorph
	}
	c.mu.Lock()
	var route *morphUDPRoute
	for candidate := range c.peers[peer] {
		if !c.auth.IsCurrent(candidate.authentication) || !matchesCID(packet, candidate.clientIDs) {
			continue
		}
		if route != nil && route != candidate {
			c.mu.Unlock()
			return 0, ErrMorph
		}
		route = candidate
	}
	if route == nil {
		c.mu.Unlock()
		return 0, ErrMorph
	}
	if _, scid, _, long := quicLongIDs(packet); long && len(scid) > 0 {
		if _, exists := route.serverIDs[string(scid)]; !exists && len(route.serverIDs) < morphCIDLimit {
			c.addServerCIDLocked(route, string(scid), 0)
		}
	}
	keys := route.credential.morph
	c.mu.Unlock()
	wire := make([]byte, 12+len(packet))
	if _, err := rand.Read(wire[:12]); err != nil {
		return 0, err
	}
	var nonce [12]byte
	copy(nonce[:], wire[:12])
	if err := morphXOR(wire[12:], packet, keys.UDPS2C, nonce, 0); err != nil {
		return 0, err
	}
	n, err := c.PacketConn.WriteTo(wire, address)
	if n != len(wire) && err == nil {
		err = io.ErrShortWrite
	}
	if err != nil {
		return 0, err
	}
	return len(packet), nil
}

func (c *morphPacketConn) addServerCIDLocked(route *morphUDPRoute, id string, sequence uint64) {
	k := morphCIDKey{route.credential.key, id}
	if owner := c.index[k]; owner != nil && owner != route {
		return
	}
	if evicted := addMorphCID(route.serverIDs, id, sequence); evicted != "" {
		delete(c.index, morphCIDKey{route.credential.key, evicted})
	}
	if _, exists := route.serverIDs[id]; exists {
		c.index[k] = route
	}
}
func (c *morphPacketConn) removeServerCIDLocked(route *morphUDPRoute, id string) {
	delete(route.serverIDs, id)
	delete(c.index, morphCIDKey{route.credential.key, id})
}
