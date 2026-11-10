// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// Copyright (C) 2026 PPanel contributors <https://github.com/perfect-panel>
// SPDX-License-Identifier: GPL-3.0-only

package nowhere

import (
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/perfect-panel/nowhere/internal/authscan"
	"github.com/sagernet/sing/common"
	"golang.org/x/crypto/chacha20"
)

const morphStreamLimit = uint64(1) << 38

// Recreate the cipher at an exact byte offset so a short failed Write never
// consumes keystream for bytes the underlying connection did not transmit.
func morphXOR(output, input []byte, key [32]byte, nonce [12]byte, offset uint64) error {
	if len(input) == 0 && offset <= morphStreamLimit {
		return nil
	}
	if offset >= morphStreamLimit || uint64(len(input)) > morphStreamLimit-offset {
		return ErrMorph
	}
	cipher, err := chacha20.NewUnauthenticatedCipher(key[:], nonce[:])
	if err != nil {
		return err
	}
	cipher.SetCounter(uint32(offset / 64))
	if skip := int(offset % 64); skip != 0 {
		var scratch [64]byte
		cipher.XORKeyStream(scratch[:skip], scratch[:skip])
	}
	cipher.XORKeyStream(output, input)
	return nil
}

type morphTCPConn struct {
	net.Conn
	nonce                   [12]byte
	keys                    MorphKeys
	authentication          Authentication
	canWrite                atomic.Bool
	readMu, writeMu         sync.Mutex
	readOffset, writeOffset uint64
}

func (c *morphTCPConn) Read(output []byte) (int, error) {
	if len(output) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.readOffset >= morphStreamLimit {
		return 0, ErrMorph
	}
	output = output[:min(uint64(len(output)), morphStreamLimit-c.readOffset)]
	n, err := c.Conn.Read(output)
	if n > 0 {
		if cipherErr := morphXOR(output[:n], output[:n], c.keys.TCPC2S, c.nonce, c.readOffset); cipherErr != nil {
			return 0, cipherErr
		}
		c.readOffset += uint64(n)
	}
	return n, err
}
func (c *morphTCPConn) Write(input []byte) (int, error) {
	if !c.canWrite.Load() {
		return 0, ErrMorph
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if len(input) == 0 {
		return 0, nil
	}
	encoded := make([]byte, len(input))
	if err := morphXOR(encoded, input, c.keys.TCPS2C, c.nonce, c.writeOffset); err != nil {
		return 0, err
	}
	total := 0
	for total < len(encoded) {
		n, err := c.Conn.Write(encoded[total:])
		if n < 0 || n > len(encoded)-total {
			return total, io.ErrShortWrite
		}
		total += n
		c.writeOffset += uint64(n)
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrNoProgress
		}
	}
	return total, nil
}
func (c *morphTCPConn) Upstream() any { return c.Conn }

func physicalRemoteIP(conn net.Conn) netip.Addr {
	if raw, ok := common.Top(conn).(net.Conn); ok {
		return remoteIP(raw.RemoteAddr())
	}
	return remoteIP(conn.RemoteAddr())
}
func setCarrierLinger(conn net.Conn, value int) error {
	if raw, ok := common.Top(conn).(interface{ SetLinger(int) error }); ok {
		return raw.SetLinger(value)
	}
	return ErrMorph
}

// A Morph match is tentative: it neither warms authentication caches nor
// clears source cooldown. Only the later exporter-bound AuthFrame does that.
func (a *Authenticator) matchMorph(source netip.Addr, work int, match func(authCredential) bool) (authCredential, error) {
	for {
		state := a.users.Load()
		if state == nil || len(state.credentials) == 0 {
			return authCredential{}, ErrNoUsers
		}
		candidates, _ := a.addressCache.Load(source, state.generation)
		var selected *authCredential
		for i := 0; i < candidates.Count(); i++ {
			index := int(candidates.At(i))
			if index >= len(state.credentials) {
				continue
			}
			permit, ok := a.guard.AcquireKnown(source, work)
			if !ok {
				return authCredential{}, authscan.ErrLimited
			}
			candidate := state.credentials[index]
			valid := match(candidate)
			permit.Release()
			if valid {
				selected = &candidate
				break
			}
		}
		if selected == nil {
			permit, ok := a.guard.Acquire(source, work*(len(state.credentials)-candidates.Count()))
			if !ok {
				return authCredential{}, authscan.ErrLimited
			}
			for i, candidate := range state.credentials {
				if candidates.Contains(uint32(i)) {
					continue
				}
				if match(candidate) {
					selected = &candidate
					break
				}
			}
			if selected == nil {
				permit.Done(false)
			} else {
				permit.Release()
			}
		}
		a.updateMu.RLock()
		current := a.users.Load() == state
		a.updateMu.RUnlock()
		if !current {
			continue
		}
		if selected == nil {
			return authCredential{}, ErrMorph
		}
		return *selected, nil
	}
}

func (p *Portal) acceptMorphTCP(raw net.Conn, config *tls.Config, deadline time.Time) (*morphTCPConn, *tls.Config, error) {
	var bootstrap [76]byte
	if _, err := io.ReadFull(raw, bootstrap[:]); err != nil {
		return nil, nil, err
	}
	var identity preludeIdentity
	credential, err := p.authenticator.matchMorph(physicalRemoteIP(raw), 4, func(candidate authCredential) bool {
		value, valid := decodePrelude(candidate.morph, bootstrap[:64], bootstrap[64:])
		if valid {
			identity = value
		}
		return valid
	})
	if err != nil {
		return nil, nil, err
	}
	if !p.prelude.accept(credential.key, identity, false) {
		return nil, nil, ErrMorphReplay
	}
	c := &morphTCPConn{Conn: raw, keys: credential.morph, authentication: Authentication{Identity: credential.identity, key: credential.key}}
	copy(c.nonce[:], bootstrap[64:])
	cloned := config.Clone()
	original := config.GetConfigForClient
	cloned.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		var selected *tls.Config
		if original != nil {
			var err error
			selected, err = original(hello)
			if err != nil {
				return nil, err
			}
		}
		version, alpn := false, false
		for _, v := range hello.SupportedVersions {
			if v == tls.VersionTLS13 {
				version = true
			}
		}
		for _, name := range hello.SupportedProtos {
			if name == DefaultALPN {
				alpn = true
			}
		}
		if !version || !alpn || !p.authenticator.IsCurrent(c.authentication) {
			return nil, ErrMorph
		}
		if !time.Now().Before(deadline) {
			return nil, ErrMorph
		}
		if !p.prelude.accept(credential.key, identity, true) {
			return nil, ErrMorphReplay
		}
		c.canWrite.Store(true)
		return selected, nil
	}
	return c, cloned, nil
}
