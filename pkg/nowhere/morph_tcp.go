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
func (a *Authenticator) matchMorph(source netip.Addr, work int, match func(*authCredential) bool) (*authCredential, error) {
	for {
		state := a.users.Load()
		if state == nil || state.count == 0 {
			return nil, ErrNoUsers
		}
		candidates, _ := a.addressCache.Load(source, authCacheGeneration)
		var selected *authCredential
		var scanPermit *authscan.Permit[netip.Addr]
		var tried [authscan.CandidateCapacity]uint64
		triedCount := 0
		for i := 0; i < candidates.Count(); i++ {
			candidate := state.candidate(candidates.At(i))
			if candidate == nil {
				continue
			}
			tried[triedCount] = candidate.id
			triedCount++
			permit, ok := a.guard.AcquireKnown(source, work)
			if !ok {
				return nil, authscan.ErrLimited
			}
			valid := match(candidate)
			permit.Release()
			if valid {
				selected = candidate
				break
			}
		}
		if selected == nil {
			permit, ok := a.guard.Acquire(source, scanWork(work, state.count-triedCount))
			if !ok {
				return nil, authscan.ErrLimited
			}
			scanPermit = permit
			state.each(func(candidate *authCredential) bool {
				for _, id := range tried[:triedCount] {
					if id == candidate.id {
						return true
					}
				}
				if match(candidate) {
					selected = candidate
					return false
				}
				return true
			})
		}
		a.updateMu.RLock()
		if a.users.Load() != state {
			a.updateMu.RUnlock()
			// A stale snapshot cannot judge this source. In particular, do not
			// arm cooldown before retrying against newly published users.
			scanPermit.Release()
			continue
		}
		if selected == nil {
			scanPermit.Done(false)
			a.updateMu.RUnlock()
			return nil, ErrMorph
		}
		scanPermit.Release()
		a.updateMu.RUnlock()
		return selected, nil
	}
}

func scanWork(perCandidate, count int) int {
	if perCandidate <= 0 || count <= 0 {
		return 1
	}
	maxInt := int(^uint(0) >> 1)
	if count > maxInt/perCandidate {
		return maxInt
	}
	return perCandidate * count
}

// selectMorphTCP preprocesses the key-independent Prelude fields once.
func (a *Authenticator) selectMorphTCP(source netip.Addr, bootstrap []byte) (*authCredential, preludeIdentity, error) {
	if len(bootstrap) != morphPreludeLen+morphNonceLen {
		return nil, preludeIdentity{}, ErrMorph
	}
	prepared, _ := preparePrelude(bootstrap[:morphPreludeLen], bootstrap[morphPreludeLen:])
	var identity preludeIdentity
	credential, err := a.matchMorph(source, 4, func(candidate *authCredential) bool {
		value, valid := prepared.decode(&candidate.morph)
		if valid {
			identity = value
		}
		return valid
	})
	return credential, identity, err
}

func (p *Portal) acceptMorphTCP(raw net.Conn, config *tls.Config, deadline time.Time) (*morphTCPConn, *tls.Config, error) {
	var bootstrap [76]byte
	if _, err := io.ReadFull(raw, bootstrap[:]); err != nil {
		return nil, nil, err
	}
	credential, identity, err := p.authenticator.selectMorphTCP(physicalRemoteIP(raw), bootstrap[:])
	if err != nil {
		return nil, nil, err
	}
	if !p.prelude.accept(credential.key, identity, false) {
		return nil, nil, ErrMorphReplay
	}
	c := &morphTCPConn{Conn: raw, keys: credential.morph, authentication: credential.authentication()}
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
