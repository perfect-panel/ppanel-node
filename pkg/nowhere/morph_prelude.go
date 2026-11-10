// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// Copyright (C) 2026 PPanel contributors <https://github.com/perfect-panel>
// SPDX-License-Identifier: GPL-3.0-only

package nowhere

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"sync"
)

const morphPreludeLen = 64
const morphNonceLen = 12
const maxPreludeCounter = 1<<48 - 1

var ErrMorph = errors.New("nowhere: invalid Morph bootstrap")
var ErrMorphReplay = errors.New("nowhere: Morph bootstrap replay")

type preludeIdentity struct{ identity, counter uint64 }

func preludeInput(prelude []byte, nonce []byte) [62]byte {
	var input [62]byte
	copy(input[:12], nonce)
	copy(input[12:44], prelude[:32])
	for i, value := range prelude[32:64] {
		input[44+i/8] |= (value >> 7) << (7 - i%8)
	}
	return input
}

func decodePrelude(keys MorphKeys, prelude, nonce []byte) (preludeIdentity, bool) {
	prepared, ok := preparePrelude(prelude, nonce)
	if !ok {
		return preludeIdentity{}, false
	}
	return prepared.decode(&keys)
}

// The bit unpacking and nonce/header assembly do not depend on the key.
// Perform them once per connection, not once per user inspected.
type preparedPrelude struct {
	input   [62]byte
	payload [28]byte
}

func preparePrelude(prelude, nonce []byte) (preparedPrelude, bool) {
	if len(prelude) != 64 || len(nonce) != 12 {
		return preparedPrelude{}, false
	}
	prepared := preparedPrelude{input: preludeInput(prelude, nonce)}
	for i, value := range prelude[32:64] {
		for bit := 0; bit < 7; bit++ {
			offset := i*7 + bit
			prepared.payload[offset/8] |= ((value >> uint(6-bit)) & 1) << uint(7-offset%8)
		}
	}
	return prepared, true
}

func (prepared *preparedPrelude) decode(keys *MorphKeys) (preludeIdentity, bool) {
	input, payload := prepared.input, prepared.payload
	mask := hmacSHA256(keys.PreludeMask[:], input[:48])
	for i := range payload {
		payload[i] ^= mask[i]
	}
	copy(input[48:], payload[:14])
	tag := hmacSHA256(keys.PreludeAuth[:], input[:])
	var counter [8]byte
	copy(counter[2:], payload[8:14])
	return preludeIdentity{identity: binary.BigEndian.Uint64(payload[:8]), counter: binary.BigEndian.Uint64(counter[:])}, hmac.Equal(tag[:14], payload[14:])
}

// Shared by all TCP listeners and user generations. Credentials scope the
// client-generated Identity; an update must not erase replay history.
type preludeKey struct {
	key      AuthKey
	identity uint64
}
type preludeWindow struct {
	key     preludeKey
	highest uint64
	bits    [16]uint64
}
type preludeReplay struct {
	mu      sync.Mutex
	index   map[preludeKey]int
	entries []preludeWindow
	next    int
}

func newPreludeReplay(capacity int) *preludeReplay {
	return &preludeReplay{index: make(map[preludeKey]int, capacity), entries: make([]preludeWindow, capacity)}
}
func (r *preludeReplay) accept(key AuthKey, value preludeIdentity, commit bool) bool {
	if value.counter == 0 || value.counter > maxPreludeCounter {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	k := preludeKey{key: key, identity: value.identity}
	index, found := r.index[k]
	if !found {
		if !commit {
			return true
		}
		index = r.next
		r.next = (r.next + 1) % len(r.entries)
		if r.entries[index].highest != 0 {
			delete(r.index, r.entries[index].key)
		}
		r.entries[index] = preludeWindow{key: k, highest: value.counter, bits: [16]uint64{1}}
		r.index[k] = index
		return true
	}
	window := &r.entries[index]
	if value.counter <= window.highest {
		offset := window.highest - value.counter
		if offset >= 1024 || window.bits[offset/64]&(uint64(1)<<(offset%64)) != 0 {
			return false
		}
		if commit {
			window.bits[offset/64] |= uint64(1) << (offset % 64)
		}
		return true
	}
	if !commit {
		return true
	}
	shift := value.counter - window.highest
	if shift >= 1024 {
		window.bits = [16]uint64{}
	} else {
		words, bits := int(shift/64), uint(shift%64)
		for i := 15; i >= 0; i-- {
			var value uint64
			if i >= words {
				value = window.bits[i-words] << bits
				if bits != 0 && i > words {
					value |= window.bits[i-words-1] >> (64 - bits)
				}
			}
			window.bits[i] = value
		}
	}
	window.highest = value.counter
	window.bits[0] |= 1
	return true
}
