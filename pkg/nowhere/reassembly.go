// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// Copyright (C) 2026 PPanel contributors <https://github.com/perfect-panel>
// SPDX-License-Identifier: GPL-3.0-only

package nowhere

import (
	"bytes"
	"errors"
	"sync"
	"time"
)

const (
	DefaultReassemblySlots = 64
	DefaultReassemblyBytes = 1 << 20
)

var (
	ErrReassemblyLimit    = errors.New("nowhere: UDP reassembly limit reached")
	ErrReassemblyConflict = errors.New("nowhere: conflicting UDP fragment")
	ErrReassemblyLength   = errors.New("nowhere: invalid reassembled UDP length")
)

type ReassemblyConfig struct {
	MaxSlots int
	MaxBytes int
	TTL      time.Duration
}

func DefaultReassemblyConfig() ReassemblyConfig {
	return ReassemblyConfig{MaxSlots: DefaultReassemblySlots, MaxBytes: DefaultReassemblyBytes, TTL: 10 * time.Second}
}

type reassemblyKey struct {
	flowID   FlowID
	packetID uint32
}

type reassemblySlot struct {
	createdAt     time.Time
	fragmentCount uint8
	totalLength   uint16
	fragments     [][]byte
	received      int
	retained      int
}

type DatagramReassembler struct {
	config        ReassemblyConfig
	mu            sync.Mutex
	slots         map[reassemblyKey]*reassemblySlot
	reservedBytes int
}

func NewDatagramReassembler(config ReassemblyConfig) (*DatagramReassembler, error) {
	if config.MaxSlots <= 0 || config.MaxBytes <= 0 || config.TTL <= 0 {
		return nil, ErrReassemblyLimit
	}
	return &DatagramReassembler{config: config, slots: make(map[reassemblyKey]*reassemblySlot)}, nil
}

func (reassembler *DatagramReassembler) SlotCount() int {
	reassembler.mu.Lock()
	defer reassembler.mu.Unlock()
	return len(reassembler.slots)
}

func (reassembler *DatagramReassembler) ReservedBytes() int {
	reassembler.mu.Lock()
	defer reassembler.mu.Unlock()
	return reassembler.reservedBytes
}

// Push takes ownership of frame.Payload until the packet completes or is
// discarded. It returns a complete payload only for the final fragment.
func (reassembler *DatagramReassembler) Push(frame UDPFrame, now time.Time) ([]byte, bool, error) {
	return reassembler.PushWithLimit(frame, now, reassembler.config.MaxBytes)
}

// PushWithLimit applies a caller-supplied shared byte ceiling in addition to
// the reassembler's own bound. Existing slots remain usable even if other UDP
// queues temporarily consume the rest of the shared connection budget.
func (reassembler *DatagramReassembler) PushWithLimit(
	frame UDPFrame,
	now time.Time,
	maxReservedBytes int,
) ([]byte, bool, error) {
	if frame.Type != UDPFrameFragment || !validUDPFragment(frame) {
		return nil, false, ErrInvalidUDPFrame
	}
	reassembler.mu.Lock()
	defer reassembler.mu.Unlock()
	reassembler.expireLocked(now)
	key := reassemblyKey{flowID: frame.FlowID, packetID: frame.PacketID}
	if slot := reassembler.slots[key]; slot != nil {
		if slot.fragmentCount != frame.FragmentCount || slot.totalLength != frame.TotalLength {
			reassembler.removeLocked(key)
			return nil, false, ErrReassemblyConflict
		}
		index := int(frame.FragmentIndex)
		if existing := slot.fragments[index]; existing != nil {
			if !bytes.Equal(existing, frame.Payload) {
				reassembler.removeLocked(key)
				return nil, false, ErrReassemblyConflict
			}
			return nil, false, nil
		}
		if slot.retained+len(frame.Payload) > int(slot.totalLength) {
			reassembler.removeLocked(key)
			return nil, false, ErrReassemblyLength
		}
		slot.fragments[index] = frame.Payload
		slot.received++
		slot.retained += len(frame.Payload)
		if slot.received != int(slot.fragmentCount) {
			return nil, false, nil
		}
		return reassembler.completeLocked(key, slot)
	}

	maxReservedBytes = min(maxReservedBytes, reassembler.config.MaxBytes)
	if int(frame.TotalLength) > maxReservedBytes {
		return nil, false, ErrReassemblyLimit
	}
	if len(reassembler.slots) >= reassembler.config.MaxSlots {
		reassembler.evictOldestLocked()
	}
	if reassembler.reservedBytes+int(frame.TotalLength) > maxReservedBytes {
		return nil, false, ErrReassemblyLimit
	}
	fragments := make([][]byte, int(frame.FragmentCount))
	fragments[int(frame.FragmentIndex)] = frame.Payload
	slot := &reassemblySlot{
		createdAt:     now,
		fragmentCount: frame.FragmentCount,
		totalLength:   frame.TotalLength,
		fragments:     fragments,
		received:      1,
		retained:      len(frame.Payload),
	}
	reassembler.slots[key] = slot
	reassembler.reservedBytes += int(frame.TotalLength)
	return nil, false, nil
}

func (reassembler *DatagramReassembler) RemoveFlow(flowID FlowID) {
	reassembler.mu.Lock()
	defer reassembler.mu.Unlock()
	for key := range reassembler.slots {
		if key.flowID == flowID {
			reassembler.removeLocked(key)
		}
	}
}

func (reassembler *DatagramReassembler) Clear() {
	reassembler.mu.Lock()
	clear(reassembler.slots)
	reassembler.reservedBytes = 0
	reassembler.mu.Unlock()
}

func (reassembler *DatagramReassembler) Expire(now time.Time) int {
	reassembler.mu.Lock()
	defer reassembler.mu.Unlock()
	return reassembler.expireLocked(now)
}

func (reassembler *DatagramReassembler) completeLocked(key reassemblyKey, slot *reassemblySlot) ([]byte, bool, error) {
	defer reassembler.removeLocked(key)
	if slot.retained != int(slot.totalLength) {
		return nil, false, ErrReassemblyLength
	}
	payload := make([]byte, 0, int(slot.totalLength))
	for _, fragment := range slot.fragments {
		if fragment == nil {
			return nil, false, ErrReassemblyLength
		}
		payload = append(payload, fragment...)
	}
	if len(payload) != int(slot.totalLength) {
		return nil, false, ErrReassemblyLength
	}
	return payload, true, nil
}

func (reassembler *DatagramReassembler) expireLocked(now time.Time) int {
	expired := 0
	for key, slot := range reassembler.slots {
		if now.Sub(slot.createdAt) > reassembler.config.TTL {
			reassembler.removeLocked(key)
			expired++
		}
	}
	return expired
}

func (reassembler *DatagramReassembler) evictOldestLocked() {
	var oldestKey reassemblyKey
	var oldest *reassemblySlot
	for key, slot := range reassembler.slots {
		if oldest == nil || slot.createdAt.Before(oldest.createdAt) {
			oldestKey, oldest = key, slot
		}
	}
	if oldest != nil {
		reassembler.removeLocked(oldestKey)
	}
}

func (reassembler *DatagramReassembler) removeLocked(key reassemblyKey) {
	slot := reassembler.slots[key]
	if slot == nil {
		return
	}
	delete(reassembler.slots, key)
	reassembler.reservedBytes -= int(slot.totalLength)
	if reassembler.reservedBytes < 0 {
		reassembler.reservedBytes = 0
	}
}
