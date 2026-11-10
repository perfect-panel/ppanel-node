// Copyright (C) 2026 PPanel contributors <https://github.com/perfect-panel>
// SPDX-License-Identifier: GPL-3.0-or-later

package nowhere

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
)

// Morph is masking, not authentication. A new UDP route is only cached after
// verifying the QUIC v1 Initial AEAD; the exporter-bound NW3 tag still decides
// the authenticated user. See RFC 9001 section 5 and appendix A.
func initialLabel(secret []byte, label string, size int) []byte {
	label = "tls13 " + label
	info := append([]byte{0, byte(size), byte(len(label))}, []byte(label)...)
	info = append(info, 0, 1)
	value := hmacSHA256(secret, info)
	return value[:size]
}
func quicLongIDs(packet []byte) (dest, source []byte, end int, ok bool) {
	if len(packet) < 7 || packet[0]&0xc0 != 0xc0 || binary.BigEndian.Uint32(packet[1:5]) != 1 {
		return
	}
	n := int(packet[5])
	if n > 20 || len(packet) < 7+n {
		return
	}
	dest = packet[6 : 6+n]
	i := 6 + n
	m := int(packet[i])
	i++
	if m > 20 || len(packet) < i+m {
		return
	}
	return dest, packet[i : i+m], i + m, true
}
func quicVarint(packet []byte, offset *int) (uint64, bool) {
	if *offset >= len(packet) {
		return 0, false
	}
	n := 1 << uint(packet[*offset]>>6)
	if len(packet)-*offset < n {
		return 0, false
	}
	value := uint64(packet[*offset] & 63)
	for i := 1; i < n; i++ {
		value = value<<8 | uint64(packet[*offset+i])
	}
	*offset += n
	return value, true
}
func validClientInitial(packet []byte) bool {
	dcid, _, offset, ok := quicLongIDs(packet)
	if !ok || packet[0]&0x30 != 0 || len(dcid) < 8 {
		return false
	}
	tokenLen, ok := quicVarint(packet, &offset)
	if !ok || tokenLen > uint64(len(packet)-offset) {
		return false
	}
	offset += int(tokenLen)
	length, ok := quicVarint(packet, &offset)
	if !ok || length > uint64(len(packet)-offset) || length < 20 || offset+20 > len(packet) {
		return false
	}
	salt := []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	initial := hmacSHA256(salt, dcid)
	secret := initialLabel(initial[:], "client in", 32)
	hp, _ := aes.NewCipher(initialLabel(secret, "quic hp", 16))
	var mask [16]byte
	hp.Encrypt(mask[:], packet[offset+4:offset+20])
	first := packet[0] ^ mask[0]&15
	if first&12 != 0 {
		return false
	}
	pnLen := int(first&3) + 1
	header := append([]byte(nil), packet[:offset+pnLen]...)
	header[0] = first
	nonce := initialLabel(secret, "quic iv", 12)
	for i := 0; i < pnLen; i++ {
		header[offset+i] ^= mask[i+1]
		nonce[12-pnLen+i] ^= header[offset+i]
	}
	block, _ := aes.NewCipher(initialLabel(secret, "quic key", 16))
	aead, _ := cipher.NewGCM(block)
	_, err := aead.Open(nil, nonce, packet[offset+pnLen:offset+int(length)], header)
	return err == nil
}
