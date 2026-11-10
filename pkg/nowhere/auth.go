// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// Copyright (C) 2026 PPanel contributors <https://github.com/perfect-panel>
// SPDX-License-Identifier: GPL-3.0-only

package nowhere

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

const (
	TLSExporterLen    = 32
	AuthTagLen        = 16
	AuthFrameLen      = AuthTagLen
	AuthExporterLabel = "EXPORTER-Nowhere-nw3-Auth"
)

var (
	ErrInvalidSharedKey = errors.New("nowhere: invalid shared key")
	ErrInvalidAuthFrame = errors.New("nowhere: invalid authentication frame")
)

var authRootSalt = sha256.Sum256([]byte("nowhere/nw3/auth-root"))

type AuthTransport uint8

const (
	AuthTransportTLSTCP AuthTransport = 0x01
	AuthTransportQUIC   AuthTransport = 0x02
)

type AuthKey [sha256.Size]byte
type TLSExporter [TLSExporterLen]byte
type AuthFrame [AuthFrameLen]byte

// authenticationMAC precomputes the HMAC pads used by every carrier for one
// user. The authenticated message has a fixed size, so the two SHA-256 inputs
// can stay on the stack instead of constructing a hash.Hash for every user
// inspected by a cold multi-user scan.
type authenticationMAC struct {
	inner [sha256.BlockSize]byte
	outer [sha256.BlockSize]byte
}

func DeriveAuthKey(sharedKey []byte) (AuthKey, error) {
	if !ValidSharedKey(sharedKey) {
		return AuthKey{}, ErrInvalidSharedKey
	}
	authRoot := hmacSHA256(authRootSalt[:], sharedKey)
	mac := hmac.New(sha256.New, authRoot[:])
	_, _ = mac.Write([]byte("vector-authentication"))
	_, _ = mac.Write([]byte{1})
	var key AuthKey
	copy(key[:], mac.Sum(nil))
	return key, nil
}

func ValidSharedKey(sharedKey []byte) bool {
	if len(sharedKey) != 32 {
		return false
	}
	for _, value := range sharedKey {
		if !(value >= '0' && value <= '9' || value >= 'a' && value <= 'f') {
			return false
		}
	}
	return true
}

func EncodeAuthFrame(key AuthKey, transport AuthTransport, exporter TLSExporter) (AuthFrame, error) {
	if transport != AuthTransportTLSTCP && transport != AuthTransportQUIC {
		return AuthFrame{}, ErrInvalidAuthFrame
	}
	var frame AuthFrame
	tag := AuthenticationTag(key, transport, exporter)
	copy(frame[:], tag[:])
	return frame, nil
}

func AuthenticationTag(key AuthKey, transport AuthTransport, exporter TLSExporter) [AuthTagLen]byte {
	return newAuthenticationMAC(key).tag(transport, exporter)
}

func newAuthenticationMAC(key AuthKey) authenticationMAC {
	var mac authenticationMAC
	for index := range sha256.BlockSize {
		keyByte := byte(0)
		if index < len(key) {
			keyByte = key[index]
		}
		mac.inner[index] = keyByte ^ 0x36
		mac.outer[index] = keyByte ^ 0x5c
	}
	return mac
}

func (mac authenticationMAC) tag(
	transport AuthTransport,
	exporter TLSExporter,
) [AuthTagLen]byte {
	var inner [sha256.BlockSize + 1 + TLSExporterLen]byte
	copy(inner[:sha256.BlockSize], mac.inner[:])
	inner[sha256.BlockSize] = byte(transport)
	copy(inner[sha256.BlockSize+1:], exporter[:])
	innerDigest := sha256.Sum256(inner[:])

	var outer [sha256.BlockSize + sha256.Size]byte
	copy(outer[:sha256.BlockSize], mac.outer[:])
	copy(outer[sha256.BlockSize:], innerDigest[:])
	full := sha256.Sum256(outer[:])
	var tag [AuthTagLen]byte
	copy(tag[:], full[:])
	return tag
}

func ValidateAuthFrame(frame AuthFrame, key AuthKey, transport AuthTransport, exporter TLSExporter) error {
	if transport != AuthTransportTLSTCP && transport != AuthTransportQUIC {
		return ErrInvalidAuthFrame
	}
	expected := AuthenticationTag(key, transport, exporter)
	if !hmac.Equal(frame[:], expected[:]) {
		return ErrInvalidAuthFrame
	}
	return nil
}

func ReadAuthFrame(reader io.Reader) (AuthFrame, error) {
	var frame AuthFrame
	if _, err := io.ReadFull(reader, frame[:]); err != nil {
		return AuthFrame{}, fmt.Errorf("nowhere: read authentication frame: %w", err)
	}
	return frame, nil
}

func hmacSHA256(key, input []byte) [sha256.Size]byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(input)
	var output [sha256.Size]byte
	copy(output[:], mac.Sum(nil))
	return output
}
