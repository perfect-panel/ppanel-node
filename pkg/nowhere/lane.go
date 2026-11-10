// Copyright (C) 2026 PPanel contributors <https://github.com/perfect-panel>
// SPDX-License-Identifier: GPL-3.0-or-later

package nowhere

import (
	"io"
	"net"
	"sync"
	"time"
)

// lockedWriter keeps the one-byte setup result ordered before data-plane
// payload. The product callback reports handshake success synchronously, but
// the lock also protects custom callback providers that start a writer before
// returning.
type lockedWriter struct {
	writer io.Writer
	mu     sync.Mutex
}

func (writer *lockedWriter) Write(payload []byte) (int, error) {
	writer.mu.Lock()
	written, err := writer.writer.Write(payload)
	writer.mu.Unlock()
	return written, err
}

func (writer *lockedWriter) CloseWrite() error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if closer, exists := writer.writer.(interface{ CloseWrite() error }); exists {
		return closer.CloseWrite()
	}
	return nil
}

func (writer *lockedWriter) SetWriteDeadline(deadline time.Time) error {
	if setter, exists := writer.writer.(interface{ SetWriteDeadline(time.Time) error }); exists {
		return setter.SetWriteDeadline(deadline)
	}
	return nil
}

type uotPacketSource struct{ reader io.Reader }

func (source *uotPacketSource) ReadPacket(output []byte) (int, error) {
	return ReadUOTPacket(source.reader, output)
}

type uotPacketSink struct{ writer io.Writer }

func (sink *uotPacketSink) WritePacket(payload []byte) error {
	return WriteUOTPacket(sink.writer, payload)
}

type prefixedConn struct {
	net.Conn
	reader io.Reader
}

func (conn *prefixedConn) Read(output []byte) (int, error) { return conn.reader.Read(output) }
