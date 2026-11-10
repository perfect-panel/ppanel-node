// Copyright (C) 2026 PPanel contributors <https://github.com/perfect-panel>
// SPDX-License-Identifier: GPL-3.0-or-later

package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const rustVectorBinaryEnvironment = "NOWHERE_RUST_VECTOR_BINARY"

// TestNowhereRustInterop sends real upstream Rust Vector traffic through the
// node's Xray dispatcher, including accounting and device admission.
func TestNowhereRustInterop(t *testing.T) {
	binary := strings.TrimSpace(os.Getenv(rustVectorBinaryEnvironment))
	if binary == "" {
		t.Skip(rustVectorBinaryEnvironment + " is not set")
	}
	for _, morph := range []bool{false, true} {
		t.Run(fmt.Sprintf("morph=%v", morph), func(t *testing.T) {
			c, h, _, _, _, pin := newNowhereTestCore(t, morph)
			tcpTarget, udpTarget := nowhereEcho(t, "tcp"), nowhereEcho(t, "udp")
			for _, carrier := range []string{"tcp", "udp"} {
				t.Run(carrier, func(t *testing.T) {
					socksAddress := reserveTCPAddress(t)
					process := startRustVector(t, binary, h.Addr("tcp").String(), socksAddress, carrier, morph, pin)
					defer func() {
						process.stop()
						if t.Failed() {
							t.Logf("Rust Vector output:\n%s", process.logs.String())
						}
					}()
					waitForTCP(t, socksAddress, process, 10*time.Second)
					checkSOCKSTCP(t, socksAddress, tcpTarget)
					checkSOCKSUDP(t, socksAddress, udpTarget)
					checkSOCKSTCPConcurrent(t, socksAddress, tcpTarget)
				})
			}
			usage, err := c.GetUserTrafficSlice(nowhereTestTag, 0)
			if err != nil || len(usage) != 1 || usage[0].UID != 42 || usage[0].Upload == 0 || usage[0].Download == 0 {
				t.Fatalf("Rust traffic not billed: %+v %v", usage, err)
			}
		})
	}
}

func reserveTCPAddress(t testing.TB) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

type rustVectorProcess struct {
	cancel  context.CancelFunc
	command *exec.Cmd
	done    chan struct{}
	logs    bytes.Buffer
	waitErr error
	once    sync.Once
}

func startRustVector(
	t testing.TB,
	binary string,
	portalAddress string,
	socksAddress string,
	carrier string,
	morph bool,
	pin string,
) *rustVectorProcess {
	t.Helper()
	host, port, err := net.SplitHostPort(portalAddress)
	if err != nil {
		t.Fatal(err)
	}
	query := url.Values{"in": {socksAddress}, "pin": {pin}, "sni": {"localhost"}, "morph": {"0"}}
	if morph {
		query.Set("morph", "1")
	}
	commandURL := "vector://0123456789abcdef0123456789abcdef@" + host + "/" + carrier + ":" + port + "?" + query.Encode()
	ctx, cancel := context.WithCancel(context.Background())
	command := exec.CommandContext(ctx, binary, commandURL)
	command.Cancel = func() error { return command.Process.Signal(os.Interrupt) }
	command.WaitDelay = 5 * time.Second
	command.Env = append(os.Environ(), "NOW_HANDSHAKE_TIMEOUT=3s", "NOW_FLOW_SETUP_TIMEOUT=5s")
	process := &rustVectorProcess{cancel: cancel, command: command, done: make(chan struct{})}
	command.Stdout = &process.logs
	command.Stderr = &process.logs
	if err := command.Start(); err != nil {
		cancel()
		t.Fatalf("start Rust Vector: %v", err)
	}
	go func() {
		process.waitErr = command.Wait()
		close(process.done)
	}()
	t.Cleanup(process.stop)
	return process
}

func (process *rustVectorProcess) stop() {
	process.once.Do(func() {
		process.cancel()
		select {
		case <-process.done:
		case <-time.After(5 * time.Second):
			_ = process.command.Process.Kill()
			<-process.done
		}
	})
}

func waitForTCP(t testing.TB, address string, process *rustVectorProcess, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-process.done:
			t.Fatalf("Rust Vector exited before readiness: %v\n%s", process.waitErr, process.logs.String())
		default:
		}
		connection, err := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	process.stop()
	t.Fatalf("Rust Vector SOCKS listener %s did not become ready\n%s", address, process.logs.String())
}

func checkSOCKSTCP(t *testing.T, socksAddress, target string) {
	t.Helper()
	connection := dialSOCKSConnect(t, socksAddress, target)
	defer func() { _ = connection.Close() }()
	payload := []byte("rust-vector-tcp")
	if _, err := connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, response); err != nil || !bytes.Equal(response, payload) {
		t.Fatalf("TCP echo = %q, err=%v", response, err)
	}
}

func checkSOCKSTCPConcurrent(t *testing.T, socksAddress, target string) {
	t.Helper()
	const (
		flowCount    = 4
		payloadBytes = 2 << 20
	)
	connections := make([]net.Conn, flowCount)
	for index := range connections {
		connection := dialSOCKSConnect(t, socksAddress, target)
		_ = connection.SetDeadline(time.Now().Add(60 * time.Second))
		connections[index] = connection
		defer func() { _ = connection.Close() }()
	}
	start := make(chan struct{})
	errorsChannel := make(chan error, flowCount*2)
	var wait sync.WaitGroup
	for _, connection := range connections {
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			n, err := io.CopyN(io.Discard, connection, payloadBytes)
			if err != nil {
				err = fmt.Errorf("TCP echo read %d/%d bytes: %w", n, payloadBytes, err)
			}
			errorsChannel <- err
		}()
		go func() {
			defer wait.Done()
			payload := make([]byte, 128<<10)
			<-start
			remaining := int64(payloadBytes)
			for remaining > 0 {
				length := min(int64(len(payload)), remaining)
				written, err := connection.Write(payload[:length])
				if err != nil {
					errorsChannel <- err
					return
				}
				if written != int(length) {
					errorsChannel <- io.ErrShortWrite
					return
				}
				remaining -= length
			}
			if closer, exists := connection.(interface{ CloseWrite() error }); exists {
				if err := closer.CloseWrite(); err != nil {
					errorsChannel <- err
					return
				}
			}
			errorsChannel <- nil
		}()
	}
	close(start)
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func checkSOCKSUDP(t *testing.T, socksAddress, target string) {
	t.Helper()
	control := dialSOCKS(t, socksAddress)
	defer func() { _ = control.Close() }()
	if _, err := control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	relay, err := readSOCKSReply(control)
	if err != nil {
		t.Fatalf("SOCKS UDP ASSOCIATE: %v", err)
	}
	if relay.IP == nil || relay.IP.IsUnspecified() {
		relay.IP = net.ParseIP("127.0.0.1")
	}
	packet, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = packet.Close() }()
	_ = packet.SetDeadline(time.Now().Add(5 * time.Second))
	payload := []byte("rust-vector-udp")
	host, rawPort, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	request := append([]byte{0, 0, 0, 1}, net.ParseIP(host).To4()...)
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	request = append(request, payload...)
	if _, err = packet.WriteToUDP(request, relay); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 2048)
	length, _, err := packet.ReadFromUDP(response)
	if err != nil {
		t.Fatal(err)
	}
	offset, err := socksAddressEnd(response[:length], 3)
	if err != nil {
		t.Fatalf("SOCKS UDP response: %v", err)
	}
	if !bytes.Equal(response[offset:length], payload) {
		t.Fatalf("UDP echo = %q", response[offset:length])
	}
}

func dialSOCKS(t testing.TB, address string) net.Conn {
	t.Helper()
	connection, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = connection.Write([]byte{5, 1, 0}); err != nil {
		_ = connection.Close()
		t.Fatal(err)
	}
	response := make([]byte, 2)
	if _, err = io.ReadFull(connection, response); err != nil || !bytes.Equal(response, []byte{5, 0}) {
		_ = connection.Close()
		t.Fatalf("SOCKS greeting = %v, err=%v", response, err)
	}
	return connection
}

func dialSOCKSConnect(t testing.TB, address, target string) net.Conn {
	t.Helper()
	connection := dialSOCKS(t, address)
	host, rawPort, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	request := append([]byte{5, 1, 0, 1}, net.ParseIP(host).To4()...)
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	if _, err := connection.Write(request); err != nil {
		_ = connection.Close()
		t.Fatal(err)
	}
	if _, err := readSOCKSReply(connection); err != nil {
		_ = connection.Close()
		t.Fatalf("SOCKS CONNECT: %v", err)
	}
	return connection
}

func readSOCKSReply(reader io.Reader) (*net.UDPAddr, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	if header[0] != 5 || header[1] != 0 || header[2] != 0 {
		return nil, fmt.Errorf("reply header %v", header)
	}
	address := append([]byte(nil), header...)
	switch header[3] {
	case 1:
		address = append(address, make([]byte, net.IPv4len+2)...)
	case 4:
		address = append(address, make([]byte, net.IPv6len+2)...)
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return nil, err
		}
		address = append(address, length[0])
		address = append(address, make([]byte, int(length[0])+2)...)
	default:
		return nil, errors.New("invalid SOCKS address type")
	}
	readStart := 4
	if header[3] == 3 {
		readStart = 5
	}
	if _, err := io.ReadFull(reader, address[readStart:]); err != nil {
		return nil, err
	}
	end, err := socksAddressEnd(address, 3)
	if err != nil {
		return nil, err
	}
	port := int(binary.BigEndian.Uint16(address[end-2 : end]))
	var host string
	switch header[3] {
	case 1:
		host = net.IP(address[4:8]).String()
	case 4:
		host = net.IP(address[4:20]).String()
	case 3:
		host = string(address[5 : 5+int(address[4])])
	}
	ip := net.ParseIP(host)
	if ip == nil {
		resolved, resolveErr := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
		if resolveErr != nil {
			return nil, resolveErr
		}
		return resolved, nil
	}
	return &net.UDPAddr{IP: ip, Port: port}, nil
}

func socksAddressEnd(packet []byte, typeOffset int) (int, error) {
	if len(packet) <= typeOffset {
		return 0, io.ErrUnexpectedEOF
	}
	var end int
	switch packet[typeOffset] {
	case 1:
		end = typeOffset + 1 + net.IPv4len + 2
	case 4:
		end = typeOffset + 1 + net.IPv6len + 2
	case 3:
		if len(packet) <= typeOffset+1 {
			return 0, io.ErrUnexpectedEOF
		}
		end = typeOffset + 2 + int(packet[typeOffset+1]) + 2
	default:
		return 0, errors.New("invalid SOCKS address type")
	}
	if len(packet) < end {
		return 0, io.ErrUnexpectedEOF
	}
	return end, nil
}
