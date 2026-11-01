package main

import (
	"context"
	"net"
	"testing"

	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/sys/unix"
)

func TestXrayListenerUsesTCPOnLinux(t *testing.T) {
	t.Setenv("GODEBUG", "")
	for _, tc := range []struct {
		name    string
		sockopt *internet.SocketConfig
	}{
		{name: "no socket settings"},
		{name: "default socket settings", sockopt: &internet.SocketConfig{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var system internet.DefaultListener
			listener, err := system.Listen(context.Background(), &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, tc.sockopt)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			raw, err := listener.(*net.TCPListener).SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			var protocol int
			var socketErr error
			if err := raw.Control(func(fd uintptr) {
				protocol, socketErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PROTOCOL)
			}); err != nil {
				t.Fatal(err)
			}
			if socketErr != nil {
				t.Fatal(socketErr)
			}
			if protocol != unix.IPPROTO_TCP {
				t.Fatalf("listener protocol = %d, want TCP (%d)", protocol, unix.IPPROTO_TCP)
			}
		})
	}
}
