package main

import (
	"net"
	"testing"
)

func TestTCPListenersDisableMPTCPByDefault(t *testing.T) {
	// Verify the compiled default, without relying on the service manager or
	// the developer's environment to disable MPTCP on vulnerable Linux kernels.
	t.Setenv("GODEBUG", "")
	var config net.ListenConfig
	if config.MultipathTCP() {
		t.Fatal("TCP listeners default to MPTCP; ppnode must build with multipathtcp=0")
	}
}
