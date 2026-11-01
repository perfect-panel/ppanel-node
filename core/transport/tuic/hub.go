// Derived from wyx2685/Xray-core 83ad74c46335, transport/internet/tuic.
// Listener setup follows e087e74a1bf2's FinalMask API.
// Licensed under MPL-2.0; see LICENSE and README.md in this directory.

package tuic

import (
	"context"
	"net"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	upstream "github.com/xtls/xray-core/transport/internet/tuic"
)

type Listener struct {
	service *serverService
	rawConn net.PacketConn
	cancel  context.CancelFunc
}

func (l *Listener) Addr() net.Addr {
	return l.rawConn.LocalAddr()
}

func (l *Listener) Close() error {
	l.cancel()
	if l.service != nil {
		_ = l.service.CloseWithError()
	}
	return l.rawConn.Close()
}

func Listen(ctx context.Context, address xnet.Address, port xnet.Port, streamSettings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	if streamSettings == nil || streamSettings.SecuritySettings == nil {
		return nil, errors.New("TUIC requires TLS")
	}

	tlsConfig, ok := streamSettings.SecuritySettings.(*xtls.Config)
	if !ok || tlsConfig == nil {
		return nil, errors.New("TUIC requires TLS configuration")
	}

	authenticator := upstream.AuthenticatorFromContext(ctx)
	if authenticator == nil {
		return nil, errors.New("TUIC requires authenticator from context")
	}

	addr := &net.UDPAddr{
		IP:   address.IP(),
		Port: int(port),
	}
	var udpConn net.PacketConn
	var err error
	if streamSettings.FinalMask != nil {
		udpConn, err = streamSettings.FinalMask.ListenPacket(ctx, addr)
	} else {
		udpConn, err = internet.ListenSystemPacket(ctx, addr, streamSettings.SocketSettings)
	}
	if err != nil {
		return nil, err
	}

	serverTLSConfig := tlsConfig.GetTLSConfig(xtls.WithNextProto("h3"))
	if serverTLSConfig == nil {
		_ = udpConn.Close()
		return nil, errors.New("failed to get TLS config for TUIC")
	}

	listenerCtx, cancel := context.WithCancel(ctx)
	settings := upstream.ServerSettingsFromContext(ctx)
	service, err := newServerService(serverOptions{
		Context:           listenerCtx,
		TLSConfig:         serverTLSConfig,
		CongestionControl: settings.CongestionControl,
		AuthTimeout:       settings.AuthTimeout,
		ZeroRTTHandshake:  settings.ZeroRTTHandshake,
		UDPTimeout:        settings.UDPTimeout,
		Authenticator:     authenticator,
		Handler:           handler,
		LocalAddr:         udpConn.LocalAddr(),
	})
	if err != nil {
		cancel()
		_ = udpConn.Close()
		return nil, errors.New("failed to create TUIC service").Base(err)
	}
	if err := service.Start(udpConn); err != nil {
		cancel()
		_ = udpConn.Close()
		return nil, errors.New("failed to start TUIC service").Base(err)
	}

	errors.LogInfo(ctx, "TUIC server listening on ", address, ":", port)

	return &Listener{
		service: service,
		rawConn: udpConn,
		cancel:  cancel,
	}, nil
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, Listen))
}
