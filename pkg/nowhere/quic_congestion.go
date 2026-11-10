// Copyright (C) 2026 PPanel contributors <https://github.com/perfect-panel>
// SPDX-License-Identifier: GPL-3.0-or-later

package nowhere

import (
	"time"

	congestionMeta1 "github.com/perfect-panel/nowhere/internal/congestion_meta1"
	congestionMeta2 "github.com/perfect-panel/nowhere/internal/congestion_meta2"
	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
)

// ConfigureQUICCongestion follows the upstream Portal's BBR default.
// quic-go constructs the handshake with its built-in controller, so the
// replacement is installed immediately after acceptance and before any
// authenticated data-plane stream is served.
func ConfigureQUICCongestion(conn *quic.Conn) {
	if conn == nil {
		return
	}
	conn.SetCongestionControl(congestionMeta2.NewBbrSender(
		congestionMeta2.DefaultClock{TimeFunc: time.Now},
		conn.InitialPacketSize(),
		congestion.ByteCount(congestionMeta1.InitialCongestionWindow),
	))
}
