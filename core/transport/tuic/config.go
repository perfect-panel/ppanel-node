package tuic

import (
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/transport/internet"
	upstream "github.com/xtls/xray-core/transport/internet/tuic"
)

// ProtocolName distinguishes the repaired listener from the upstream listener.
// Authentication and packet interfaces remain those of the upstream TUIC proxy.
const ProtocolName = "ppnode-tuic"
const protocolName = ProtocolName

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() any { return new(upstream.Config) }))
}
