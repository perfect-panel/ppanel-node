package core

import (
	"fmt"
	xray "github.com/xtls/xray-core/core"

	"github.com/perfect-panel/ppanel-node/api/panel"
	inboundbuilder "github.com/perfect-panel/ppanel-node/core/inbound"
)

func (v *XrayCore) AddNode(tag string, info *panel.NodeInfo) error {
	inBoundConfig, err := inboundbuilder.Build(info, tag)
	if err != nil {
		return fmt.Errorf("build inbound error: %s", err)
	}
	err = v.addInbound(inBoundConfig)
	if err != nil {
		return fmt.Errorf("add inbound error: %s", err)
	}
	return nil
}

func (v *XrayCore) DelNode(tag string) error {
	err := v.removeInbound(tag)
	if err != nil {
		return fmt.Errorf("remove in error: %s", err)
	}
	return nil
}

func (v *XrayCore) AddNodeConfig(config *xray.InboundHandlerConfig) error {
	return v.addInbound(config)
}
