package core

import (
	"context"
	"fmt"
	"time"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
)

func (v *XrayCore) removeInbound(tag string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return v.ihm.RemoveHandler(ctx, tag)
}

func (v *XrayCore) addInbound(config *core.InboundHandlerConfig) error {
	rawHandler, err := core.CreateObject(v.Server, config)
	if err != nil {
		return err
	}
	handler, ok := rawHandler.(inbound.Handler)
	if !ok {
		return fmt.Errorf("not an InboundHandler: %s", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := v.ihm.AddHandler(ctx, handler); err != nil {
		// The manager registers the handler before Start. Remove this failed
		// registration without removing a different handler on duplicate tags.
		if current, lookupErr := v.ihm.GetHandler(ctx, handler.Tag()); lookupErr == nil && current == handler {
			_ = v.ihm.RemoveHandler(ctx, handler.Tag())
		} else {
			_ = handler.Close()
		}
		return err
	}
	return nil
}
