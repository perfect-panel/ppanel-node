package panel

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"time"

	serverv1 "github.com/perfect-panel/ppanel-node/api/server/v1"
	"google.golang.org/protobuf/proto"
)

func (c *NodeClient) GetUserAlive(ctx context.Context) (map[int]int, error) {
	const path = "/v1/server/alivelist"
	req := c.Client.R().SetContext(ctx)
	if c.UseProtobuf {
		setProtobufResponseAccept(req)
	}
	r, err := req.Get(path)
	if err != nil {
		return nil, fmt.Errorf("get online devices: %w", err)
	}
	if err := checkPanelResponse(r, c.APIHost+path); err != nil {
		return nil, err
	}
	var alive map[int]int
	if isProtobufResponse(r) {
		var message serverv1.GetServerAliveListResponse
		if err := proto.Unmarshal(r.Body(), &message); err != nil {
			return nil, err
		}
		if message.Data == nil {
			return nil, fmt.Errorf("missing online device data")
		}
		alive = make(map[int]int, len(message.Data.Alive))
		for id, count := range message.Data.Alive {
			if int64(int(id)) != id || int64(int(count)) != count {
				return nil, fmt.Errorf("online device count out of range")
			}
			alive[int(id)] = int(count)
		}
	} else {
		var message struct {
			Alive map[int]int `json:"alive"`
			Data  *AliveMap   `json:"data"`
		}
		if err := json.Unmarshal(r.Body(), &message); err != nil {
			return nil, err
		}
		alive = message.Alive
		if message.Data != nil {
			alive = message.Data.Alive
		}
		if alive == nil {
			return nil, fmt.Errorf("missing online device data")
		}
	}
	for id, count := range alive {
		if id <= 0 || count < 0 {
			return nil, fmt.Errorf("invalid online device count")
		}
	}
	return alive, nil
}

// ClaimDevice atomically reserves a global subscription/IP slot. HTTP or
// decoding failures are errors, never implicit permission to admit a device.
func (c *NodeClient) ClaimDevice(ctx context.Context, id int, ip string) (bool, time.Duration, error) {
	const path = "/v1/server/device"
	req := c.Client.R().SetContext(ctx)
	if c.UseProtobuf {
		if err := setProtobufRequestBody(req, &serverv1.ClaimServerDeviceRequest{UserId: int64(id), Ip: ip}); err != nil {
			return false, 0, err
		}
	} else {
		req.SetBody(map[string]any{"uid": id, "ip": ip})
	}
	r, err := req.Post(path)
	if err != nil {
		return false, 0, fmt.Errorf("claim device: %w", err)
	}
	if err := checkPanelResponse(r, c.APIHost+path); err != nil {
		return false, 0, err
	}
	var allowed bool
	var ttl int64
	if isProtobufResponse(r) {
		var message serverv1.ClaimServerDeviceResponse
		if err := proto.Unmarshal(r.Body(), &message); err != nil {
			return false, 0, err
		}
		if message.Data == nil {
			return false, 0, fmt.Errorf("missing device claim data")
		}
		allowed, ttl = message.Data.Allowed, message.Data.TtlSeconds
	} else {
		var message struct {
			Allowed    *bool `json:"allowed"`
			TTLSeconds int64 `json:"ttl_seconds"`
		}
		if err := json.Unmarshal(r.Body(), &message); err != nil {
			return false, 0, err
		}
		if message.Allowed == nil {
			return false, 0, fmt.Errorf("missing device claim decision")
		}
		allowed, ttl = *message.Allowed, message.TTLSeconds
	}
	if ttl <= 0 || ttl > 86400 {
		return false, 0, fmt.Errorf("invalid device lease lifetime")
	}
	return allowed, time.Duration(ttl) * time.Second, nil
}
