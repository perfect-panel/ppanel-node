package node

import (
	"context"
	"errors"
	"sync"

	"github.com/perfect-panel/ppanel-node/api/panel"
)

type trafficDestination struct {
	host, secret, protocol string
	id                     int
}

type trafficBatch struct {
	client *panel.NodeClient
	users  map[int]panel.UserTraffic
}

// trafficQueue survives core replacement, including reports for removed nodes.
// The panel has no idempotency key, so failed/ambiguous requests are retried with
// at-least-once delivery; successful batches are removed only after an ACK.
type trafficQueue struct {
	mu      sync.Mutex
	pending map[trafficDestination]*trafficBatch
}

func newTrafficQueue() *trafficQueue {
	return &trafficQueue{pending: make(map[trafficDestination]*trafficBatch)}
}

func (q *trafficQueue) add(client *panel.NodeClient, traffic []panel.UserTraffic) {
	if len(traffic) == 0 {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	key := trafficDestination{client.APIHost, client.SecretKey, client.NodeType, client.NodeId}
	batch := q.pending[key]
	if batch == nil {
		batch = &trafficBatch{users: make(map[int]panel.UserTraffic)}
		q.pending[key] = batch
	}
	batch.client = client
	for _, delta := range traffic {
		value := batch.users[delta.UID]
		value.UID = delta.UID
		value.Upload += delta.Upload
		value.Download += delta.Download
		batch.users[delta.UID] = value
	}
}

func (q *trafficQueue) report(ctx context.Context) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	var result error
	for key, batch := range q.pending {
		if ctx.Err() != nil {
			return errors.Join(result, ctx.Err())
		}
		traffic := make([]panel.UserTraffic, 0, len(batch.users))
		for _, value := range batch.users {
			traffic = append(traffic, value)
		}
		if err := batch.client.ReportUserTraffic(ctx, &traffic); err != nil {
			result = errors.Join(result, err)
			continue
		}
		delete(q.pending, key)
	}
	return result
}

func (c *Controller) collectTraffic(threshold int) []panel.UserTraffic {
	traffic, _ := c.server.GetUserTrafficSlice(c.tag, threshold)
	c.traffic.add(c.apiClient, traffic)
	return traffic
}
