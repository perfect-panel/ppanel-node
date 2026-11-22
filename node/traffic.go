package node

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"

	"github.com/perfect-panel/ppanel-node/api/panel"
)

// Match the panel's per-subscription admission bound, and keep SQL/HTTP
// request size bounded when many users accumulate traffic during an outage.
const maxTrafficReportBytes int64 = 10 << 40
const maxTrafficReportUsers = 1000

type trafficDestination struct {
	host, secret, protocol string
	id                     int
}

type trafficBatch struct {
	client   *panel.NodeClient
	users    map[int]panel.UserTraffic
	inflight []panel.UserTraffic
	reportID string
}

// trafficQueue survives core replacement, including reports for removed nodes.
// An uncertain send is frozen until ACK. New deltas accumulate separately.
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
		for batch.inflight != nil || len(batch.users) > 0 {
			if batch.inflight == nil {
				batch.reportID = rand.Text()
				batch.inflight = make([]panel.UserTraffic, 0, min(len(batch.users), maxTrafficReportUsers))
				for id, pending := range batch.users {
					part := pending
					part.Upload = min(part.Upload, maxTrafficReportBytes)
					part.Download = min(part.Download, maxTrafficReportBytes-part.Upload)
					batch.inflight = append(batch.inflight, part)
					if part == pending {
						delete(batch.users, id)
					} else {
						pending.Upload -= part.Upload
						pending.Download -= part.Download
						batch.users[id] = pending
					}
					if len(batch.inflight) == maxTrafficReportUsers {
						break
					}
				}
			}
			if err := batch.client.ReportTrafficBatch(ctx, batch.reportID, batch.inflight); err != nil {
				result = errors.Join(result, err)
				break
			}
			batch.inflight = nil
		}
		if batch.inflight != nil {
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
