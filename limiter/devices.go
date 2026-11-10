package limiter

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/juju/ratelimit"
	"github.com/perfect-panel/ppanel-node/api/panel"
)

type DeviceAdmission func(context.Context, int, string) (bool, time.Duration, error)

type onlineDevice struct {
	connections int
	until       time.Time
	ttl         time.Duration
	seen        time.Time
	pending     bool
	granted     bool
}

func leaseDeadline(start time.Time, ttl time.Duration) time.Time {
	// Redis lease scores use whole seconds. Cache permission conservatively
	// so a node never reuses it during the server's final fractional second.
	return start.Add(ttl - time.Second)
}

func (l *Limiter) SetDeviceAdmission(admit DeviceAdmission) {
	l.aliveMu.Lock()
	for _, claim := range l.admission.claims {
		claim.cancel()
	}
	clear(l.admission.claims)
	clear(l.admission.denied)
	l.admission.denialOrder.Init()
	l.admission.version++
	l.admission.failures, l.admission.retryAt, l.admission.probe = 0, time.Time{}, nil
	l.admitDevice = admit
	l.aliveMu.Unlock()
}

// CheckLimit is the legacy check-and-record API. Runtime connections use
// Acquire so closing their writer or cancelling their context releases them.
func (l *Limiter) CheckLimit(tag, ip string, _ bool) (*ratelimit.Bucket, bool) {
	bucket, _, rejected := l.Acquire(context.Background(), tag, ip)
	return bucket, rejected
}

// Acquire counts canonical source IPs for TCP and UDP alike. New IPs of
// limited subscriptions require a successful atomic panel admission.
func (l *Limiter) Acquire(ctx context.Context, tag, ip string) (*ratelimit.Bucket, func(), bool) {
	address, err := netip.ParseAddr(ip)
	if err != nil || address.Zone() != "" || address.IsUnspecified() || ctx.Err() != nil {
		return nil, nil, true
	}
	ip = address.Unmap().String()
	l.aliveMu.Lock()
	now := l.clock()
	value, ok := l.UserLimitInfo.Load(tag)
	if !ok {
		l.aliveMu.Unlock()
		return nil, nil, true
	}
	user := value.(*UserLimitInfo)
	uid, deviceLimit := user.UID, user.DeviceLimit
	devices := l.online[uid]
	device := devices[ip]
	// Expiration of unrelated IPs belongs to the periodic heartbeat sweep.
	if device != nil && device.connections == 0 && !device.until.After(now) {
		delete(devices, ip)
		device = nil
	}
	ttl := 5 * time.Minute
	until := leaseDeadline(now, ttl)
	granted := device != nil && device.granted
	if deviceLimit > 0 && (device == nil || !device.granted || !device.until.After(now)) {
		if l.admitDevice != nil {
			if !l.claimDeviceLocked(ctx, tag, ip, user) {
				l.aliveMu.Unlock()
				return nil, nil, true
			}
			devices = l.online[uid]
			device = devices[ip]
			ttl, until, granted = device.ttl, device.until, device.granted
		} else if device == nil {
			// The legacy local-only fallback needs an exact count only when
			// admitting a new IP at capacity. Atomic admission never scans here.
			if len(devices) >= deviceLimit {
				pruneIdleDevices(devices, now)
			}
			if max(l.aliveList[uid], len(devices)) >= deviceLimit {
				l.aliveMu.Unlock()
				return nil, nil, true
			}
		}
	} else if device != nil {
		// Reusing a granted IP must not extend its lease without a panel ACK.
		ttl, until = device.ttl, device.until
	}
	if devices == nil {
		devices = make(map[string]*onlineDevice)
		l.online[uid] = devices
	}
	if device == nil {
		device = &onlineDevice{}
		devices[ip] = device
	}
	device.connections++
	device.seen, device.pending = l.clock(), true
	device.ttl, device.until = ttl, until
	device.granted = granted
	if user.ExpireTime != 0 && user.ExpireTime < now.Unix() {
		user.DynamicSpeedLimit, user.ExpireTime = 0, 0
	}
	speed := int64(determineSpeedLimit(l.SpeedLimit, determineSpeedLimit(user.SpeedLimit, user.DynamicSpeedLimit))) * 1000000 / 8
	var bucket *ratelimit.Bucket
	if speed > 0 {
		stored, _ := l.SpeedLimiter.LoadOrStore(tag, ratelimit.NewBucketWithQuantum(time.Second, speed, speed))
		bucket = stored.(*ratelimit.Bucket)
	}
	l.aliveMu.Unlock()
	var once sync.Once
	release := func() {
		once.Do(func() {
			l.aliveMu.Lock()
			device.connections--
			l.aliveMu.Unlock()
		})
	}
	stop := context.AfterFunc(ctx, release)
	return bucket, func() { stop(); release() }, false
}

// GetOnlineDevice is a non-destructive heartbeat snapshot. Idle but still
// open connections continue renewing their slot; closed connections do not.
func (l *Limiter) GetOnlineDevice() (*[]panel.OnlineUser, error) {
	l.aliveMu.Lock()
	defer l.aliveMu.Unlock()
	users := make([]panel.OnlineUser, 0)
	now := l.clock()
	for uid, devices := range l.online {
		for ip, device := range devices {
			if device.connections == 0 && !device.until.After(now) {
				delete(devices, ip)
			} else if device.connections > 0 || device.pending {
				users = append(users, panel.OnlineUser{UID: uid, IP: ip})
			}
		}
		if len(devices) == 0 {
			delete(l.online, uid)
		}
	}
	l.pruneDeniedClaims(now)
	return &users, nil
}

func pruneIdleDevices(devices map[string]*onlineDevice, now time.Time) {
	for ip, device := range devices {
		if device.connections == 0 && !device.until.After(now) {
			delete(devices, ip)
		}
	}
}

func (l *Limiter) OnlineReportAcknowledged(users []panel.OnlineUser, sentAt time.Time) {
	l.aliveMu.Lock()
	defer l.aliveMu.Unlock()
	for _, user := range users {
		if device := l.online[user.UID][user.IP]; device != nil {
			if until := leaseDeadline(sentAt, device.ttl); until.After(device.until) {
				device.until = until
			}
			device.granted = true
			if !device.seen.After(sentAt) {
				device.pending = false
			}
		}
	}
}
