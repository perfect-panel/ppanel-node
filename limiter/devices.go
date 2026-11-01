package limiter

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/juju/ratelimit"
	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/common/logx"
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
	now := time.Now()
	l.aliveMu.Lock()
	value, ok := l.UserLimitInfo.Load(tag)
	if !ok {
		l.aliveMu.Unlock()
		return nil, nil, true
	}
	user := value.(*UserLimitInfo)
	uid, deviceLimit := user.UID, user.DeviceLimit
	devices := l.online[uid]
	for addr, device := range devices {
		if device.connections == 0 && !device.until.After(now) {
			delete(devices, addr)
		}
	}
	device := devices[ip]
	ttl := 5 * time.Minute
	until := leaseDeadline(now, ttl)
	granted := device != nil && device.granted
	if deviceLimit > 0 && (device == nil || !device.granted || !device.until.After(now)) {
		if admit := l.admitDevice; admit != nil {
			l.aliveMu.Unlock()
			allowed, grantedTTL, err := admit(ctx, uid, ip)
			if err != nil {
				logx.Component("limiter").WithField("uid", uid).WithError(err).Warn("申请设备名额失败")
			}
			if err != nil || !allowed || grantedTTL <= 0 || ctx.Err() != nil {
				return nil, nil, true
			}
			ttl, until = grantedTTL, leaseDeadline(now, grantedTTL)
			granted = true
			if !until.After(time.Now()) {
				return nil, nil, true
			}
			l.aliveMu.Lock()
			// A user can be revoked while the network request is in flight.
			current, exists := l.UserLimitInfo.Load(tag)
			if !exists || current.(*UserLimitInfo).UID != uid {
				l.aliveMu.Unlock()
				return nil, nil, true
			}
			user = current.(*UserLimitInfo)
			devices = l.online[uid]
			device = devices[ip]
		} else if device == nil && max(l.aliveList[uid], len(devices)) >= deviceLimit {
			l.aliveMu.Unlock()
			return nil, nil, true
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
	device.seen, device.pending = time.Now(), true
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
	now := time.Now()
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
	return &users, nil
}

func (l *Limiter) OnlineReportAcknowledged(users []panel.OnlineUser, sentAt time.Time) {
	l.aliveMu.Lock()
	defer l.aliveMu.Unlock()
	for _, user := range users {
		if device := l.online[user.UID][user.IP]; device != nil {
			device.until = leaseDeadline(sentAt, device.ttl)
			device.granted = true
			if !device.seen.After(sentAt) {
				device.pending = false
			}
		}
	}
}
