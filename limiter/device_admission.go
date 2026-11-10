package limiter

import (
	"container/list"
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/perfect-panel/ppanel-node/common/logx"
)

const (
	deviceClaimTimeout     = 5 * time.Second
	maxPendingDeviceClaims = 64
	maxDeviceClaimWaiters  = 256
	maxDeniedDeviceClaims  = 4096
)

type deviceClaimKey struct {
	uid int
	ip  string
}

type deviceClaim struct {
	tag               string
	user              *UserLimitInfo
	version, round    uint64
	start             time.Time
	done              chan struct{}
	cancel            context.CancelFunc
	waiters           int
	finished, allowed bool
}

type deniedDeviceClaim struct {
	key   deviceClaimKey
	user  *UserLimitInfo
	until time.Time
}

// All state is protected by aliveMu. Only pending requests and bounded quota
// denials live here; successful leases live in online and are renewed by ACKs.
type deviceAdmissionState struct {
	claims           map[deviceClaimKey]*deviceClaim
	denied           map[deviceClaimKey]*list.Element
	denialOrder      list.List
	pending, waiters int
	version, round   uint64
	failures         int
	retryAt          time.Time
	probe            *deviceClaim
	timeout          time.Duration
}

// claimDeviceLocked releases aliveMu while awaiting a shared request. Caller
// cancellation removes one waiter; the final waiter cancels unused work.
func (l *Limiter) claimDeviceLocked(ctx context.Context, tag, ip string, user *UserLimitInfo) bool {
	a := &l.admission
	key := deviceClaimKey{uid: user.UID, ip: ip}
	now := l.clock()
	if ctx.Err() != nil || a.waiters >= maxDeviceClaimWaiters || l.deniedClaim(key, user, now) {
		return false
	}
	claim := a.claims[key]
	if claim != nil && claim.user != user {
		claim = nil
	}
	if claim == nil {
		if a.pending >= maxPendingDeviceClaims || now.Before(a.retryAt) || a.probe != nil {
			return false
		}
		timeout := a.timeout
		if timeout <= 0 {
			timeout = deviceClaimTimeout
		}
		requestContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
		claim = &deviceClaim{tag: tag, user: user, version: a.version, round: a.round, start: now, done: make(chan struct{}), cancel: cancel}
		if a.claims == nil {
			a.claims = make(map[deviceClaimKey]*deviceClaim)
		}
		a.claims[key] = claim
		a.pending++
		if a.failures > 0 {
			a.probe = claim
		}
		go l.runDeviceClaim(requestContext, key, claim, l.admitDevice)
	}
	claim.waiters++
	a.waiters++
	l.aliveMu.Unlock()
	select {
	case <-ctx.Done():
	case <-claim.done:
	}
	l.aliveMu.Lock()
	claim.waiters--
	a.waiters--
	if claim.waiters == 0 && !claim.finished {
		claim.cancel()
	}
	device := l.online[user.UID][ip]
	return ctx.Err() == nil && claim.allowed && l.claimUserCurrent(claim) &&
		device != nil && device.granted && device.until.After(l.clock())
}

func (l *Limiter) claimUserCurrent(claim *deviceClaim) bool {
	current, exists := l.UserLimitInfo.Load(claim.tag)
	return exists && current == claim.user && claim.version == l.admission.version
}

func (l *Limiter) runDeviceClaim(ctx context.Context, key deviceClaimKey, claim *deviceClaim, admit DeviceAdmission) {
	allowed, ttl, err := admit(ctx, key.uid, key.ip)
	requestErr := ctx.Err()
	claim.cancel()
	var logErr error
	l.aliveMu.Lock()
	defer func() {
		l.aliveMu.Unlock()
		if logErr != nil {
			logx.Component("limiter").WithField("uid", key.uid).WithError(logErr).Warn("申请设备名额失败")
		}
	}()
	a := &l.admission
	a.pending--
	if a.claims[key] == claim {
		delete(a.claims, key)
	}
	if a.probe == claim {
		a.probe = nil
	}
	defer close(claim.done)
	claim.finished = true
	if !l.claimUserCurrent(claim) || errors.Is(requestErr, context.Canceled) {
		return
	}
	now := l.clock()
	until := leaseDeadline(claim.start, ttl)
	if requestErr != nil {
		err = requestErr
	}
	if err == nil && allowed && (ttl <= time.Second || !until.After(now)) {
		err = errors.New("expired device admission lease")
	}
	if err != nil {
		l.failDeviceAdmission(claim, err, now)
		logErr = err
		return
	}
	if claim.round == a.round && a.failures > 0 {
		a.failures, a.retryAt = 0, time.Time{}
		a.round++
	}
	if !allowed {
		l.cacheDeniedClaim(key, claim.user, now.Add(time.Second+time.Duration(rand.Int64N(int64(time.Second)))))
		return
	}
	// Publish permission before waking waiters so another connection cannot
	// start a duplicate HTTP call between completion and the first admission.
	devices := l.online[key.uid]
	if devices == nil {
		devices = make(map[string]*onlineDevice)
		l.online[key.uid] = devices
	}
	device := devices[key.ip]
	if device == nil {
		device = &onlineDevice{}
		devices[key.ip] = device
	}
	if !device.granted || until.After(device.until) {
		device.until = until
	}
	device.granted, device.ttl = true, ttl
	claim.allowed = true
}

func (l *Limiter) failDeviceAdmission(claim *deviceClaim, err error, now time.Time) {
	a := &l.admission
	if claim.round == a.round {
		a.failures = min(a.failures+1, 6)
		a.round++
		ceiling := min(time.Second<<(a.failures-1), 30*time.Second)
		delay := ceiling/2 + time.Duration(rand.Int64N(int64(ceiling/2)+1))
		a.retryAt = now.Add(delay)
	}
	// Concurrent failures belong to one failure round. Only the recovery probe
	// advances backoff; older completions cannot undo a successful probe.
	var retry interface{ RetryAfter() time.Duration }
	if a.failures > 0 && errors.As(err, &retry) && retry.RetryAfter() > 0 {
		delay := retry.RetryAfter()
		delay += time.Duration(rand.Int64N(int64(min(delay/10, time.Second)) + 1))
		if until := now.Add(delay); until.After(a.retryAt) {
			a.retryAt = until
		}
	}
}

func (l *Limiter) deniedClaim(key deviceClaimKey, user *UserLimitInfo, now time.Time) bool {
	e := l.admission.denied[key]
	if e == nil {
		return false
	}
	denied := e.Value.(deniedDeviceClaim)
	if denied.user != user || !now.Before(denied.until) {
		l.removeDeniedClaim(e)
		return false
	}
	l.admission.denialOrder.MoveToFront(e)
	return true
}

func (l *Limiter) cacheDeniedClaim(key deviceClaimKey, user *UserLimitInfo, until time.Time) {
	a := &l.admission
	if a.denied == nil {
		a.denied = make(map[deviceClaimKey]*list.Element)
	}
	if old := a.denied[key]; old != nil {
		l.removeDeniedClaim(old)
	}
	if len(a.denied) >= maxDeniedDeviceClaims {
		l.removeDeniedClaim(a.denialOrder.Back())
	}
	a.denied[key] = a.denialOrder.PushFront(deniedDeviceClaim{key: key, user: user, until: until})
}

func (l *Limiter) removeDeniedClaim(e *list.Element) {
	delete(l.admission.denied, e.Value.(deniedDeviceClaim).key)
	l.admission.denialOrder.Remove(e)
}

func (l *Limiter) pruneDeniedClaims(now time.Time) {
	for _, e := range l.admission.denied {
		if !now.Before(e.Value.(deniedDeviceClaim).until) {
			l.removeDeniedClaim(e)
		}
	}
}
