package limiter

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/common/format"
	"github.com/perfect-panel/ppanel-node/conf"
)

type admissionClock struct{ nanos atomic.Int64 }

func (c *admissionClock) now() time.Time   { return time.Unix(0, c.nanos.Load()) }
func (c *admissionClock) set(at time.Time) { c.nanos.Store(at.UnixNano()) }

func admissionTestLimiter() (*Limiter, *admissionClock, string) {
	l := NewManager().Add("claims", []panel.UserInfo{{Id: 21, Uuid: "user", DeviceLimit: 1000}}, nil, "vless")
	clock := &admissionClock{}
	clock.set(time.Now())
	l.clock = clock.now
	return l, clock, format.UserTag("claims", "user")
}

func waitForAdmissionState(t *testing.T, l *Limiter, ready func(*deviceAdmissionState) bool) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for {
		l.aliveMu.Lock()
		ok := ready(&l.admission)
		l.aliveMu.Unlock()
		if ok {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("admission state did not settle")
		case <-time.After(time.Millisecond):
		}
	}
}

func TestDeviceClaimsCoalesceAndBoundWaiters(t *testing.T) {
	l, clock, tag := admissionTestLimiter()
	var calls atomic.Int32
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	l.SetDeviceAdmission(func(ctx context.Context, _ int, _ string) (bool, time.Duration, error) {
		calls.Add(1)
		select {
		case <-release:
			return true, time.Minute, nil
		case <-ctx.Done():
			return false, 0, ctx.Err()
		}
	})
	var group sync.WaitGroup
	for i := range maxDeviceClaimWaiters {
		group.Go(func() {
			ip := "127.0.0.1"
			if i%2 == 0 {
				ip = "::ffff:127.0.0.1"
			}
			_, closeConn, rejected := l.Acquire(t.Context(), tag, ip)
			if rejected {
				t.Error("shared request rejected")
				return
			}
			closeConn()
		})
	}
	waitForAdmissionState(t, l, func(a *deviceAdmissionState) bool { return a.waiters == maxDeviceClaimWaiters })
	if _, _, rejected := l.Acquire(t.Context(), tag, "127.0.0.1"); !rejected {
		t.Fatal("waiter bound exceeded")
	}
	if calls.Load() != 1 {
		t.Fatalf("same-IP requests = %d, want 1", calls.Load())
	}
	unblock()
	group.Wait()
	for range 32 {
		_, closeConn, rejected := l.Acquire(t.Context(), tag, "127.0.0.1")
		if rejected {
			t.Fatal("warm lease rejected")
		}
		closeConn()
	}
	if calls.Load() != 1 {
		t.Fatal("warm lease triggered a panel request")
	}
	clock.set(clock.now().Add(time.Minute))
	_, closeConn, rejected := l.Acquire(t.Context(), tag, "127.0.0.1")
	if rejected || calls.Load() != 2 {
		t.Fatal("expired lease did not require a fresh grant")
	}
	closeConn()
}

func TestDeviceClaimsBoundConcurrentHTTPWork(t *testing.T) {
	l, _, tag := admissionTestLimiter()
	var calls atomic.Int32
	entered := make(chan struct{}, maxPendingDeviceClaims)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	l.SetDeviceAdmission(func(ctx context.Context, _ int, _ string) (bool, time.Duration, error) {
		calls.Add(1)
		entered <- struct{}{}
		select {
		case <-release:
			return true, time.Minute, nil
		case <-ctx.Done():
			return false, 0, ctx.Err()
		}
	})
	var group sync.WaitGroup
	for i := range maxPendingDeviceClaims {
		group.Go(func() {
			_, closeConn, rejected := l.Acquire(t.Context(), tag, fmt.Sprintf("10.0.0.%d", i+1))
			if rejected {
				t.Error("in-capacity claim rejected")
				return
			}
			closeConn()
		})
	}
	for range maxPendingDeviceClaims {
		<-entered
	}
	if _, _, rejected := l.Acquire(t.Context(), tag, "10.0.1.1"); !rejected {
		t.Fatal("pending request bound exceeded")
	}
	if calls.Load() != maxPendingDeviceClaims {
		t.Fatal("excess request reached the panel")
	}
	unblock()
	group.Wait()
	_, closeConn, rejected := l.Acquire(t.Context(), tag, "10.0.1.1")
	if rejected {
		t.Fatal("capacity not released")
	}
	closeConn()
}

func TestCancelingOneWaiterKeepsSharedClaimAlive(t *testing.T) {
	l, _, tag := admissionTestLimiter()
	entered := make(chan context.Context, 1)
	release := make(chan struct{})
	l.SetDeviceAdmission(func(ctx context.Context, _ int, _ string) (bool, time.Duration, error) {
		entered <- ctx
		select {
		case <-release:
			return true, time.Minute, nil
		case <-ctx.Done():
			return false, 0, ctx.Err()
		}
	})
	first, cancel := context.WithCancel(t.Context())
	defer cancel()
	results := make(chan bool, 2)
	open := func(ctx context.Context) {
		_, closeConn, rejected := l.Acquire(ctx, tag, "127.0.0.1")
		if closeConn != nil {
			closeConn()
		}
		results <- rejected
	}
	go open(first)
	requestCtx := <-entered
	go open(t.Context())
	waitForAdmissionState(t, l, func(a *deviceAdmissionState) bool { return a.waiters == 2 })
	cancel()
	if !<-results {
		t.Fatal("canceled waiter admitted")
	}
	if requestCtx.Err() != nil {
		t.Fatal("one waiter canceled shared request")
	}
	close(release)
	if <-results {
		t.Fatal("remaining waiter rejected")
	}
}

func TestLastWaiterCancellationAndTimeoutDoNotGrant(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		t.Run(fmt.Sprint(timeout), func(t *testing.T) {
			l, _, tag := admissionTestLimiter()
			l.admission.timeout = 20 * time.Millisecond
			entered := make(chan struct{})
			l.SetDeviceAdmission(func(ctx context.Context, _ int, _ string) (bool, time.Duration, error) {
				close(entered)
				<-ctx.Done()
				return true, time.Hour, nil
			})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan bool, 1)
			go func() { _, _, rejected := l.Acquire(ctx, tag, "127.0.0.1"); done <- rejected }()
			<-entered
			if !timeout {
				cancel()
			}
			if !<-done {
				t.Fatal("canceled or timed-out grant admitted")
			}
			waitForAdmissionState(t, l, func(a *deviceAdmissionState) bool { return a.pending == 0 && a.waiters == 0 })
			if len(l.online) != 0 {
				t.Fatal("canceled grant published online state")
			}
			if !timeout && l.admission.failures != 0 {
				t.Fatal("client cancellation tripped panel backoff")
			}
		})
	}
}

func TestDeviceAdmissionRevocationRejectsOldIncarnation(t *testing.T) {
	l, _, tag := admissionTestLimiter()
	entered := make(chan struct{})
	var calls atomic.Int32
	l.SetDeviceAdmission(func(ctx context.Context, _ int, _ string) (bool, time.Duration, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-ctx.Done()
		}
		return true, time.Minute, nil
	})
	done := make(chan bool, 1)
	go func() { _, _, rejected := l.Acquire(t.Context(), tag, "127.0.0.1"); done <- rejected }()
	<-entered
	user := panel.UserInfo{Id: 21, Uuid: "user", DeviceLimit: 1}
	l.UpdateUser("claims", nil, []panel.UserInfo{user})
	l.UpdateUser("claims", []panel.UserInfo{user}, nil)
	if !<-done {
		t.Fatal("old user incarnation admitted")
	}
	_, closeConn, rejected := l.Acquire(t.Context(), tag, "127.0.0.1")
	if rejected || calls.Load() != 2 {
		t.Fatal("re-added user did not receive a new grant")
	}
	closeConn()
}

func TestDeviceAdmissionHonorsRetryAfterAndProbesOnce(t *testing.T) {
	l, clock, tag := admissionTestLimiter()
	var calls atomic.Int32
	probeEntered, probeRelease := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch calls.Add(1) {
		case 2:
			w.Header().Set("Retry-After", "60")
			http.Error(w, "busy", 503)
			return
		case 3:
			close(probeEntered)
			select {
			case <-probeRelease:
			case <-r.Context().Done():
				return
			}
		}
		fmt.Fprint(w, `{"allowed":true,"ttl_seconds":300}`)
	}))
	defer server.Close()
	client, err := panel.NewNodeClient(&conf.NodeApiConfig{APIHost: server.URL, NodeType: "vless"})
	if err != nil {
		t.Fatal(err)
	}
	l.SetDeviceAdmission(client.ClaimDevice)
	_, closeConn, rejected := l.Acquire(t.Context(), tag, "127.0.0.1")
	if rejected {
		t.Fatal("initial grant rejected")
	}
	closeConn()
	if _, _, rejected := l.Acquire(t.Context(), tag, "127.0.0.2"); !rejected {
		t.Fatal("503 admitted")
	}
	if l.admission.retryAt.Before(clock.now().Add(time.Minute)) {
		t.Fatal("Retry-After shortened")
	}
	for i := range 32 {
		if _, _, rejected := l.Acquire(t.Context(), tag, fmt.Sprintf("10.0.0.%d", i+1)); !rejected {
			t.Fatal("backoff admitted")
		}
	}
	_, closeConn, rejected = l.Acquire(t.Context(), tag, "127.0.0.1")
	if rejected || calls.Load() != 2 {
		t.Fatal("backoff blocked warm lease or retried new claims")
	}
	closeConn()
	clock.set(l.admission.retryAt)
	result := make(chan bool, 1)
	go func() {
		_, closeConn, rejected := l.Acquire(t.Context(), tag, "127.0.0.2")
		if closeConn != nil {
			closeConn()
		}
		result <- rejected
	}()
	<-probeEntered
	for i := range 32 {
		if _, _, rejected := l.Acquire(t.Context(), tag, fmt.Sprintf("10.0.0.%d", i+1)); !rejected {
			t.Fatal("additional probe admitted")
		}
	}
	if calls.Load() != 3 {
		t.Fatal("recovery created a request burst")
	}
	close(probeRelease)
	if <-result {
		t.Fatal("recovery probe failed")
	}
	_, closeConn, rejected = l.Acquire(t.Context(), tag, "127.0.0.3")
	if rejected || calls.Load() != 4 || l.admission.failures != 0 {
		t.Fatal("successful probe did not restore admission")
	}
	closeConn()
}

func TestDeviceAdmissionBackoffGrowsAndIsBounded(t *testing.T) {
	l, clock, tag := admissionTestLimiter()
	l.SetDeviceAdmission(func(context.Context, int, string) (bool, time.Duration, error) {
		return false, 0, errors.New("panel unavailable")
	})
	for i := range 10 {
		if _, _, rejected := l.Acquire(t.Context(), tag, "127.0.0.1"); !rejected {
			t.Fatal("failure admitted")
		}
		ceiling := min(time.Second<<min(i, 5), 30*time.Second)
		delay := l.admission.retryAt.Sub(clock.now())
		if delay < ceiling/2 || delay > ceiling {
			t.Fatalf("backoff #%d = %s, ceiling=%s", i, delay, ceiling)
		}
		clock.set(l.admission.retryAt)
	}
}

func TestBurstFailuresAdvanceBackoffOnce(t *testing.T) {
	l, clock, tag := admissionTestLimiter()
	release := make(chan struct{})
	l.SetDeviceAdmission(func(ctx context.Context, _ int, _ string) (bool, time.Duration, error) {
		select {
		case <-release:
			return false, 0, errors.New("panel unavailable")
		case <-ctx.Done():
			return false, 0, ctx.Err()
		}
	})
	var group sync.WaitGroup
	for i := range 16 {
		group.Go(func() {
			if _, _, rejected := l.Acquire(t.Context(), tag, fmt.Sprintf("10.0.0.%d", i+1)); !rejected {
				t.Error("failed burst admitted")
			}
		})
	}
	waitForAdmissionState(t, l, func(a *deviceAdmissionState) bool { return a.pending == 16 })
	close(release)
	group.Wait()
	delay := l.admission.retryAt.Sub(clock.now())
	if l.admission.failures != 1 || delay < time.Second/2 || delay > time.Second {
		t.Fatalf("one failure wave escalated backoff: failures=%d delay=%s", l.admission.failures, delay)
	}
}

func TestOlderSuccessDoesNotClearNewerFailureBackoff(t *testing.T) {
	l, clock, tag := admissionTestLimiter()
	entered, release := make(chan struct{}), make(chan struct{})
	l.SetDeviceAdmission(func(ctx context.Context, _ int, ip string) (bool, time.Duration, error) {
		if ip == "127.0.0.1" {
			close(entered)
			select {
			case <-release:
				return true, time.Minute, nil
			case <-ctx.Done():
				return false, 0, ctx.Err()
			}
		}
		return false, 0, errors.New("panel unavailable")
	})
	done := make(chan bool, 1)
	go func() {
		_, closeConn, rejected := l.Acquire(t.Context(), tag, "127.0.0.1")
		if closeConn != nil {
			closeConn()
		}
		done <- rejected
	}()
	<-entered
	if _, _, rejected := l.Acquire(t.Context(), tag, "127.0.0.2"); !rejected {
		t.Fatal("failure admitted")
	}
	close(release)
	if <-done {
		t.Fatal("valid earlier grant rejected")
	}
	if l.admission.failures != 1 || !l.admission.retryAt.After(clock.now()) {
		t.Fatal("older success cleared new backoff")
	}
}

func TestDeviceQuotaDenialsAreCachedBoundedAndExpire(t *testing.T) {
	l, clock, tag := admissionTestLimiter()
	var calls atomic.Int32
	l.SetDeviceAdmission(func(context.Context, int, string) (bool, time.Duration, error) {
		calls.Add(1)
		return false, time.Minute, nil
	})
	for range 32 {
		if _, _, rejected := l.Acquire(t.Context(), tag, "127.0.0.1"); !rejected {
			t.Fatal("denial admitted")
		}
	}
	if calls.Load() != 1 {
		t.Fatal("quota denial not cached")
	}
	for i := range maxDeniedDeviceClaims + 10 {
		ip := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}).String()
		if _, _, rejected := l.Acquire(t.Context(), tag, ip); !rejected {
			t.Fatal("denial admitted")
		}
	}
	if len(l.admission.denied) > maxDeniedDeviceClaims || len(l.online) != 0 {
		t.Fatal("unbounded denial cache or denied online state")
	}
	clock.set(clock.now().Add(3 * time.Second))
	l.GetOnlineDevice()
	if len(l.admission.denied) != 0 {
		t.Fatal("heartbeat did not prune expired denials")
	}
	before := calls.Load()
	l.Acquire(t.Context(), tag, "127.0.0.1")
	if calls.Load() != before+1 {
		t.Fatal("expired denial was reused")
	}
}

func TestNewGrantDoesNotInheritUnconfirmedLease(t *testing.T) {
	l, clock, tag := admissionTestLimiter()
	l.online[21] = map[string]*onlineDevice{"127.0.0.1": {until: clock.now().Add(time.Hour)}}
	l.SetDeviceAdmission(func(context.Context, int, string) (bool, time.Duration, error) { return true, time.Minute, nil })
	_, closeConn, rejected := l.Acquire(t.Context(), tag, "127.0.0.1")
	if rejected {
		t.Fatal("grant rejected")
	}
	closeConn()
	if want := clock.now().Add(59 * time.Second); l.online[21]["127.0.0.1"].until != want {
		t.Fatal("unconfirmed expiry extended the panel grant")
	}
}

func BenchmarkAcquireCachedDevice(b *testing.B) {
	for _, size := range []int{1, 1000, 100000} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			l, _, tag := admissionTestLimiter()
			l.SetDeviceAdmission(func(context.Context, int, string) (bool, time.Duration, error) {
				b.Error("warm lease called panel")
				return false, 0, nil
			})
			l.online[21] = make(map[string]*onlineDevice, size)
			for i := range size {
				ip := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}).String()
				l.online[21][ip] = &onlineDevice{until: l.clock().Add(time.Hour), ttl: time.Hour, granted: true}
			}
			b.ReportAllocs()
			for b.Loop() {
				_, closeConn, rejected := l.Acquire(b.Context(), tag, "10.0.0.0")
				if rejected {
					b.Fatal("warm lease rejected")
				}
				closeConn()
			}
		})
	}
}
