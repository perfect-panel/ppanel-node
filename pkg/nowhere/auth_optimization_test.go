package nowhere

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/perfect-panel/nowhere/internal/authscan"
)

func TestShortHMACMatchesStandardAndDoesNotAllocate(t *testing.T) {
	for _, keyLen := range []int{0, 16, 20, 32, 64, 65, 100} {
		for _, inputLen := range []int{0, 1, 21, 48, 62, 64, 65, 257} {
			key, input := make([]byte, keyLen), make([]byte, inputLen)
			for i := range key {
				key[i] = byte(i * 7)
			}
			for i := range input {
				input[i] = byte(i * 11)
			}
			reference := hmac.New(sha256.New, key)
			_, _ = reference.Write(input)
			got := hmacSHA256(key, input)
			if !hmac.Equal(got[:], reference.Sum(nil)) {
				t.Fatalf("HMAC mismatch: key=%d input=%d", keyLen, inputLen)
			}
		}
	}
	var key [32]byte
	var input [62]byte
	var result [32]byte
	if allocs := testing.AllocsPerRun(1000, func() { result = hmacSHA256(key[:], input[:]) }); allocs != 0 {
		t.Fatalf("short HMAC allocations=%v", allocs)
	}
	if result == [32]byte{} {
		t.Fatal("missing HMAC result")
	}
}

func TestColdMorphAllocationsDoNotGrowPerCandidate(t *testing.T) {
	for _, count := range []int{64, 4096} {
		a, _, _ := selectedAuthFixture(t, count)
		maxInt := int(^uint(0) >> 1)
		a.guard = authscan.NewGuard(authscan.HashAddr, authscan.GuardOptions{WorkRate: maxInt / 4, WorkBurst: maxInt / 2})
		prelude, nonce := fixedPrelude()
		bootstrap := append(prelude, nonce...)
		bootstrap[40] ^= 1
		source := netip.MustParseAddr("10.1.0.1")
		allocs := testing.AllocsPerRun(10, func() {
			a.guard.Reset(source)
			if _, _, err := a.selectMorphTCP(source, bootstrap); !errors.Is(err, ErrMorph) {
				t.Fatalf("invalid Prelude: %v", err)
			}
		})
		if allocs > 3 {
			t.Fatalf("%d candidates allocate %v objects per scan", count, allocs)
		}
	}
}

func TestScanWorkSaturatesWithoutOverflow(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	if scanWork(4096, maxInt) != maxInt || scanWork(4, 1000) != 4000 || scanWork(4, 0) != 1 {
		t.Fatal("scan budget arithmetic overflowed")
	}
}

func TestDeltaKeyExchangeKeepsOwnersAndCallerBuffersIsolated(t *testing.T) {
	a, records, old := selectedAuthFixture(t, 2)
	firstKey, _ := DeriveAuthKey(records[0].Key)
	changes := []User{{Name: records[0].Name, Key: append([]byte(nil), records[1].Key...)}, {Name: records[1].Name, Key: append([]byte(nil), records[0].Key...)}}
	update, err := a.PrepareChanges(changes, nil)
	if err != nil {
		t.Fatal(err)
	}
	changes[0].Key[0] = 'f'
	if err = a.Commit(update); err != nil {
		t.Fatal(err)
	}
	if a.IsCurrent(old) {
		t.Fatal("reassigned key retained its former owner")
	}
	frame, _ := EncodeAuthFrame(firstKey, AuthTransportTLSTCP, testExporter())
	got, err := a.AuthenticateConnection(frame, AuthTransportTLSTCP, testExporter(), netip.Addr{})
	if err != nil || got.Identity != records[1].Name {
		t.Fatalf("exchanged key owner: %+v %v", got, err)
	}
	secondKey, _ := DeriveAuthKey(records[1].Key)
	if a.users.Load().user(records[0].Name).key != secondKey {
		t.Fatal("caller mutation changed a prepared credential")
	}
}

func TestIncrementalUpdatesReuseCredentialsAndUntouchedShards(t *testing.T) {
	a, records, _ := selectedAuthFixture(t, 1024)
	before := a.users.Load()
	stable := before.user(records[0].Name)
	source := netip.MustParseAddr("10.1.0.1")
	frame, _ := EncodeAuthFrame(stable.key, AuthTransportTLSTCP, testExporter())
	if _, err := a.AuthenticateConnection(frame, AuthTransportTLSTCP, testExporter(), source); err != nil {
		t.Fatal(err)
	}
	cached, _ := a.addressCache.Load(source, authCacheGeneration)
	changed := records[1023]
	changed.Key = []byte(testSharedKey)
	old := before.user(changed.Name)
	update, err := a.PrepareChanges([]User{changed}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.users.Load() != before {
		t.Fatal("prepare published early")
	}
	if err := a.Commit(update); err != nil {
		t.Fatal(err)
	}
	after := a.users.Load()
	if after.count != before.count || after.user(stable.identity) != stable {
		t.Fatal("unchanged credentials were rebuilt")
	}
	if after.user(changed.Name) == old || a.IsCurrent(old.authentication()) {
		t.Fatal("rotation retained old authentication")
	}
	if before.user(changed.Name) != old || before.credential(old.key) != old {
		t.Fatal("published snapshot was mutated")
	}
	changedKeys, changedNames := 0, 0
	for i := range authShardCount {
		if after.shards[i] != before.shards[i] {
			changedKeys++
		}
		if fmt.Sprintf("%p", after.names[i]) != fmt.Sprintf("%p", before.names[i]) {
			changedNames++
		}
	}
	if changedKeys > 2 || changedNames != 1 {
		t.Fatalf("copied unrelated shards: keys=%d names=%d", changedKeys, changedNames)
	}
	nextCached, _ := a.addressCache.Load(source, authCacheGeneration)
	if cached != nextCached {
		t.Fatal("unrelated update invalidated a warm candidate")
	}
	if _, err := a.AuthenticateConnection(frame, AuthTransportTLSTCP, testExporter(), source); err != nil {
		t.Fatal(err)
	}
}

func TestIncrementalUpdatesAreAtomicAndRejectStaleWriters(t *testing.T) {
	a, records, _ := selectedAuthFixture(t, 2)
	before := a.users.Load()
	if _, err := a.PrepareChanges([]User{{Name: "duplicate", Key: records[0].Key}}, []string{records[1].Name}); !errors.Is(err, ErrDuplicateAuthKey) {
		t.Fatalf("duplicate key: %v", err)
	}
	if a.users.Load() != before {
		t.Fatal("failed preparation removed a user")
	}
	one, err := a.PrepareChanges([]User{{Name: "one", Key: []byte(testSharedKey)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	two, err := a.PrepareChanges(nil, []string{records[0].Name})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Commit(one); err != nil {
		t.Fatal(err)
	}
	if err := a.Commit(two); !errors.Is(err, ErrStaleAuthUpdate) {
		t.Fatalf("stale writer: %v", err)
	}
	if a.users.Load().user("one") == nil || a.users.Load().user(records[0].Name) == nil {
		t.Fatal("stale delta overwrote newer state")
	}
	noop, err := a.PrepareChanges([]User{records[0]}, nil)
	if err != nil {
		t.Fatal(err)
	}
	current := a.users.Load()
	if err := a.Commit(noop); err != nil {
		t.Fatal(err)
	}
	if a.users.Load() != current {
		t.Fatal("unchanged user caused a new table publication")
	}
}

func TestRemovedThenReaddedCredentialCannotReviveSelection(t *testing.T) {
	a, records, old := selectedAuthFixture(t, 1)
	source := netip.MustParseAddr("10.1.0.1")
	frame, _ := EncodeAuthFrame(old.key, AuthTransportQUIC, testExporter())
	if _, err := a.authenticateSelected(frame, AuthTransportQUIC, testExporter(), source, old); err != nil {
		t.Fatal(err)
	}
	removed, err := a.PrepareChanges(nil, []string{records[0].Name})
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Commit(removed); err != nil {
		t.Fatal(err)
	}
	readded, err := a.PrepareChanges(records, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Commit(readded); err != nil {
		t.Fatal(err)
	}
	if a.IsCurrent(old) {
		t.Fatal("retired credential ID became current again")
	}
	if _, err := a.authenticateSelected(frame, AuthTransportQUIC, testExporter(), source, old); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("retired selection: %v", err)
	}
	if hasCurrentCachedCandidate(a, source) {
		t.Fatal("cached retired ID became trusted")
	}
	fresh, err := a.AuthenticateConnection(frame, AuthTransportQUIC, testExporter(), source)
	if err != nil || fresh.id == old.id {
		t.Fatalf("fresh authentication: %+v %v", fresh, err)
	}
}

func TestConcurrentDeltaUpdatesKeepUnchangedAuthenticationValid(t *testing.T) {
	a, records, stable := selectedAuthFixture(t, 32)
	frame, _ := EncodeAuthFrame(stable.key, AuthTransportTLSTCP, testExporter())
	source := netip.MustParseAddr("10.1.0.1")
	if _, err := a.AuthenticateConnection(frame, AuthTransportTLSTCP, testExporter(), source); err != nil {
		t.Fatal(err)
	}
	a.guard = authscan.NewGuard(authscan.HashAddr, authscan.GuardOptions{WorkRate: 1 << 26, Concurrent: 16})
	var group sync.WaitGroup
	group.Go(func() {
		for i := range 100 {
			user := records[0]
			user.Key = []byte(fmt.Sprintf("%032x", i+1000))
			update, err := a.PrepareChanges([]User{user}, nil)
			if err != nil {
				t.Error(err)
				return
			}
			if err = a.Commit(update); err != nil {
				t.Error(err)
				return
			}
		}
	})
	for range 4 {
		group.Go(func() {
			for range 500 {
				got, err := a.AuthenticateConnection(frame, AuthTransportTLSTCP, testExporter(), source)
				if err != nil || got != stable {
					t.Errorf("unrelated delta disrupted auth: %+v %v", got, err)
					return
				}
			}
		})
	}
	group.Wait()
}

func TestMorphStaleMissRetriesWithoutSourceCooldown(t *testing.T) {
	a, _, _ := selectedAuthFixture(t, 1)
	source := netip.MustParseAddr("10.1.0.2")
	updated := false
	matched, err := a.matchMorph(source, 4, func(c *authCredential) bool {
		if !updated {
			updated = true
			update, err := a.PrepareChanges([]User{{Name: "new", Key: []byte(testSharedKey)}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err = a.Commit(update); err != nil {
				t.Fatal(err)
			}
		}
		return c.identity == "new"
	})
	if err != nil || matched == nil || matched.identity != "new" {
		t.Fatalf("stale miss prevented retry: %v %v", matched, err)
	}
	if a.guard.SourceBlocked(source) {
		t.Fatal("stale miss armed source cooldown")
	}
}

func TestMorphInitialHeaderDoesNotBypassAEADAndRetiredRouteCleanup(t *testing.T) {
	a, _, _ := selectedAuthFixture(t, 1)
	c := a.users.Load().user("user-0")
	initial := captureInitial(t)
	initial[len(initial)-1] ^= 1
	raw := &queuedMorphPacketConn{peer: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 7777}, packets: [][]byte{maskPacket(t, initial, c.morph.UDPC2S)}}
	conn := newMorphPacketConn(raw, a)
	if _, _, err := conn.ReadFrom(make([]byte, 65535)); !errors.Is(err, io.EOF) {
		t.Fatalf("tampered Initial: %v", err)
	}
	if len(conn.routes) != 0 {
		t.Fatal("header-only match created a route")
	}
	old := &morphUDPRoute{credential: c, serverIDs: map[string]uint64{"same-cid": 0}}
	fresh := &morphUDPRoute{credential: c, serverIDs: map[string]uint64{"same-cid": 0}}
	key := morphCIDKey{c.key, "same-cid"}
	conn.index[key] = fresh
	conn.removeLocked(old)
	if conn.index[key] != fresh {
		t.Fatal("retired route erased a newer CID owner")
	}
}
