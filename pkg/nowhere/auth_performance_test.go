package nowhere

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/perfect-panel/nowhere/internal/authscan"
)

func performanceRecords(count int) []User {
	records := make([]User, count, count+1)
	for i := range records {
		records[i] = User{Name: fmt.Sprint(i + 1), Key: []byte(fmt.Sprintf("%032x", i+1))}
	}
	// The target is last in the input and in the final index shard. A cold
	// successful lookup therefore inspects at least 255/256 of the table.
	for candidate := count + 100; ; candidate++ {
		key := []byte(fmt.Sprintf("%032x", candidate))
		derived, _ := DeriveAuthKey(key)
		if derived[0] == 255 {
			records[count-1] = User{Name: "target", Key: key}
			return records
		}
	}
}

func performanceAuthenticator(b *testing.B, records []User) *Authenticator {
	b.Helper()
	update, err := PrepareAuthUpdate(records)
	if err != nil {
		b.Fatal(err)
	}
	a := NewAuthenticator()
	if err := a.Commit(update); err != nil {
		b.Fatal(err)
	}
	maxInt := int(^uint(0) >> 1)
	// Measure algorithm/allocation cost, not intentional production throttling.
	a.guard = authscan.NewGuard(authscan.HashAddr, authscan.GuardOptions{WorkRate: maxInt / 4, WorkBurst: maxInt / 2})
	return a
}

func performanceSource(sequence uint64) netip.Addr {
	var addr [16]byte
	addr[0] = 0xfd
	binary.BigEndian.PutUint64(addr[8:], sequence)
	return netip.AddrFrom16(addr)
}

func performancePrelude(shared []byte) []byte {
	keys := deriveMorphKeys(shared)
	bootstrap := make([]byte, morphPreludeLen+morphNonceLen)
	for i := range 32 {
		bootstrap[i] = byte(i)
		bootstrap[32+i] = byte(i&1) << 7
	}
	for i := range morphNonceLen {
		bootstrap[morphPreludeLen+i] = byte(i)
	}
	input := preludeInput(bootstrap[:morphPreludeLen], bootstrap[morphPreludeLen:])
	var payload [28]byte
	binary.BigEndian.PutUint64(payload[:8], 123)
	payload[13] = 1
	copy(input[48:], payload[:14])
	tag := hmacSHA256(keys.PreludeAuth[:], input[:])
	copy(payload[14:], tag[:14])
	mask := hmacSHA256(keys.PreludeMask[:], input[:48])
	for i := range payload {
		payload[i] ^= mask[i]
	}
	for i := range 32 {
		for bit := 0; bit < 7; bit++ {
			offset := i*7 + bit
			bootstrap[32+i] |= ((payload[offset/8] >> uint(7-offset%8)) & 1) << uint(6-bit)
		}
	}
	return bootstrap
}

func benchmarkTCPAuthentication(a *Authenticator, source netip.Addr, bootstrap []byte, frame AuthFrame) error {
	credential, _, err := a.selectMorphTCP(source, bootstrap)
	if err != nil {
		return err
	}
	_, err = a.authenticateSelected(frame, AuthTransportTLSTCP, TLSExporter{}, source, credential.authentication())
	return err
}

func BenchmarkMorphAuthentication(b *testing.B) {
	initial := captureInitial(b)
	for _, count := range []int{1000, 10000, 100000} {
		records := performanceRecords(count)
		b.Run(fmt.Sprintf("users=%d", count), func(b *testing.B) {
			for _, carrier := range []string{"tcp", "quic"} {
				for _, cached := range []bool{false, true} {
					mode := "cold"
					if cached {
						mode = "cached"
					}
					b.Run(carrier+"/"+mode, func(b *testing.B) {
						a := performanceAuthenticator(b, records)
						shared := records[len(records)-1].Key
						key, _ := DeriveAuthKey(shared)
						transport := AuthTransportTLSTCP
						if carrier == "quic" {
							transport = AuthTransportQUIC
						}
						frame, _ := EncodeAuthFrame(key, transport, TLSExporter{})
						bootstrap := performancePrelude(shared)
						keys := deriveMorphKeys(shared)
						wire := make([]byte, len(initial)+12)
						if err := morphXOR(wire[12:], initial, keys.UDPC2S, [12]byte{}, 0); err != nil {
							b.Fatal(err)
						}
						output := make([]byte, len(initial))
						source := performanceSource(0)
						if cached {
							if _, err := a.AuthenticateConnection(frame, transport, TLSExporter{}, source); err != nil {
								b.Fatal(err)
							}
						}
						var sequence uint64
						b.ReportAllocs()
						for b.Loop() {
							if !cached {
								sequence++
								source = performanceSource(sequence)
							}
							if carrier == "tcp" {
								if err := benchmarkTCPAuthentication(a, source, bootstrap, frame); err != nil {
									b.Fatal(err)
								}
							} else {
								raw := &queuedMorphPacketConn{packets: [][]byte{wire}, peer: net.UDPAddrFromAddrPort(netip.AddrPortFrom(source, 12345))}
								conn := newMorphPacketConn(raw, a)
								if n, _, err := conn.ReadFrom(output); err != nil || n != len(initial) {
									b.Fatalf("Initial: %d %v", n, err)
								}
								var selected Authentication
								for route := range conn.routes {
									selected = route.authentication
								}
								if _, err := a.authenticateSelected(frame, transport, TLSExporter{}, source, selected); err != nil {
									b.Fatal(err)
								}
							}
						}
					})
				}
			}
		})
	}
}

func benchmarkChangeOne(a *Authenticator, records []User, extra User, add bool) error {
	var update *AuthUpdate
	var err error
	if add {
		update, err = a.PrepareChanges([]User{extra}, nil)
	} else {
		update, err = a.PrepareChanges(nil, []string{extra.Name})
	}
	if err != nil {
		return err
	}
	return a.Commit(update)
}

// Each operation includes one addition followed by removal of that same user.
func BenchmarkAuthUserChanges(b *testing.B) {
	for _, count := range []int{1000, 10000, 100000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			records := performanceRecords(count)
			a := performanceAuthenticator(b, records)
			extra := User{Name: "extra", Key: []byte("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")}
			b.ReportAllocs()
			for b.Loop() {
				if err := benchmarkChangeOne(a, records, extra, true); err != nil {
					b.Fatal(err)
				}
				if err := benchmarkChangeOne(a, records, extra, false); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
