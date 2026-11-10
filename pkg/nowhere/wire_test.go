// SPDX-License-Identifier: GPL-3.0-only

package nowhere

import (
	"bytes"
	"io"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

func TestFlowHeaderMatchesUpstreamFixedVectors(t *testing.T) {
	for _, kind := range []FlowKind{FlowKindTCP, FlowKindUDP} {
		encoded, err := EncodeFlowHeader(FlowHeader{Kind: kind})
		if err != nil || encoded[0] != byte(kind) {
			t.Fatal(encoded, err)
		}
		decoded, err := DecodeFlowHeader([]byte{byte(kind) | 0xfe})
		if err != nil || decoded.Kind != kind {
			t.Fatal(decoded, err)
		}
	}
	for _, id := range []uint64{0, 4, 4294967288} {
		got, err := UDPFlowID(id)
		if err != nil || uint64(got) != (id>>2)+1 {
			t.Fatal(id, got, err)
		}
	}
	for _, id := range []uint64{1, 2, 3, 4294967292, 1 << 62} {
		if _, err := UDPFlowID(id); err == nil {
			t.Fatalf("accepted %d", id)
		}
	}
}

func TestTargetMatchesSOCKS5Vectors(t *testing.T) {
	tests := []struct {
		target M.Socksaddr
		wire   []byte
	}{
		{M.ParseSocksaddr("192.0.2.1:443"), []byte{1, 192, 0, 2, 1, 1, 187}},
		{M.ParseSocksaddr("[2001:db8::1]:53"), []byte{4, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 53}},
		{M.Socksaddr{Fqdn: "xn--bcher-kva.example", Port: 8080}, append(append([]byte{3, 21}, []byte("xn--bcher-kva.example")...), 0x1f, 0x90)},
	}
	for _, test := range tests {
		buffer := make([]byte, TargetMaxEncodedLen)
		length, err := EncodeTarget(test.target, buffer)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buffer[:length], test.wire) {
			t.Fatalf("wire=%x want=%x", buffer[:length], test.wire)
		}
		decoded, err := ReadTarget(bytes.NewReader(test.wire))
		if err != nil || decoded.String() != test.target.String() {
			t.Fatalf("decoded=%s want=%s err=%v", decoded, test.target, err)
		}
	}
}

func TestSetupResultRejectsUnknownValues(t *testing.T) {
	for value := SetupReady; value <= SetupInternalError; value++ {
		decoded, err := DecodeSetupResult([]byte{byte(value)})
		if err != nil || decoded != value {
			t.Fatalf("value=%d decoded=%d err=%v", value, decoded, err)
		}
	}
	if _, err := DecodeSetupResult([]byte{5}); err == nil {
		t.Fatal("accepted unknown setup result")
	}
}

func TestWriteSetupResultCompletesShortWrites(t *testing.T) {
	writer := &oneByteWriter{}
	if err := WriteSetupResult(writer, SetupInvalidRequest); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(writer.output, []byte{byte(SetupInvalidRequest)}) {
		t.Fatalf("output=%x", writer.output)
	}
}

type oneByteWriter struct{ output []byte }

func (writer *oneByteWriter) Write(input []byte) (int, error) {
	if len(input) == 0 {
		return 0, nil
	}
	writer.output = append(writer.output, input[0])
	return 1, nil
}

var _ io.Writer = (*oneByteWriter)(nil)
