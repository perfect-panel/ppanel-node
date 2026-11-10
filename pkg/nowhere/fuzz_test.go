// SPDX-License-Identifier: GPL-3.0-only

package nowhere

import (
	"bytes"
	"testing"
)

func FuzzDecodeFlowHeader(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4})
	f.Add([]byte{0xff, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = DecodeFlowHeader(input)
	})
}

func FuzzDecodeUDPFrame(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 1})
	f.Add([]byte{1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 2, 0, 2, 1})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = DecodeUDPFrame(input)
	})
}

func FuzzReadTarget(f *testing.F) {
	f.Add([]byte{1, 127, 0, 0, 1, 0, 80})
	f.Add([]byte{3, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 1, 187})
	f.Add([]byte{3, 255})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = ReadTarget(bytes.NewReader(input))
	})
}
