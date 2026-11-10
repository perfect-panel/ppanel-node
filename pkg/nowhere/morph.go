// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// Copyright (C) 2026 PPanel contributors <https://github.com/perfect-panel>
// SPDX-License-Identifier: GPL-3.0-only

package nowhere

type MorphKeys struct {
	TCPC2S, TCPS2C, UDPC2S, UDPS2C [32]byte
	PreludeAuth, PreludeMask       [32]byte
}

func deriveMorphKeys(sharedKey []byte) MorphKeys {
	root := hmacSHA256([]byte("nowhere/nw3/morph"), sharedKey)
	derive := func(label string) [32]byte { return hmacSHA256(root[:], append([]byte(label), 1)) }
	return MorphKeys{TCPC2S: derive("tcp c2s"), TCPS2C: derive("tcp s2c"), UDPC2S: derive("udp c2s"), UDPS2C: derive("udp s2c"), PreludeAuth: derive("tcp prelude auth"), PreludeMask: derive("tcp prelude mask")}
}
