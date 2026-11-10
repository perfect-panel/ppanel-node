// Package nowhere implements the server side of NW3, including optional Morph
// and the authenticated Prelude Extension used by Nowhere 3.3.0.
//
// The wire contract is pinned to NodePassProject/Nowhere 3.3.0 (000007b).
// This is native Go; it does not embed the Rust runtime.
//
// SPDX-License-Identifier: GPL-3.0-only
package nowhere
