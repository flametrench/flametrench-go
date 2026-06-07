// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
package flags

import (
	"crypto/sha256"
	"encoding/binary"
)

// AssignBucket returns the percentage-rollout bucket for a (key, subjectID)
// pair. The result is in [0, 9999] (basis points). Defined by ADR 0021:
//
//	h  = SHA-256( utf8(key) || 0x00 || utf8(subjectID) )
//	n  = uint32_big_endian(h[0..4])
//	return n mod 10000
//
// subjectID MUST be the full wire-format id string (e.g. "usr_<32hex>"),
// UTF-8 encoded. Using the bare hex payload or the hyphenated UUID produces
// a different bucket and fails the cross-SDK conformance vectors.
func AssignBucket(key, subjectID string) uint32 {
	h := sha256.New()
	h.Write([]byte(key))
	h.Write([]byte{0x00})
	h.Write([]byte(subjectID))
	digest := h.Sum(nil)
	n := binary.BigEndian.Uint32(digest[:4])
	return n % 10000
}
