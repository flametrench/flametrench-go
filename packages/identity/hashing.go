// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// MaxPasswordBytes is the hard cap on plaintext length before Argon2id.
// Without a cap a caller could burn the Argon2id memory cost (m=19 MiB)
// repeatedly on a multi-megabyte string. Reject rather than truncate
// so the caller learns about it. Matches the Python SDK constant.
const MaxPasswordBytes = 1024

// ErrPasswordTooLong is returned by HashPassword / VerifyPasswordHash
// when the candidate plaintext exceeds MaxPasswordBytes.
var ErrPasswordTooLong = errors.New("password exceeds 1024-byte cap")

const (
	argon2idSaltBytes = 16
	argon2idKeyLen    = 32
	argon2idVariant   = "argon2id"
	argon2idVersion   = argon2.Version // 0x13 = 19
)

func checkPasswordLength(plaintext string) error {
	if len(plaintext) > MaxPasswordBytes {
		return ErrPasswordTooLong
	}
	return nil
}

// HashPassword hashes a plaintext password with Argon2id at the spec
// floor parameters and returns a PHC-encoded string. The output
// verifies identically against any conforming Flametrench identity
// SDK's verifier (Argon2id cross-SDK interop is part of the
// conformance contract — see spec/conformance/fixtures/identity/argon2id.json).
//
// Plaintext over MaxPasswordBytes returns ErrPasswordTooLong.
func HashPassword(plaintext string) (string, error) {
	if err := checkPasswordLength(plaintext); err != nil {
		return "", err
	}
	salt := make([]byte, argon2idSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("salt generation failed: %w", err)
	}
	key := argon2.IDKey(
		[]byte(plaintext),
		salt,
		Argon2idFloor.TimeCost,
		Argon2idFloor.MemoryKiB,
		Argon2idFloor.Parallelism,
		argon2idKeyLen,
	)
	return encodePHC(salt, key), nil
}

// VerifyPasswordHash verifies a candidate plaintext against a PHC-encoded
// Argon2id hash. Returns true on match; false on any verification
// failure (wrong password, malformed PHC string, unsupported variant).
// Never returns false-positive on bad input.
//
// Plaintext over MaxPasswordBytes returns ErrPasswordTooLong — that's
// a caller-side input failure, not a verification outcome. All other
// PHC-parse / variant failures collapse to false.
func VerifyPasswordHash(phcHash, candidatePassword string) (bool, error) {
	if err := checkPasswordLength(candidatePassword); err != nil {
		return false, err
	}
	params, salt, want, err := decodePHC(phcHash)
	if err != nil {
		return false, nil
	}
	// Cross-implementation hashes may be at parameters above (but not
	// below) the spec floor. We compute at whatever parameters the hash
	// declares to remain compatible, then compare in constant time.
	got := argon2.IDKey(
		[]byte(candidatePassword),
		salt,
		params.TimeCost,
		params.MemoryKiB,
		params.Parallelism,
		uint32(len(want)),
	)
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

type argon2idParams struct {
	MemoryKiB   uint32
	TimeCost    uint32
	Parallelism uint8
}

// encodePHC renders an Argon2id PHC string in the standard format used
// across Flametrench SDKs:
//
//	$argon2id$v=19$m=<mem>,t=<time>,p=<para>$<b64salt>$<b64hash>
//
// (Where b64 is unpadded standard base64, matching argon2-cffi /
// PHP password_hash / Node argon2 / Spring Boot's defaults.)
func encodePHC(salt, key []byte) string {
	b64 := base64.RawStdEncoding
	return fmt.Sprintf(
		"$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2idVariant,
		argon2idVersion,
		Argon2idFloor.MemoryKiB,
		Argon2idFloor.TimeCost,
		Argon2idFloor.Parallelism,
		b64.EncodeToString(salt),
		b64.EncodeToString(key),
	)
}

// decodePHC parses an Argon2id PHC string. Returns the parameters, salt,
// expected hash, or an error if the string is malformed / non-argon2id.
func decodePHC(phc string) (argon2idParams, []byte, []byte, error) {
	parts := strings.Split(phc, "$")
	// Expected: ["", "argon2id", "v=19", "m=...,t=...,p=...", b64salt, b64hash]
	if len(parts) != 6 || parts[0] != "" {
		return argon2idParams{}, nil, nil, errors.New("malformed PHC string")
	}
	if parts[1] != argon2idVariant {
		return argon2idParams{}, nil, nil, fmt.Errorf("unsupported variant %q", parts[1])
	}
	if !strings.HasPrefix(parts[2], "v=") {
		return argon2idParams{}, nil, nil, errors.New("missing version segment")
	}
	v, err := strconv.Atoi(parts[2][2:])
	if err != nil || v != argon2idVersion {
		return argon2idParams{}, nil, nil, fmt.Errorf("unsupported version %q", parts[2])
	}

	var params argon2idParams
	for _, kv := range strings.Split(parts[3], ",") {
		eq := strings.IndexByte(kv, '=')
		if eq == -1 {
			return argon2idParams{}, nil, nil, fmt.Errorf("malformed param %q", kv)
		}
		key := kv[:eq]
		val := kv[eq+1:]
		n, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			return argon2idParams{}, nil, nil, fmt.Errorf("non-integer param %q", kv)
		}
		switch key {
		case "m":
			params.MemoryKiB = uint32(n)
		case "t":
			params.TimeCost = uint32(n)
		case "p":
			params.Parallelism = uint8(n)
		default:
			return argon2idParams{}, nil, nil, fmt.Errorf("unknown param %q", key)
		}
	}
	if params.MemoryKiB == 0 || params.TimeCost == 0 || params.Parallelism == 0 {
		return argon2idParams{}, nil, nil, errors.New("missing argon2id parameter")
	}

	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return argon2idParams{}, nil, nil, fmt.Errorf("salt decode: %w", err)
	}
	key, err := b64.DecodeString(parts[5])
	if err != nil {
		return argon2idParams{}, nil, nil, fmt.Errorf("hash decode: %w", err)
	}
	return params, salt, key, nil
}
