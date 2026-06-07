// Package ids implements the Flametrench wire-format identifier
// specification — prefixed identifiers of the form `{prefix}_{32-hex}`
// where the hex payload is a UUIDv7.
//
// The package conforms to the spec at https://github.com/flametrench/spec/
// blob/main/docs/ids.md. The same JSON fixture corpus that gates the
// Python, Node, PHP, and Java SDKs runs against this package via the
// conformance/ runner in the repository root.
//
// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
package ids

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// InvalidIDError is returned when a string is not a syntactically valid
// wire-format identifier.
type InvalidIDError struct{ Reason string }

func (e *InvalidIDError) Error() string { return "invalid id: " + e.Reason }

// InvalidTypeError is returned when a type prefix is not in the
// registered set. Use [DecodeAny] / [IsValidShape] when application-
// defined types are legitimate inputs.
type InvalidTypeError struct{ Type string }

func (e *InvalidTypeError) Error() string {
	return fmt.Sprintf("unregistered type prefix: %q. Registered prefixes: %s",
		e.Type, strings.Join(RegisteredPrefixes(), ", "))
}

// IsInvalidID reports whether err is or wraps an InvalidIDError.
func IsInvalidID(err error) bool { var e *InvalidIDError; return errors.As(err, &e) }

// IsInvalidType reports whether err is or wraps an InvalidTypeError.
func IsInvalidType(err error) bool { var e *InvalidTypeError; return errors.As(err, &e) }

// Types is the registered type prefix set. Values are human-readable
// resource names — only the keys are wire-significant. Keep synchronized
// with `flametrench/spec/docs/ids.md` §"Type prefix registry".
var Types = map[string]string{
	"usr":  "user",
	"org":  "organization",
	"mem":  "membership",
	"inv":  "invitation",
	"ses":  "session",
	"cred": "credential",
	"tup":  "authorization_tuple",
	// v0.2 — ADR 0008
	"mfa": "mfa_factor",
	// v0.2 — ADR 0012
	"shr": "share_token",
	// v0.3 — ADR 0016
	"pat": "personal_access_token",
	// v0.4 — ADR 0019 / 0020 / 0021 / 0022
	"aud":  "audit_event",
	"file": "file_metadata",
	"flag": "feature_flag",
	"not":  "notification",
}

// RegisteredPrefixes returns the registered type prefixes in a stable
// alphabetical order, for diagnostic message rendering.
func RegisteredPrefixes() []string {
	out := make([]string, 0, len(Types))
	for k := range Types {
		out = append(out, k)
	}
	// Sort for stable error messages.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// DecodedID is the shape returned by [Decode] and [DecodeAny]. UUID is
// the canonical 8-4-4-4-12 hyphenated form.
type DecodedID struct {
	Type string
	UUID string
}

const hexPayloadLength = 32

func isHexLower(s string) bool {
	if len(s) != hexPayloadLength {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case '0' <= c && c <= '9':
		case 'a' <= c && c <= 'f':
		default:
			return false
		}
	}
	return true
}

func isVersionNibbleValid(b byte) bool {
	// Version nibble must be 1-8. Rejects nil UUID (v0) and max UUID (v15/f).
	return b >= '1' && b <= '8'
}

func assertType(t string) error {
	if _, ok := Types[t]; !ok {
		return &InvalidTypeError{Type: t}
	}
	return nil
}

// Encode encodes a type and UUID into Flametrench wire format. The UUID
// must be in canonical 8-4-4-4-12 form.
//
//	ids.Encode("usr", "0190f2a8-1b3c-7abc-8123-456789abcdef")
//	// → "usr_0190f2a81b3c7abc8123456789abcdef", nil
func Encode(typ, uuidStr string) (string, error) {
	if err := assertType(typ); err != nil {
		return "", err
	}
	// Require canonical 8-4-4-4-12 form. Matches Python's _is_valid_uuid_string.
	if len(uuidStr) != 36 ||
		uuidStr[8] != '-' || uuidStr[13] != '-' ||
		uuidStr[18] != '-' || uuidStr[23] != '-' {
		return "", &InvalidIDError{Reason: "value is not a canonical UUID: " + uuidStr}
	}
	if _, err := uuid.Parse(uuidStr); err != nil {
		return "", &InvalidIDError{Reason: "value is not a valid UUID: " + uuidStr}
	}
	// Strip hyphens, lowercase.
	hexPayload := strings.ToLower(strings.ReplaceAll(uuidStr, "-", ""))
	return typ + "_" + hexPayload, nil
}

func decodeShape(id string) (typ, hex string, err error) {
	sep := strings.IndexByte(id, '_')
	if sep == -1 {
		return "", "", &InvalidIDError{Reason: "id missing type separator: " + id}
	}
	typ = id[:sep]
	hex = id[sep+1:]
	if len(typ) == 0 {
		return "", "", &InvalidIDError{Reason: "id has empty type prefix: " + id}
	}
	if !isHexLower(hex) {
		return "", "", &InvalidIDError{Reason: "id payload is not 32 lowercase hex characters: " + id}
	}
	if !isVersionNibbleValid(hex[12]) {
		return "", "", &InvalidIDError{Reason: "id payload is not a valid UUID: " + id}
	}
	return typ, hex, nil
}

func reconstructCanonical(hex string) string {
	// Insert hyphens at positions 8, 12, 16, 20.
	var b strings.Builder
	b.Grow(36)
	b.WriteString(hex[0:8])
	b.WriteByte('-')
	b.WriteString(hex[8:12])
	b.WriteByte('-')
	b.WriteString(hex[12:16])
	b.WriteByte('-')
	b.WriteString(hex[16:20])
	b.WriteByte('-')
	b.WriteString(hex[20:32])
	return b.String()
}

// Decode parses a Flametrench wire-format ID into its type prefix and
// canonical UUID. Returns [InvalidTypeError] when the prefix is outside
// [Types]; for application-defined prefixes use [DecodeAny].
func Decode(id string) (DecodedID, error) {
	typ, hex, err := decodeShape(id)
	if err != nil {
		return DecodedID{}, err
	}
	if err := assertType(typ); err != nil {
		return DecodedID{}, err
	}
	return DecodedID{Type: typ, UUID: reconstructCanonical(hex)}, nil
}

// DecodeAny parses a wire-format ID without checking the registered-type
// set. Use this for backend storage adapters that need to convert
// wire-format object IDs to canonical UUIDs without knowing the
// application's domain types in advance.
//
// Validates structural shape only (separator, 32 lowercase hex chars,
// version nibble 1–8). Never returns [InvalidTypeError].
func DecodeAny(id string) (DecodedID, error) {
	typ, hex, err := decodeShape(id)
	if err != nil {
		return DecodedID{}, err
	}
	return DecodedID{Type: typ, UUID: reconstructCanonical(hex)}, nil
}

// IsValid reports whether s is a valid wire-format ID. If expectedType
// is non-empty, additionally asserts the decoded type matches.
func IsValid(s string, expectedType ...string) bool {
	decoded, err := Decode(s)
	if err != nil {
		return false
	}
	for _, want := range expectedType {
		if want != "" && decoded.Type != want {
			return false
		}
	}
	return true
}

// IsValidShape is the predicate counterpart to [DecodeAny]. Returns
// true for any well-formed wire-format ID regardless of registry
// membership.
func IsValidShape(s string) bool {
	_, err := DecodeAny(s)
	return err == nil
}

// TypeOf returns the type prefix of a registered wire-format ID.
func TypeOf(id string) (string, error) {
	d, err := Decode(id)
	if err != nil {
		return "", err
	}
	return d.Type, nil
}

// Generate returns a fresh wire-format ID of the given type. Uses
// UUIDv7 so generated IDs are sortable by creation time.
func Generate(typ string) (string, error) {
	if err := assertType(typ); err != nil {
		return "", err
	}
	u, err := uuid.NewV7()
	if err != nil {
		return "", &InvalidIDError{Reason: "uuid v7 generation failed: " + err.Error()}
	}
	return Encode(typ, u.String())
}

// MustGenerate is like [Generate] but panics on error. Useful in
// initialization code where a panic is more correct than error
// propagation (the only errors are unregistered-type and UUID-generator
// failure, both of which indicate misconfiguration).
func MustGenerate(typ string) string {
	id, err := Generate(typ)
	if err != nil {
		panic(err)
	}
	return id
}
