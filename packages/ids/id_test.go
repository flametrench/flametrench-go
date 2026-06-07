// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
package ids

import (
	"strings"
	"testing"
)

// Cases from spec/docs/ids.md §"Conformance fixtures" (Valid encoding table).
var validEncodingCases = []struct {
	Type, UUID, Wire string
}{
	{"usr", "0190f2a8-1b3c-7abc-8123-456789abcdef", "usr_0190f2a81b3c7abc8123456789abcdef"},
	{"org", "01000000-0000-7000-8000-000000000000", "org_01000000000070008000000000000000"},
	{"ses", "01ffffff-ffff-7fff-bfff-ffffffffffff", "ses_01ffffffffff7fffbfffffffffffffff"},
}

func TestEncode(t *testing.T) {
	for _, tc := range validEncodingCases {
		got, err := Encode(tc.Type, tc.UUID)
		if err != nil {
			t.Errorf("Encode(%q,%q) errored: %v", tc.Type, tc.UUID, err)
			continue
		}
		if got != tc.Wire {
			t.Errorf("Encode(%q,%q) = %q; want %q", tc.Type, tc.UUID, got, tc.Wire)
		}
	}
}

func TestDecode(t *testing.T) {
	for _, tc := range validEncodingCases {
		got, err := Decode(tc.Wire)
		if err != nil {
			t.Errorf("Decode(%q) errored: %v", tc.Wire, err)
			continue
		}
		if got.Type != tc.Type || got.UUID != tc.UUID {
			t.Errorf("Decode(%q) = (%q, %q); want (%q, %q)",
				tc.Wire, got.Type, got.UUID, tc.Type, tc.UUID)
		}
	}
}

func TestEncodeRoundtrip(t *testing.T) {
	for _, tc := range validEncodingCases {
		wire, err := Encode(tc.Type, tc.UUID)
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		decoded, err := Decode(wire)
		if err != nil {
			t.Fatalf("Decode: %v", err)
		}
		if decoded.Type != tc.Type || decoded.UUID != tc.UUID {
			t.Errorf("roundtrip(%q,%q) = (%q,%q); want (%q,%q)",
				tc.Type, tc.UUID, decoded.Type, decoded.UUID, tc.Type, tc.UUID)
		}
	}
}

// Cases from spec/docs/ids.md §"Conformance fixtures" (Reject table).
var rejectCases = []struct {
	Name   string
	Input  string
	Reason string // for diagnostic only; the test asserts on error type
}{
	{"missing-separator", "usr0190f2a81b3c7abc8123456789abcdef", "no underscore"},
	{"unregistered-prefix", "xyz_0190f2a81b3c7abc8123456789abcdef", "xyz not in registry"},
	{"payload-too-short", "usr_0190f2a8", "payload < 32 chars"},
	{"payload-too-long", "usr_0190f2a81b3c7abc8123456789abcdef0000", "payload > 32 chars"},
	{"uppercase-hex", "usr_0190F2A81B3C7ABC8123456789ABCDEF", "uppercase not allowed"},
	{"non-hex-character", "usr_0190f2a81b3c7abc8123456789abcdeg0", "g is not hex"},
	{"empty-payload", "usr_", "payload empty"},
	{"empty-input", "", "input empty"},
	{"nil-uuid", "usr_00000000000000000000000000000000", "version nibble = 0"},
	{"max-uuid", "usr_ffffffffffffffffffffffffffffffff", "version nibble = f"},
}

func TestDecodeRejects(t *testing.T) {
	for _, tc := range rejectCases {
		t.Run(tc.Name, func(t *testing.T) {
			_, err := Decode(tc.Input)
			if err == nil {
				t.Fatalf("Decode(%q) succeeded; want error (%s)", tc.Input, tc.Reason)
			}
		})
	}
}

func TestIsValid(t *testing.T) {
	for _, tc := range validEncodingCases {
		if !IsValid(tc.Wire) {
			t.Errorf("IsValid(%q) = false; want true", tc.Wire)
		}
		if !IsValid(tc.Wire, tc.Type) {
			t.Errorf("IsValid(%q, %q) = false; want true", tc.Wire, tc.Type)
		}
		// Type assertion rejects non-matching type.
		if IsValid(tc.Wire, "xyz") {
			t.Errorf("IsValid(%q, %q) = true; want false (wrong type)", tc.Wire, "xyz")
		}
	}
	for _, tc := range rejectCases {
		if IsValid(tc.Input) {
			t.Errorf("IsValid(%q) = true; want false (%s)", tc.Input, tc.Reason)
		}
	}
}

func TestTypeOf(t *testing.T) {
	for _, tc := range validEncodingCases {
		typ, err := TypeOf(tc.Wire)
		if err != nil {
			t.Fatalf("TypeOf(%q): %v", tc.Wire, err)
		}
		if typ != tc.Type {
			t.Errorf("TypeOf(%q) = %q; want %q", tc.Wire, typ, tc.Type)
		}
	}
}

func TestGenerate(t *testing.T) {
	for _, typ := range []string{"usr", "org", "ses", "cred", "tup", "mfa", "shr", "pat"} {
		id, err := Generate(typ)
		if err != nil {
			t.Errorf("Generate(%q): %v", typ, err)
			continue
		}
		if !IsValid(id, typ) {
			t.Errorf("Generate(%q) produced invalid id: %q", typ, id)
		}
		// Generated IDs must have version nibble 7 (UUIDv7).
		// Position 12 of the hex payload is at offset len(typ)+1+12.
		sep := strings.IndexByte(id, '_')
		hex := id[sep+1:]
		if hex[12] != '7' {
			t.Errorf("Generate(%q) version nibble is %c; want '7' (UUIDv7)", typ, hex[12])
		}
	}
}

func TestGenerateUnknownType(t *testing.T) {
	_, err := Generate("xyz")
	if err == nil {
		t.Fatal("Generate(\"xyz\") succeeded; want InvalidTypeError")
	}
	if !IsInvalidType(err) {
		t.Errorf("Generate(\"xyz\") err type = %T; want *InvalidTypeError", err)
	}
}

// DecodeAny + IsValidShape: structural-only checks; no registry consultation.
func TestDecodeAny(t *testing.T) {
	// App-defined prefix passes shape but would fail Decode.
	app := "proj_0190f2a81b3c7abc8123456789abcdef"
	d, err := DecodeAny(app)
	if err != nil {
		t.Fatalf("DecodeAny(%q): %v", app, err)
	}
	if d.Type != "proj" {
		t.Errorf("DecodeAny(%q).Type = %q; want %q", app, d.Type, "proj")
	}
	if _, err := Decode(app); err == nil {
		t.Errorf("Decode(%q) succeeded for app-defined prefix; want InvalidTypeError", app)
	}

	// Structural failures still rejected.
	if _, err := DecodeAny("proj_short"); err == nil {
		t.Error("DecodeAny(\"proj_short\") succeeded; want InvalidIDError")
	}
}

func TestIsValidShape(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool
	}{
		{"registered-prefix", "usr_0190f2a81b3c7abc8123456789abcdef", true},
		{"app-defined-prefix", "proj_0190f2a81b3c7abc8123456789abcdef", true},
		{"missing-separator", "usrabc", false},
		{"empty-string", "", false},
		{"nil-uuid", "usr_00000000000000000000000000000000", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsValidShape(tc.input); got != tc.want {
				t.Errorf("IsValidShape(%q) = %v; want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestRegisteredPrefixesStable(t *testing.T) {
	// Stable alphabetical order — matters for error messages.
	got := RegisteredPrefixes()
	want := []string{"aud", "cred", "inv", "mem", "mfa", "org", "pat", "ses", "shr", "tup", "usr"}
	if len(got) != len(want) {
		t.Fatalf("RegisteredPrefixes() len = %d; want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("RegisteredPrefixes()[%d] = %q; want %q", i, got[i], want[i])
		}
	}
}
