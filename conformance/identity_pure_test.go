// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

// Pure-function conformance runners for identity fixtures that don't
// require a store. Argon2id verification, PAT structural validation,
// PAT bearer-prefix routing, TOTP RFC 6238 vectors, recovery-code
// format validation.
//
// Stateful fixtures (list-users, user-display-name, mfa enrollment,
// invitation acceptance, etc.) land in the follow-up commit alongside
// the Postgres adapters so the byte-equality assertion runs against
// both in-memory and Postgres backends.

package conformance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/flametrench/flametrench-go/packages/identity"
)

func loadJSONFixture(t *testing.T, path string) Fixture {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var f Fixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return f
}

// TestArgon2idCrossSDKInterop is THE Argon2id parity test — the PHC hash
// shipped in the spec fixture was generated with argon2-cffi at the
// spec floor; this Go SDK's VerifyPasswordHash MUST accept it for the
// matching plaintext and reject it for any other.
func TestArgon2idCrossSDKInterop(t *testing.T) {
	path := filepath.Join("fixtures", "identity", "argon2id.json")
	f := loadJSONFixture(t, path)
	for _, c := range f.Tests {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			phc, _ := c.Input["phc_hash"].(string)
			pw, _ := c.Input["candidate_password"].(string)
			want, _ := c.Expected["result"].(bool)
			got, err := identity.VerifyPasswordHash(phc, pw)
			if err != nil {
				t.Fatalf("VerifyPasswordHash: %v", err)
			}
			if got != want {
				t.Errorf("result = %v; want %v", got, want)
			}
		})
	}
}

func TestPatTokenFormatConformance(t *testing.T) {
	path := filepath.Join("fixtures", "identity", "pat", "token-format.json")
	f := loadJSONFixture(t, path)
	for _, c := range f.Tests {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			token, _ := c.Input["token"].(string)
			want, _ := c.Expected["result"].(bool)
			got := identity.IsStructurallyValidPatToken(token)
			if got != want {
				t.Errorf("IsStructurallyValidPatToken(%q) = %v; want %v", token, got, want)
			}
		})
	}
}

func TestPatBearerPrefixRoutingConformance(t *testing.T) {
	path := filepath.Join("fixtures", "identity", "pat", "bearer-prefix-routing.json")
	f := loadJSONFixture(t, path)
	for _, c := range f.Tests {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			token, _ := c.Input["token"].(string)
			want, _ := c.Expected["result"].(string)
			got := string(identity.ClassifyBearer(token))
			if got != want {
				t.Errorf("ClassifyBearer(%q) = %q; want %q", token, got, want)
			}
		})
	}
}

func TestTotpRFC6238Conformance(t *testing.T) {
	path := filepath.Join("fixtures", "identity", "mfa", "totp-rfc6238.json")
	f := loadJSONFixture(t, path)
	for _, c := range f.Tests {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			secretASCII, _ := c.Input["secret_ascii"].(string)
			tsFloat, _ := c.Input["timestamp"].(float64)
			digitsFloat, _ := c.Input["digits"].(float64)
			alg, _ := c.Input["algorithm"].(string)
			want, _ := c.Expected["result"].(string)
			code, err := identity.TotpCompute(
				[]byte(secretASCII),
				int64(tsFloat),
				identity.TotpComputeOptions{Digits: int(digitsFloat), Algorithm: alg},
			)
			if err != nil {
				t.Fatalf("TotpCompute: %v", err)
			}
			if code != want {
				t.Errorf("code = %q; want %q", code, want)
			}
		})
	}
}

func TestRecoveryCodeFormatConformance(t *testing.T) {
	path := filepath.Join("fixtures", "identity", "mfa", "recovery-code-format.json")
	f := loadJSONFixture(t, path)
	for _, c := range f.Tests {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			code, _ := c.Input["code"].(string)
			want, _ := c.Expected["result"].(bool)
			got := identity.IsValidRecoveryCode(code)
			if got != want {
				t.Errorf("IsValidRecoveryCode(%q) = %v; want %v", code, got, want)
			}
		})
	}
}

// suppress unused import if file is moved
var _ = strings.Contains
