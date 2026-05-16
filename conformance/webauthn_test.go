// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

// WebAuthn conformance runner — drives the spec's
// fixtures/identity/mfa/webauthn-*.json corpus against the Go SDK's
// WebAuthnVerifyAssertion. The cross-SDK guarantee is that a given
// (COSE pubkey, authenticatorData, clientDataJSON, signature) tuple
// verifies / rejects identically across Python / Node / PHP / Java / Go.

package conformance

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/flametrench/flametrench-go/packages/identity"
)

// WebAuthnSharedInputs is the "shared" block at the top of the
// webauthn fixture files; per-case input overrides only the fields
// that differ (typically just the COSE key + signature).
type webauthnShared struct {
	StoredRpID           string `json:"stored_rp_id"`
	ExpectedOrigin       string `json:"expected_origin"`
	ExpectedChallengeHex string `json:"expected_challenge_hex"`
	StoredSignCount      int64  `json:"stored_sign_count"`
	AuthenticatorDataHex string `json:"authenticator_data_hex"`
	ClientDataJSONHex    string `json:"client_data_json_hex"`
	// The bare webauthn-assertion fixture pins the COSE key + signature in
	// shared and overrides per-case only the failure field (signature, RP
	// ID, challenge bytes, etc.). The algorithms fixture overrides COSE +
	// signature per case. Both shapes must work — make shared the fallback.
	CosePublicKeyHex string `json:"cose_public_key_hex"`
	SignatureHex     string `json:"signature_hex"`
}

type webauthnFixture struct {
	Capability string         `json:"capability"`
	Operation  string         `json:"operation"`
	Shared     webauthnShared `json:"shared"`
	Tests      []FixtureCase  `json:"tests"`
}

func loadWebauthnFixture(t *testing.T, path string) webauthnFixture {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var f webauthnFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return f
}

func hexDecode(t *testing.T, name, s string) []byte {
	t.Helper()
	if s == "" {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %s: %v", name, err)
	}
	return b
}

func runWebauthnFixture(t *testing.T, path string) {
	f := loadWebauthnFixture(t, path)
	if f.Capability != "identity" || f.Operation != "webauthn_verify_assertion" {
		t.Fatalf("%s: unexpected capability/operation %s/%s", path, f.Capability, f.Operation)
	}
	shared := f.Shared
	for _, c := range f.Tests {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			// Per-case can override any shared field; otherwise inherit.
			rpID := shared.StoredRpID
			if v, ok := c.Input["stored_rp_id"].(string); ok {
				rpID = v
			}
			origin := shared.ExpectedOrigin
			if v, ok := c.Input["expected_origin"].(string); ok {
				origin = v
			}
			challengeHex := shared.ExpectedChallengeHex
			if v, ok := c.Input["expected_challenge_hex"].(string); ok {
				challengeHex = v
			}
			storedCount := shared.StoredSignCount
			if v, ok := c.Input["stored_sign_count"].(float64); ok {
				storedCount = int64(v)
			}
			authDataHex := shared.AuthenticatorDataHex
			if v, ok := c.Input["authenticator_data_hex"].(string); ok {
				authDataHex = v
			}
			clientDataHex := shared.ClientDataJSONHex
			if v, ok := c.Input["client_data_json_hex"].(string); ok {
				clientDataHex = v
			}
			cosePubHex := shared.CosePublicKeyHex
			if v, ok := c.Input["cose_public_key_hex"].(string); ok {
				cosePubHex = v
			}
			sigHex := shared.SignatureHex
			if v, ok := c.Input["signature_hex"].(string); ok {
				sigHex = v
			}

			opts := identity.WebAuthnVerifyOptions{
				CosePublicKey:       hexDecode(t, "cose_public_key_hex", cosePubHex),
				StoredSignCount:     storedCount,
				StoredRpID:          rpID,
				ExpectedChallenge:   hexDecode(t, "expected_challenge_hex", challengeHex),
				ExpectedOrigin:      origin,
				AuthenticatorData:   hexDecode(t, "authenticator_data_hex", authDataHex),
				ClientDataJSON:      hexDecode(t, "client_data_json_hex", clientDataHex),
				Signature:           hexDecode(t, "signature_hex", sigHex),
				RequireUserVerified: true,
				RequireUserPresent:  true,
			}
			// require_user_verified / require_user_present overrides.
			if v, ok := c.Input["require_user_verified"].(bool); ok {
				opts.RequireUserVerified = v
			}
			if v, ok := c.Input["require_user_present"].(bool); ok {
				opts.RequireUserPresent = v
			}

			result, err := identity.WebAuthnVerifyAssertion(opts)

			// expected.result is an object {ok: bool, new_sign_count: int} | {ok: false, reason: string}.
			expectedResult, _ := c.Expected["result"].(map[string]any)
			wantOK, _ := expectedResult["ok"].(bool)
			if wantOK {
				if err != nil {
					t.Errorf("%s: WebAuthnVerifyAssertion errored: %v", c.ID, err)
					return
				}
				wantSC, _ := expectedResult["new_sign_count"].(float64)
				if result.NewSignCount != int64(wantSC) {
					t.Errorf("%s: new_sign_count = %d; want %d", c.ID, result.NewSignCount, int64(wantSC))
				}
			} else {
				if err == nil {
					t.Errorf("%s: WebAuthnVerifyAssertion succeeded with %+v; want failure", c.ID, result)
					return
				}
				wantReason, _ := expectedResult["reason"].(string)
				var webErr *identity.WebAuthnError
				if !errors.As(err, &webErr) {
					t.Errorf("%s: error is not *WebAuthnError: %T %v", c.ID, err, err)
					return
				}
				if webErr.Reason != wantReason {
					t.Errorf("%s: reason = %q; want %q (msg: %s)", c.ID, webErr.Reason, wantReason, webErr.Msg)
				}
			}
		})
	}
}

func TestWebAuthnAssertionConformance(t *testing.T) {
	runWebauthnFixture(t, filepath.Join("fixtures", "identity", "mfa", "webauthn-assertion.json"))
}

func TestWebAuthnAssertionAlgorithmsConformance(t *testing.T) {
	runWebauthnFixture(t, filepath.Join("fixtures", "identity", "mfa", "webauthn-assertion-algorithms.json"))
}

func TestWebAuthnCounterDecreaseRejectedConformance(t *testing.T) {
	runWebauthnFixture(t, filepath.Join("fixtures", "identity", "mfa", "webauthn-counter-decrease-rejected.json"))
}
