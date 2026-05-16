// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
package identity

import (
	"strings"
	"testing"
	"time"
)

func TestInMemUserLifecycle(t *testing.T) {
	s := NewInMemoryIdentityStore()
	dn := "Alice Founder"
	u, err := s.CreateUser(&dn)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.Status != StatusActive {
		t.Errorf("Status = %q; want active", u.Status)
	}
	if u.DisplayName == nil || *u.DisplayName != dn {
		t.Errorf("DisplayName not preserved")
	}

	got, err := s.GetUser(u.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got.ID != u.ID {
		t.Errorf("round-trip user id mismatch")
	}

	// Suspend → reinstate → revoke.
	if _, err := s.SuspendUser(u.ID); err != nil {
		t.Fatalf("SuspendUser: %v", err)
	}
	if _, err := s.ReinstateUser(u.ID); err != nil {
		t.Fatalf("ReinstateUser: %v", err)
	}
	if _, err := s.RevokeUser(u.ID); err != nil {
		t.Fatalf("RevokeUser: %v", err)
	}
	// Re-revoke: already-terminal.
	if _, err := s.RevokeUser(u.ID); err == nil {
		t.Error("revoking already-revoked user should error")
	}
}

func TestInMemPasswordCredentialAndSession(t *testing.T) {
	s := NewInMemoryIdentityStore()
	u, _ := s.CreateUser(nil)
	c, err := s.CreatePasswordCredential(u.ID, "alice@example.com", "correcthorsebatterystaple")
	if err != nil {
		t.Fatalf("CreatePasswordCredential: %v", err)
	}
	if c.Type != CredentialTypePassword {
		t.Errorf("Type mismatch")
	}

	// Duplicate identifier rejects.
	if _, err := s.CreatePasswordCredential(u.ID, "alice@example.com", "x"); err == nil {
		t.Error("duplicate password+identifier should reject")
	}

	// Verify works for correct password.
	vc, err := s.VerifyPassword("alice@example.com", "correcthorsebatterystaple")
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if vc.UsrID != u.ID || vc.CredID != c.ID {
		t.Errorf("VerifyPassword wrong subject")
	}

	// Wrong password rejects.
	if _, err := s.VerifyPassword("alice@example.com", "wrong"); err == nil {
		t.Error("wrong password should reject")
	}

	// Unknown identifier rejects.
	if _, err := s.VerifyPassword("nope@example.com", "anything"); err == nil {
		t.Error("unknown identifier should reject")
	}

	// CreateSession + VerifySessionToken roundtrip.
	swt, err := s.CreateSession(u.ID, c.ID, 3600)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	ses, err := s.VerifySessionToken(swt.Token)
	if err != nil {
		t.Fatalf("VerifySessionToken: %v", err)
	}
	if ses.ID != swt.Session.ID {
		t.Errorf("session id mismatch")
	}

	// Revoke credential cascades to session.
	if _, err := s.RevokeCredential(c.ID); err != nil {
		t.Fatalf("RevokeCredential: %v", err)
	}
	if _, err := s.VerifySessionToken(swt.Token); err == nil {
		t.Error("session token should be invalid after credential revoke")
	}
}

func TestInMemPATLifecycle(t *testing.T) {
	s := NewInMemoryIdentityStore()
	u, _ := s.CreateUser(nil)

	exp := time.Now().UTC().Add(24 * time.Hour)
	res, err := s.CreatePat(CreatePatInput{
		UsrID: u.ID, Name: "ci-deploys", Scope: []string{"deploy:read"},
		ExpiresAt: &exp,
	})
	if err != nil {
		t.Fatalf("CreatePat: %v", err)
	}
	if !strings.HasPrefix(res.Token, "pat_") {
		t.Errorf("token doesn't start with pat_: %s", res.Token)
	}
	if !IsStructurallyValidPatToken(res.Token) {
		t.Errorf("token fails structural check: %s", res.Token)
	}

	// Verify correct token.
	vp, err := s.VerifyPatToken(res.Token)
	if err != nil {
		t.Fatalf("VerifyPatToken: %v", err)
	}
	if vp.UsrID != u.ID {
		t.Errorf("PAT verify wrong usr")
	}

	// Tampered secret rejects.
	tampered := res.Token[:len(res.Token)-3] + "AAA"
	if _, err := s.VerifyPatToken(tampered); err == nil {
		t.Error("tampered PAT should reject")
	}

	// Malformed token rejects.
	if _, err := s.VerifyPatToken("not-a-pat"); err == nil {
		t.Error("malformed PAT should reject")
	}

	// Revoke.
	if _, err := s.RevokePat(res.Pat.ID); err != nil {
		t.Fatalf("RevokePat: %v", err)
	}
	if _, err := s.VerifyPatToken(res.Token); err == nil {
		t.Error("revoked PAT should reject verify")
	}
}

func TestInMemTotpEnrollAndVerify(t *testing.T) {
	s := NewInMemoryIdentityStore()
	u, _ := s.CreateUser(nil)
	res, err := s.EnrollTotpFactor(u.ID, "alice@example.com", TotpComputeOptions{})
	if err != nil {
		t.Fatalf("EnrollTotpFactor: %v", err)
	}
	if res.Factor.Status != FactorStatusPending {
		t.Errorf("freshly enrolled TOTP factor should be Pending")
	}

	// Compute the expected code, confirm, then verify.
	secret := s.totpSecrets[res.Factor.ID]
	code, err := TotpCompute(secret, time.Now().UTC().Unix(), TotpComputeOptions{})
	if err != nil {
		t.Fatalf("TotpCompute: %v", err)
	}
	confirmed, err := s.ConfirmTotpFactor(res.Factor.ID, code)
	if err != nil {
		t.Fatalf("ConfirmTotpFactor: %v", err)
	}
	if confirmed.Status != FactorStatusActive {
		t.Errorf("confirmed factor status = %q; want active", confirmed.Status)
	}

	// VerifyMfa with same code window succeeds.
	result, err := s.VerifyMfa(u.ID, MfaProof{Totp: &TotpProof{Code: code}})
	if err != nil {
		t.Fatalf("VerifyMfa: %v", err)
	}
	if result.Type != FactorTypeTotp {
		t.Errorf("wrong factor type")
	}
}

func TestInMemRecoveryCodes(t *testing.T) {
	s := NewInMemoryIdentityStore()
	u, _ := s.CreateUser(nil)
	res, err := s.EnrollRecoveryFactor(u.ID)
	if err != nil {
		t.Fatalf("EnrollRecoveryFactor: %v", err)
	}
	if len(res.Codes) != RecoveryCodeCount {
		t.Errorf("got %d codes; want %d", len(res.Codes), RecoveryCodeCount)
	}
	for _, c := range res.Codes {
		if !IsValidRecoveryCode(c) {
			t.Errorf("invalid recovery code: %q", c)
		}
	}

	// Use first code; second use of same code should fail.
	first := res.Codes[0]
	if _, err := s.VerifyMfa(u.ID, MfaProof{Recovery: &RecoveryProof{Code: first}}); err != nil {
		t.Errorf("first use of recovery code failed: %v", err)
	}
	if _, err := s.VerifyMfa(u.ID, MfaProof{Recovery: &RecoveryProof{Code: first}}); err == nil {
		t.Error("second use of same recovery code should fail")
	}
}
