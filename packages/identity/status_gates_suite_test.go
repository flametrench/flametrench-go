// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

// Shared-suite tests for TOTP replay protection, user-status gates, the
// revokeUser → PAT cascade and recovery re-enrollment. Every refusal
// also asserts that the refused call changed nothing.

package identity

import (
	"encoding/base32"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func testStatusGates(t *testing.T, newStore storeFactory) {
	t.Run("TotpReplay", func(t *testing.T) { testTotpReplay(t, newStore) })
	t.Run("UserStatusGates", func(t *testing.T) { testUserStatusGates(t, newStore) })
	t.Run("RevokeUserCascadesToPats", func(t *testing.T) { testRevokeUserCascadesToPats(t, newStore) })
	t.Run("RecoveryReEnroll", func(t *testing.T) { testRecoveryReEnroll(t, newStore) })
}

func wantPrecondition(t *testing.T, err error, reason string) {
	t.Helper()
	var pe *PreconditionError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v; want PreconditionError(%s)", err, reason)
	}
	if pe.Reason != reason {
		t.Errorf("Reason = %q; want %q", pe.Reason, reason)
	}
}

// confirmedTotp enrolls + confirms a TOTP factor and returns the raw
// secret. The confirm consumes the current step.
func confirmedTotp(t *testing.T, s IdentityStore, usrID string) []byte {
	t.Helper()
	res, err := s.EnrollTotpFactor(usrID, "alice", TotpComputeOptions{})
	if err != nil {
		t.Fatalf("EnrollTotpFactor: %v", err)
	}
	secret, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(res.SecretB32))
	code, _ := TotpCompute(secret, time.Now().UTC().Unix(), TotpComputeOptions{})
	if _, err := s.ConfirmTotpFactor(res.Factor.ID, code); err != nil {
		t.Fatalf("ConfirmTotpFactor: %v", err)
	}
	return secret
}

func testTotpReplay(t *testing.T, newStore storeFactory) {
	t.Run("same_code_twice_rejected_and_refusal_does_not_advance", func(t *testing.T) {
		s, done := newStore(t)
		defer done()
		u := mustUser(t, s, "")
		secret := confirmedTotp(t, s, u.ID)
		now := time.Now().UTC().Unix()
		next, _ := TotpCompute(secret, now+int64(DefaultTotpPeriod), TotpComputeOptions{})
		if _, err := s.VerifyMfa(u.ID, MfaProof{Totp: &TotpProof{Code: next}}); err != nil {
			t.Fatalf("first VerifyMfa: %v", err)
		}
		_, err := s.VerifyMfa(u.ID, MfaProof{Totp: &TotpProof{Code: next}})
		if !errors.Is(err, ErrReplayedTotp) {
			t.Fatalf("replay: err = %v; want ErrReplayedTotp", err)
		}
		// ADR 0027 §5-6: a replay is also an invalid credential, with a pinned code.
		if !errors.Is(err, ErrInvalidCredential) {
			t.Errorf("replay: errors.Is(err, ErrInvalidCredential) = false; want true")
		}
		if got := ErrorCode(err); got != "unauthorized.totp_replayed" {
			t.Errorf("replay: ErrorCode = %q; want %q", got, "unauthorized.totp_replayed")
		}
		// Older, never-used code inside the window: rejected (strict step replay).
		cur, _ := TotpCompute(secret, now, TotpComputeOptions{})
		if cur != next {
			if _, err := s.VerifyMfa(u.ID, MfaProof{Totp: &TotpProof{Code: cur}}); !errors.Is(err, ErrReplayedTotp) {
				t.Errorf("older step: err = %v; want ErrReplayedTotp", err)
			}
		}
	})

	t.Run("concurrent_verifies_of_one_code_exactly_one_succeeds", func(t *testing.T) {
		s, done := newStore(t)
		defer done()
		u := mustUser(t, s, "")
		secret := confirmedTotp(t, s, u.ID)
		next, _ := TotpCompute(secret, time.Now().UTC().Unix()+int64(DefaultTotpPeriod), TotpComputeOptions{})
		const n = 8
		var wg sync.WaitGroup
		errs := make([]error, n)
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				_, errs[i] = s.VerifyMfa(u.ID, MfaProof{Totp: &TotpProof{Code: next}})
			}(i)
		}
		close(start)
		wg.Wait()
		ok, replayed := 0, 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, ErrReplayedTotp):
				replayed++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}
		if ok != 1 || replayed != n-1 {
			t.Errorf("successes = %d, replays = %d; want 1 and %d", ok, replayed, n-1)
		}
	})
}

func testUserStatusGates(t *testing.T, newStore storeFactory) {
	t.Run("verify_password_suspended_refused_then_reinstated_ok", func(t *testing.T) {
		s, done := newStore(t)
		defer done()
		u := mustUser(t, s, "")
		mustCred(t, s, u.ID, "sus@example.com", "long-enough-password-for-floor")
		if _, err := s.SuspendUser(u.ID); err != nil {
			t.Fatalf("SuspendUser: %v", err)
		}
		if _, err := s.VerifyPassword("sus@example.com", "long-enough-password-for-floor"); !errors.Is(err, ErrInvalidCredential) {
			t.Fatalf("suspended: err = %v; want ErrInvalidCredential", err)
		}
		if _, err := s.ReinstateUser(u.ID); err != nil {
			t.Fatalf("ReinstateUser: %v", err)
		}
		if _, err := s.VerifyPassword("sus@example.com", "long-enough-password-for-floor"); err != nil {
			t.Errorf("reinstated: %v", err)
		}
	})

	t.Run("create_session_non_active_refused_creates_nothing", func(t *testing.T) {
		for _, to := range []Status{StatusSuspended, StatusRevoked} {
			t.Run(string(to), func(t *testing.T) {
				s, done := newStore(t)
				defer done()
				u := mustUser(t, s, "")
				c := mustCred(t, s, u.ID, "s@example.com", "long-enough-password-for-floor")
				var err error
				if to == StatusSuspended {
					_, err = s.SuspendUser(u.ID)
				} else {
					_, err = s.RevokeUser(u.ID)
				}
				if err != nil {
					t.Fatalf("transition: %v", err)
				}
				_, err = s.CreateSession(u.ID, c.ID, 3600)
				wantPrecondition(t, err, "user_not_active")
				page, err := s.ListSessionsForUser(u.ID, ListSessionsOptions{})
				if err != nil {
					t.Fatalf("ListSessionsForUser: %v", err)
				}
				if len(page.Data) != 0 {
					t.Errorf("refused CreateSession left %d sessions", len(page.Data))
				}
			})
		}
	})

	t.Run("verify_pat_suspended_owner_refused_then_reinstated_same_token_ok", func(t *testing.T) {
		s, done := newStore(t)
		defer done()
		u := mustUser(t, s, "")
		r, err := s.CreatePat(CreatePatInput{UsrID: u.ID, Name: "ci"})
		if err != nil {
			t.Fatalf("CreatePat: %v", err)
		}
		if _, err := s.SuspendUser(u.ID); err != nil {
			t.Fatalf("SuspendUser: %v", err)
		}
		if _, err := s.VerifyPatToken(r.Token); !errors.Is(err, ErrInvalidPatToken) {
			t.Fatalf("suspended owner: err = %v; want ErrInvalidPatToken", err)
		}
		p, err := s.GetPat(r.Pat.ID)
		if err != nil {
			t.Fatalf("GetPat: %v", err)
		}
		if p.LastUsedAt != nil || p.Status != PatStatusActive {
			t.Errorf("refused verify changed the PAT: last_used_at=%v status=%q", p.LastUsedAt, p.Status)
		}
		if _, err := s.ReinstateUser(u.ID); err != nil {
			t.Fatalf("ReinstateUser: %v", err)
		}
		if _, err := s.VerifyPatToken(r.Token); err != nil {
			t.Errorf("reinstated owner: %v", err)
		}
	})

	t.Run("create_pat_non_active_user_refused_creates_nothing", func(t *testing.T) {
		// The reason is pinned to user_not_active for both statuses, in every SDK.
		for _, to := range []Status{StatusSuspended, StatusRevoked} {
			t.Run(string(to), func(t *testing.T) {
				s, done := newStore(t)
				defer done()
				u := mustUser(t, s, "")
				var err error
				if to == StatusSuspended {
					_, err = s.SuspendUser(u.ID)
				} else {
					_, err = s.RevokeUser(u.ID)
				}
				if err != nil {
					t.Fatalf("transition: %v", err)
				}
				_, err = s.CreatePat(CreatePatInput{UsrID: u.ID, Name: "ci"})
				wantPrecondition(t, err, "user_not_active")
				page, err := s.ListPatsForUser(u.ID, ListPatsOptions{})
				if err != nil {
					t.Fatalf("ListPatsForUser: %v", err)
				}
				if len(page.Data) != 0 {
					t.Errorf("refused CreatePat left %d PATs", len(page.Data))
				}
			})
		}
	})

	t.Run("sessions_of_non_active_user_refused", func(t *testing.T) {
		for _, to := range []Status{StatusSuspended, StatusRevoked} {
			t.Run(string(to), func(t *testing.T) {
				s, done := newStore(t)
				defer done()
				u := mustUser(t, s, "")
				c := mustCred(t, s, u.ID, "s@example.com", "long-enough-password-for-floor")
				ses, err := s.CreateSession(u.ID, c.ID, 3600)
				if err != nil {
					t.Fatalf("CreateSession: %v", err)
				}
				if to == StatusSuspended {
					_, err = s.SuspendUser(u.ID)
				} else {
					_, err = s.RevokeUser(u.ID)
				}
				if err != nil {
					t.Fatalf("transition: %v", err)
				}
				if _, err := s.VerifySessionToken(ses.Token); err != ErrInvalidToken {
					t.Errorf("VerifySessionToken: err = %v; want ErrInvalidToken", err)
				}
				before, err := s.ListSessionsForUser(u.ID, ListSessionsOptions{})
				if err != nil {
					t.Fatalf("ListSessionsForUser: %v", err)
				}
				_, err = s.RefreshSession(ses.Session.ID)
				wantPrecondition(t, err, "user_not_active")
				after, err := s.ListSessionsForUser(u.ID, ListSessionsOptions{})
				if err != nil {
					t.Fatalf("ListSessionsForUser: %v", err)
				}
				if len(after.Data) != len(before.Data) {
					t.Errorf("refused RefreshSession changed session count %d -> %d", len(before.Data), len(after.Data))
				}
			})
		}
	})

	t.Run("verify_mfa_suspended_refused_consumes_nothing", func(t *testing.T) {
		t.Run("totp", func(t *testing.T) {
			s, done := newStore(t)
			defer done()
			u := mustUser(t, s, "")
			secret := confirmedTotp(t, s, u.ID)
			next, _ := TotpCompute(secret, time.Now().UTC().Unix()+int64(DefaultTotpPeriod), TotpComputeOptions{})
			if _, err := s.SuspendUser(u.ID); err != nil {
				t.Fatalf("SuspendUser: %v", err)
			}
			_, err := s.VerifyMfa(u.ID, MfaProof{Totp: &TotpProof{Code: next}})
			if err != ErrInvalidCredential {
				t.Fatalf("suspended: err = %v; want ErrInvalidCredential", err)
			}
			if _, err := s.ReinstateUser(u.ID); err != nil {
				t.Fatalf("ReinstateUser: %v", err)
			}
			// The refused verify did not advance the step, so the same code works now.
			if _, err := s.VerifyMfa(u.ID, MfaProof{Totp: &TotpProof{Code: next}}); err != nil {
				t.Errorf("reinstated, same code: %v", err)
			}
		})
		t.Run("recovery", func(t *testing.T) {
			s, done := newStore(t)
			defer done()
			u := mustUser(t, s, "")
			rec, err := s.EnrollRecoveryFactor(u.ID)
			if err != nil {
				t.Fatalf("EnrollRecoveryFactor: %v", err)
			}
			if _, err := s.SuspendUser(u.ID); err != nil {
				t.Fatalf("SuspendUser: %v", err)
			}
			_, err = s.VerifyMfa(u.ID, MfaProof{Recovery: &RecoveryProof{Code: rec.Codes[0]}})
			if err != ErrInvalidCredential {
				t.Fatalf("suspended: err = %v; want ErrInvalidCredential", err)
			}
			if _, err := s.ReinstateUser(u.ID); err != nil {
				t.Fatalf("ReinstateUser: %v", err)
			}
			// The refused verify did not consume the slot, so the same code works now.
			if _, err := s.VerifyMfa(u.ID, MfaProof{Recovery: &RecoveryProof{Code: rec.Codes[0]}}); err != nil {
				t.Errorf("reinstated, same code: %v", err)
			}
		})
	})
}

func testRevokeUserCascadesToPats(t *testing.T, newStore storeFactory) {
	s, done := newStore(t)
	defer done()
	u := mustUser(t, s, "")
	other := mustUser(t, s, "")
	r1, _ := s.CreatePat(CreatePatInput{UsrID: u.ID, Name: "a"})
	r2, _ := s.CreatePat(CreatePatInput{UsrID: u.ID, Name: "b"})
	ro, _ := s.CreatePat(CreatePatInput{UsrID: other.ID, Name: "other"})
	if _, err := s.RevokeUser(u.ID); err != nil {
		t.Fatalf("RevokeUser: %v", err)
	}
	for _, r := range []CreatePatResult{r1, r2} {
		var re *PatRevokedError
		if _, err := s.VerifyPatToken(r.Token); !errors.As(err, &re) {
			t.Errorf("%s: err = %v; want PatRevokedError", r.Pat.ID, err)
		}
		p, _ := s.GetPat(r.Pat.ID)
		if p.Status != PatStatusRevoked || p.RevokedAt == nil {
			t.Errorf("%s: status = %q revoked_at = %v; want revoked", r.Pat.ID, p.Status, p.RevokedAt)
		}
	}
	if _, err := s.VerifyPatToken(ro.Token); err != nil {
		t.Errorf("another user's PAT must be untouched: %v", err)
	}
}

func testRecoveryReEnroll(t *testing.T, newStore storeFactory) {
	activeRecovery := func(t *testing.T, s IdentityStore, usrID string) []Factor {
		t.Helper()
		fs, err := s.ListFactorsForUser(usrID)
		if err != nil {
			t.Fatalf("ListFactorsForUser: %v", err)
		}
		var out []Factor
		for _, f := range fs {
			if f.Type == FactorTypeRecovery && f.Status == FactorStatusActive {
				out = append(out, f)
			}
		}
		return out
	}

	t.Run("unexhausted_re_enroll_refused_changes_nothing", func(t *testing.T) {
		s, done := newStore(t)
		defer done()
		u := mustUser(t, s, "")
		first, err := s.EnrollRecoveryFactor(u.ID)
		if err != nil {
			t.Fatalf("EnrollRecoveryFactor: %v", err)
		}
		_, err = s.EnrollRecoveryFactor(u.ID)
		wantPrecondition(t, err, "active_singleton_exists")
		act := activeRecovery(t, s, u.ID)
		if len(act) != 1 || act[0].ID != first.Factor.ID || act[0].Remaining != len(first.Codes) {
			t.Fatalf("after refused re-enroll: active = %+v; want only %s with %d remaining", act, first.Factor.ID, len(first.Codes))
		}
		if _, err := s.VerifyMfa(u.ID, MfaProof{Recovery: &RecoveryProof{Code: first.Codes[0]}}); err != nil {
			t.Errorf("original set must still verify: %v", err)
		}
	})

	t.Run("exhausted_re_enroll_replaces_set", func(t *testing.T) {
		s, done := newStore(t)
		defer done()
		u := mustUser(t, s, "")
		first, err := s.EnrollRecoveryFactor(u.ID)
		if err != nil {
			t.Fatalf("EnrollRecoveryFactor: %v", err)
		}
		for _, c := range first.Codes {
			if _, err := s.VerifyMfa(u.ID, MfaProof{Recovery: &RecoveryProof{Code: c}}); err != nil {
				t.Fatalf("consume code: %v", err)
			}
		}
		second, err := s.EnrollRecoveryFactor(u.ID)
		if err != nil {
			t.Fatalf("re-enroll after exhaustion: %v", err)
		}
		if second.Factor.Replaces == nil || *second.Factor.Replaces != first.Factor.ID {
			t.Errorf("Replaces = %v; want %s", second.Factor.Replaces, first.Factor.ID)
		}
		act := activeRecovery(t, s, u.ID)
		if len(act) != 1 || act[0].ID != second.Factor.ID {
			t.Fatalf("active recovery factors = %+v; want only %s", act, second.Factor.ID)
		}
		old, _ := s.GetFactor(first.Factor.ID)
		if old.Status != FactorStatusRevoked {
			t.Errorf("old factor status = %q; want revoked", old.Status)
		}
		got, _ := s.GetFactor(second.Factor.ID)
		if got.Replaces == nil || *got.Replaces != first.Factor.ID {
			t.Errorf("GetFactor Replaces = %v; want %s", got.Replaces, first.Factor.ID)
		}
		if _, err := s.VerifyMfa(u.ID, MfaProof{Recovery: &RecoveryProof{Code: second.Codes[0]}}); err != nil {
			t.Errorf("new set must verify: %v", err)
		}
	})
}
