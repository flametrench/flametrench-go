// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

// Stateful conformance runners for identity fixtures that require a live
// store: list-users (ADR 0015), user-display-name (ADR 0014), TOTP replay
// (ADR 0027), user-status gates (ADR 0029) and, against Postgres, the
// share created_by status gate.

package conformance

import (
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/flametrench/flametrench-go/packages/authz"
	"github.com/flametrench/flametrench-go/packages/identity"

	"github.com/jackc/pgx/v5/pgxpool"
)

// classifyIdentityError maps a Go error to the MOST SPECIFIC fixture error
// class name. A harness passes only on an exact class match (ADR 0027 §7),
// so a subtype is checked before its parent: ReplayedTotpError is also an
// InvalidCredentialError, and must not classify as one.
func classifyIdentityError(err error) string {
	var pre *identity.PreconditionError
	var apre *authz.PreconditionError
	var revoked *identity.PatRevokedError
	var expired *identity.PatExpiredError
	switch {
	case errors.Is(err, identity.ErrNotFound):
		return "NotFoundError"
	case errors.Is(err, identity.ErrAlreadyTerminal):
		return "AlreadyTerminalError"
	case errors.As(err, &pre), errors.As(err, &apre):
		return "PreconditionError"
	case errors.Is(err, identity.ErrReplayedTotp):
		return "ReplayedTotpError"
	case errors.Is(err, identity.ErrInvalidCredential):
		return "InvalidCredentialError"
	case errors.Is(err, identity.ErrInvalidToken):
		return "InvalidTokenError"
	case errors.Is(err, identity.ErrSessionExpired):
		return "SessionExpiredError"
	case errors.Is(err, identity.ErrInvalidPatToken):
		return "InvalidPatTokenError"
	case errors.As(err, &revoked):
		return "PatRevokedError"
	case errors.As(err, &expired):
		return "PatExpiredError"
	}
	return "UnknownError:" + err.Error()
}

// assertIdentityStepError checks that err matches the expected error class.
func assertIdentityStepError(t *testing.T, caseID, op string, expected map[string]any, err error) bool {
	t.Helper()
	wantClass, hasExpectedError := expected["error"].(string)
	if !hasExpectedError {
		if err != nil {
			t.Errorf("%s/%s: unexpected error: %v", caseID, op, err)
			return false
		}
		return true
	}
	if err == nil {
		t.Errorf("%s/%s: expected %s but got no error", caseID, op, wantClass)
		return false
	}
	got := classifyIdentityError(err)
	if got != wantClass {
		t.Errorf("%s/%s: error class = %q, want %q (raw: %v)", caseID, op, got, wantClass, err)
		return false
	}
	return true
}

// runIdentityStepCase runs c against a fresh in-memory store whose clock
// the fixture can pin with set_clock.
func runIdentityStepCase(t *testing.T, c StepCase) {
	t.Helper()
	var pinned *time.Time
	store := identity.NewInMemoryIdentityStore().WithClock(func() time.Time {
		if pinned != nil {
			return *pinned
		}
		return time.Now().UTC()
	})
	runIdentitySteps(t, c, store, nil, &pinned)
}

// runIdentitySteps runs c's steps against store. shares is needed only by
// create_share; pinned is nil when the store's clock can't be pinned.
func runIdentitySteps(t *testing.T, c StepCase, store identity.IdentityStore, shares authz.ShareStore, pinned **time.Time) {
	t.Helper()
	captures := make(map[string]string)
	clockNow := func() time.Time {
		if pinned != nil && *pinned != nil {
			return **pinned
		}
		return time.Now().UTC()
	}

	for stepIdx, rawStep := range c.Steps {
		stepLabel := fmt.Sprintf("step[%d]:%s", stepIdx, rawStep.Op)
		input := resolveInput(rawStep.Input, captures)
		expected := rawStep.Expected
		if expected == nil {
			expected = map[string]any{}
		}

		switch rawStep.Op {

		case "create_user":
			var dn *string
			if v, ok := input["display_name"].(string); ok {
				dn = &v
			}
			user, err := store.CreateUser(dn)
			if !assertIdentityStepError(t, c.ID, stepLabel, expected, err) {
				return
			}
			if err == nil {
				for varName, path := range rawStep.Captures {
					if path == "user.id" {
						captures[varName] = user.ID
					}
				}
			}

		case "create_user_with_password_credential":
			identifier := strField(input, "identifier")
			password := strField(input, "password")
			user, err := store.CreateUser(nil)
			if !assertIdentityStepError(t, c.ID, stepLabel, expected, err) {
				return
			}
			if err != nil {
				continue
			}
			cred, err := store.CreatePasswordCredential(user.ID, identifier, password)
			if !assertIdentityStepError(t, c.ID, stepLabel, expected, err) {
				return
			}
			if err == nil {
				for varName, path := range rawStep.Captures {
					switch path {
					case "user.id":
						captures[varName] = user.ID
					case "credential.id":
						captures[varName] = cred.ID
					}
				}
			}

		case "suspend_user":
			usrID := strField(input, "usr_id")
			_, err := store.SuspendUser(usrID)
			if !assertIdentityStepError(t, c.ID, stepLabel, expected, err) {
				return
			}

		case "revoke_user":
			usrID := strField(input, "usr_id")
			_, err := store.RevokeUser(usrID)
			if !assertIdentityStepError(t, c.ID, stepLabel, expected, err) {
				return
			}

		case "reinstate_user":
			_, err := store.ReinstateUser(strField(input, "usr_id"))
			if !assertIdentityStepError(t, c.ID, stepLabel, expected, err) {
				return
			}

		case "verify_password":
			_, err := store.VerifyPassword(strField(input, "identifier"), strField(input, "password"))
			if !assertIdentityStepError(t, c.ID, stepLabel, expected, err) {
				return
			}

		case "create_session":
			ttl, _ := input["ttl_seconds"].(float64)
			_, err := store.CreateSession(strField(input, "usr_id"), strField(input, "cred_id"), int(ttl))
			if !assertIdentityStepError(t, c.ID, stepLabel, expected, err) {
				return
			}

		case "create_pat":
			res, err := store.CreatePat(identity.CreatePatInput{
				UsrID: strField(input, "usr_id"),
				Name:  strField(input, "name"),
				Scope: toStringSlice(input["scope"]),
			})
			if !assertIdentityStepError(t, c.ID, stepLabel, expected, err) {
				return
			}
			if err == nil {
				for varName, path := range rawStep.Captures {
					if path == "token" {
						captures[varName] = res.Token
					}
				}
			}

		case "verify_pat_token":
			_, err := store.VerifyPatToken(strField(input, "token"))
			if !assertIdentityStepError(t, c.ID, stepLabel, expected, err) {
				return
			}

		case "set_clock":
			if pinned == nil {
				t.Fatalf("%s/%s: this store's clock cannot be pinned", c.ID, stepLabel)
			}
			now, err := time.Parse(time.RFC3339, strField(input, "now"))
			if err != nil {
				t.Fatalf("%s/%s: parse now: %v", c.ID, stepLabel, err)
			}
			*pinned = &now

		case "enroll_totp_factor":
			res, err := store.EnrollTotpFactor(strField(input, "usr_id"), "conformance", identity.TotpComputeOptions{})
			if !assertIdentityStepError(t, c.ID, stepLabel, expected, err) {
				return
			}
			if err == nil {
				for varName, path := range rawStep.Captures {
					switch path {
					case "factor.id":
						captures[varName] = res.Factor.ID
					case "secret":
						captures[varName] = res.SecretB32
					}
				}
			}

		case "compute_totp_code":
			secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strField(input, "secret")))
			if err != nil {
				t.Fatalf("%s/%s: decode secret: %v", c.ID, stepLabel, err)
			}
			code, err := identity.TotpCompute(secret, clockNow().Unix(), identity.TotpComputeOptions{})
			if err != nil {
				t.Fatalf("%s/%s: TotpCompute: %v", c.ID, stepLabel, err)
			}
			for varName, path := range rawStep.Captures {
				if path == "code" {
					captures[varName] = code
				}
			}

		case "confirm_totp_factor":
			_, err := store.ConfirmTotpFactor(strField(input, "mfa_id"), strField(input, "code"))
			if !assertIdentityStepError(t, c.ID, stepLabel, expected, err) {
				return
			}

		case "verify_mfa":
			proof, _ := input["proof"].(map[string]any)
			if strField(proof, "type") != "totp" {
				t.Fatalf("%s/%s: unsupported proof type %q", c.ID, stepLabel, strField(proof, "type"))
			}
			_, err := store.VerifyMfa(strField(input, "usr_id"), identity.MfaProof{Totp: &identity.TotpProof{Code: strField(proof, "code")}})
			if !assertIdentityStepError(t, c.ID, stepLabel, expected, err) {
				return
			}

		case "create_share":
			if shares == nil {
				t.Fatalf("%s/%s: create_share needs a share store", c.ID, stepLabel)
			}
			ttl, _ := input["expires_in_seconds"].(float64)
			_, err := shares.CreateShare(authz.CreateShareInput{
				ObjectType:       strField(input, "object_type"),
				ObjectID:         strField(input, "object_id"),
				Relation:         strField(input, "relation"),
				CreatedBy:        strField(input, "created_by"),
				ExpiresInSeconds: int(ttl),
			})
			if !assertIdentityStepError(t, c.ID, stepLabel, expected, err) {
				return
			}

		case "revoke_credential":
			credID := strField(input, "cred_id")
			_, err := store.RevokeCredential(credID)
			if !assertIdentityStepError(t, c.ID, stepLabel, expected, err) {
				return
			}

		case "update_user":
			usrID := strField(input, "usr_id")
			var in identity.UpdateUserInput
			if val, present := input["display_name"]; present {
				if val == nil {
					in.ClearDisplayName = true
				} else if s, ok := val.(string); ok {
					in.DisplayName = &s
				}
			}
			_, err := store.UpdateUser(usrID, in)
			assertIdentityStepError(t, c.ID, stepLabel, expected, err)

		case "list_users":
			opts := identity.ListUsersOptions{}
			if v, ok := input["limit"].(float64); ok {
				opts.Limit = int(v)
			}
			if v := strPtr(input, "cursor"); v != nil {
				opts.Cursor = v
			}
			if v := strPtr(input, "query"); v != nil {
				opts.Query = v
			}
			if s := strField(input, "status"); s != "" {
				st := identity.Status(s)
				opts.Status = &st
			}

			page, err := store.ListUsers(opts)
			if !assertIdentityStepError(t, c.ID, stepLabel, expected, err) {
				return
			}
			if err != nil {
				continue
			}

			// Captures
			for varName, path := range rawStep.Captures {
				if path == "page.next_cursor" {
					if page.NextCursor != nil {
						captures[varName] = *page.NextCursor
					} else {
						captures[varName] = ""
					}
				}
			}

			// Assertions
			if wantIDs, ok := expected["data_ids_in_order"]; ok {
				rawWant := resolveAny(wantIDs, captures)
				wantSlice := toStringSlice(rawWant)
				gotIDs := make([]string, len(page.Data))
				for i, u := range page.Data {
					gotIDs[i] = u.ID
				}
				if len(gotIDs) != len(wantSlice) {
					t.Errorf("%s/%s: data_ids_in_order len = %d, want %d (got %v, want %v)",
						c.ID, stepLabel, len(gotIDs), len(wantSlice), gotIDs, wantSlice)
				} else {
					for i := range wantSlice {
						if gotIDs[i] != wantSlice[i] {
							t.Errorf("%s/%s: data_ids_in_order[%d] = %q, want %q",
								c.ID, stepLabel, i, gotIDs[i], wantSlice[i])
						}
					}
				}
			}
			if wantIDs, ok := expected["data_ids_unordered"]; ok {
				rawWant := resolveAny(wantIDs, captures)
				wantSlice := toStringSlice(rawWant)
				gotIDs := make([]string, len(page.Data))
				for i, u := range page.Data {
					gotIDs[i] = u.ID
				}
				wantSet := make(map[string]bool, len(wantSlice))
				for _, id := range wantSlice {
					wantSet[id] = true
				}
				gotSet := make(map[string]bool, len(gotIDs))
				for _, id := range gotIDs {
					gotSet[id] = true
				}
				if len(gotSet) != len(wantSet) {
					t.Errorf("%s/%s: data_ids_unordered = %v, want %v", c.ID, stepLabel, gotIDs, wantSlice)
				} else {
					for id := range wantSet {
						if !gotSet[id] {
							t.Errorf("%s/%s: data_ids_unordered missing %q (got %v)", c.ID, stepLabel, id, gotIDs)
						}
					}
				}
			}
			if wantCursorRaw, hasCursor := expected["next_cursor"]; hasCursor {
				if wantCursorRaw == nil {
					if page.NextCursor != nil {
						t.Errorf("%s/%s: next_cursor = %q, want null", c.ID, stepLabel, *page.NextCursor)
					}
				} else {
					wantCursor, _ := wantCursorRaw.(string)
					if page.NextCursor == nil || *page.NextCursor != wantCursor {
						got := "<nil>"
						if page.NextCursor != nil {
							got = *page.NextCursor
						}
						t.Errorf("%s/%s: next_cursor = %q, want %q", c.ID, stepLabel, got, wantCursor)
					}
				}
			}
			if wantDNMap, ok := expected["user_display_names"].(map[string]any); ok {
				resolvedDNMap := resolveAny(wantDNMap, captures).(map[string]any)
				gotByID := make(map[string]*string, len(page.Data))
				for _, u := range page.Data {
					u := u
					gotByID[u.ID] = u.DisplayName
				}
				for userID, wantDN := range resolvedDNMap {
					gotDN, ok := gotByID[userID]
					if !ok {
						t.Errorf("%s/%s: user_display_names: user %q not in page", c.ID, stepLabel, userID)
						continue
					}
					if wantDN == nil {
						if gotDN != nil {
							t.Errorf("%s/%s: user_display_names[%q] = %q, want null", c.ID, stepLabel, userID, *gotDN)
						}
					} else {
						wantStr, _ := wantDN.(string)
						if gotDN == nil {
							t.Errorf("%s/%s: user_display_names[%q] = null, want %q", c.ID, stepLabel, userID, wantStr)
						} else if *gotDN != wantStr {
							t.Errorf("%s/%s: user_display_names[%q] = %q, want %q", c.ID, stepLabel, userID, *gotDN, wantStr)
						}
					}
				}
			}

		case "assert_user_fields":
			usrID := strField(input, "usr_id")
			user, err := store.GetUser(usrID)
			if err != nil {
				t.Errorf("%s/%s: GetUser(%q): %v", c.ID, stepLabel, usrID, err)
				return
			}
			if wantDN, hasDN := input["expected_display_name"]; hasDN {
				if wantDN == nil {
					if user.DisplayName != nil {
						t.Errorf("%s/%s: display_name = %q, want null", c.ID, stepLabel, *user.DisplayName)
					}
				} else {
					wantStr, _ := wantDN.(string)
					if user.DisplayName == nil {
						t.Errorf("%s/%s: display_name = null, want %q", c.ID, stepLabel, wantStr)
					} else if *user.DisplayName != wantStr {
						t.Errorf("%s/%s: display_name = %q, want %q", c.ID, stepLabel, *user.DisplayName, wantStr)
					}
				}
			}

		default:
			t.Fatalf("%s: unknown op %q", c.ID, rawStep.Op)
		}
		_ = sort.Search // keep sort import used
	}
}

func TestListUsersConformance(t *testing.T) {
	path := filepath.Join("fixtures", "identity", "list-users.json")
	f := loadStepFixtureFile(t, path)
	for _, c := range f.Tests {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			runIdentityStepCase(t, c)
		})
	}
}

func TestUserDisplayNameConformance(t *testing.T) {
	path := filepath.Join("fixtures", "identity", "user-display-name.json")
	f := loadStepFixtureFile(t, path)
	for _, c := range f.Tests {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			runIdentityStepCase(t, c)
		})
	}
}

func TestUserStatusGatesConformance(t *testing.T) {
	f := loadStepFixtureFile(t, filepath.Join("fixtures", "identity", "user-status-gates.json"))
	for _, c := range f.Tests {
		c := c
		t.Run(c.ID, func(t *testing.T) { runIdentityStepCase(t, c) })
	}
}

func TestTotpReplayConformance(t *testing.T) {
	f := loadStepFixtureFile(t, filepath.Join("fixtures", "identity", "mfa", "totp-replay-rejected.json"))
	for _, c := range f.Tests {
		c := c
		t.Run(c.ID, func(t *testing.T) { runIdentityStepCase(t, c) })
	}
}

// TestShareCreatedByStatusConformance runs against Postgres only: the
// in-memory share store has no usr registry to check created_by against.
func TestShareCreatedByStatusConformance(t *testing.T) {
	url := pgURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Skipf("pgxpool.New: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("ping failed: %v", err)
	}
	f := loadStepFixtureFile(t, filepath.Join("fixtures", "authorization", "shares", "created-by-status.json"))
	for _, c := range f.Tests {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			resetDB(t, pool)
			runIdentitySteps(t, c, identity.NewPostgresIdentityStore(ctx, pool), authz.NewPostgresShareStore(ctx, pool), nil)
		})
	}
}
