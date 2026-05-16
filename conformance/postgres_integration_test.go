// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

// Postgres integration smoke test — verifies the three Postgres
// adapters (identity, tenancy, authz) drive a real database
// end-to-end. Skipped automatically when FT_GO_POSTGRES_URL is unset
// or the database is unreachable.

package conformance

import (
	"context"
	"os"
	"testing"
	"time"

	authz "github.com/flametrench/flametrench-go/packages/authz"
	identity "github.com/flametrench/flametrench-go/packages/identity"
	tenancy "github.com/flametrench/flametrench-go/packages/tenancy"

	"github.com/jackc/pgx/v5/pgxpool"
)

func pgURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("FT_GO_POSTGRES_URL")
	if url == "" {
		t.Skip("FT_GO_POSTGRES_URL not set; skipping Postgres integration test")
	}
	return url
}

func resetDB(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	for _, tbl := range []string{"comment", "ticket", "inst", "shr", "tup", "mem", "inv", "org", "usr_mfa_policy", "mfa", "ses", "cred", "usr", "pat"} {
		_, _ = pool.Exec(ctx, "TRUNCATE TABLE "+tbl+" CASCADE")
	}
}

func TestPostgresIntegrationSmoke(t *testing.T) {
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
	resetDB(t, pool)

	idStore := identity.NewPostgresIdentityStore(ctx, pool)
	tenStore := tenancy.NewPostgresTenancyStore(ctx, pool)
	tupStore := authz.NewPostgresTupleStore(ctx, pool)
	shrStore := authz.NewPostgresShareStore(ctx, pool)

	// 1. Create user.
	dn := "Alice Founder"
	u, err := idStore.CreateUser(&dn)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.Status != identity.StatusActive {
		t.Errorf("user status = %q", u.Status)
	}

	// 2. Create password credential.
	cred, err := idStore.CreatePasswordCredential(u.ID, "alice@example.com", "correcthorsebatterystaple")
	if err != nil {
		t.Fatalf("CreatePasswordCredential: %v", err)
	}

	// 3. Verify password.
	vc, err := idStore.VerifyPassword("alice@example.com", "correcthorsebatterystaple")
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if vc.UsrID != u.ID || vc.CredID != cred.ID {
		t.Errorf("VerifyPassword wrong subject")
	}

	// 4. Wrong password rejects.
	if _, err := idStore.VerifyPassword("alice@example.com", "wrong"); err == nil {
		t.Error("wrong password should reject")
	}

	// 5. Create session.
	swt, err := idStore.CreateSession(u.ID, cred.ID, 3600)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	verified, err := idStore.VerifySessionToken(swt.Token)
	if err != nil {
		t.Fatalf("VerifySessionToken: %v", err)
	}
	if verified.ID != swt.Session.ID {
		t.Errorf("session id mismatch")
	}

	// 6. Create org + verify owner mem + owner tuple.
	name, slug := "Acme", "acme-go-test"
	orgRes, err := tenStore.CreateOrg(u.ID, tenancy.CreateOrgOptions{Name: &name, Slug: &slug})
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	if orgRes.OwnerMembership.Role != tenancy.RoleOwner {
		t.Errorf("owner mem role = %q", orgRes.OwnerMembership.Role)
	}

	// 7. Tuple exists.
	r, err := tupStore.Check(authz.CheckInput{
		SubjectType: "usr", SubjectID: u.ID,
		Relation:   "owner",
		ObjectType: "org", ObjectID: orgRes.Org.ID,
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !r.Allowed {
		t.Error("owner tuple should be present after CreateOrg")
	}

	// 8. Add a member + tuple.
	u2, _ := idStore.CreateUser(nil)
	mem, err := tenStore.AddMember(orgRes.Org.ID, u2.ID, tenancy.RoleAdmin, &u.ID)
	if err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	r2, err := tupStore.CheckAny(authz.CheckAnyInput{
		SubjectType: "usr", SubjectID: u2.ID,
		Relations:   []string{"owner", "admin", "member"},
		ObjectType: "org", ObjectID: orgRes.Org.ID,
	})
	if err != nil {
		t.Fatalf("CheckAny: %v", err)
	}
	if !r2.Allowed {
		t.Error("admin role should match CheckAny on org_roles set")
	}

	// 9. ChangeRole — revoke-and-re-add, new mem replaces old.
	newMem, err := tenStore.ChangeRole(mem.ID, tenancy.RoleMember)
	if err != nil {
		t.Fatalf("ChangeRole: %v", err)
	}
	if newMem.Role != tenancy.RoleMember || newMem.Replaces == nil || *newMem.Replaces != mem.ID {
		t.Errorf("ChangeRole result unexpected: %+v", newMem)
	}

	// 10. Share-token roundtrip.
	shareRes, err := shrStore.CreateShare(authz.CreateShareInput{
		ObjectType: "org", ObjectID: orgRes.Org.ID,
		Relation:  "viewer",
		CreatedBy: u.ID, ExpiresInSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("CreateShare: %v", err)
	}
	verifiedShare, err := shrStore.VerifyShareToken(shareRes.Token)
	if err != nil {
		t.Fatalf("VerifyShareToken: %v", err)
	}
	if verifiedShare.Relation != "viewer" {
		t.Errorf("share relation = %q; want viewer", verifiedShare.Relation)
	}
	if _, err := shrStore.RevokeShare(shareRes.Share.ID); err != nil {
		t.Fatalf("RevokeShare: %v", err)
	}
	if _, err := shrStore.VerifyShareToken(shareRes.Token); err == nil {
		t.Error("revoked share should reject verify")
	}

	// 11. PAT roundtrip.
	exp := time.Now().UTC().Add(24 * time.Hour)
	patRes, err := idStore.CreatePat(identity.CreatePatInput{
		UsrID: u.ID, Name: "ci-deploys", Scope: []string{"deploy:read"},
		ExpiresAt: &exp,
	})
	if err != nil {
		t.Fatalf("CreatePat: %v", err)
	}
	if vp, err := idStore.VerifyPatToken(patRes.Token); err != nil {
		t.Fatalf("VerifyPatToken: %v", err)
	} else if vp.UsrID != u.ID {
		t.Errorf("PAT verify wrong user")
	}
	tampered := patRes.Token[:len(patRes.Token)-3] + "AAA"
	if _, err := idStore.VerifyPatToken(tampered); err == nil {
		t.Error("tampered PAT should reject")
	}
	if _, err := idStore.RevokePat(patRes.Pat.ID); err != nil {
		t.Fatalf("RevokePat: %v", err)
	}
	if _, err := idStore.VerifyPatToken(patRes.Token); err == nil {
		t.Error("revoked PAT should reject")
	}

	// 12. ADR 0017 — Postgres rewrite-rule evaluation.
	rules := authz.Rules{
		"proj": map[string]authz.Rule{
			"viewer": {
				authz.This{},
				authz.ComputedUserset{Relation: "editor"},
				authz.TupleToUserset{TuplesetRelation: "parent_org", ComputedUsersetRelation: "member"},
			},
		},
	}
	tupStoreRules := authz.NewPostgresTupleStoreWithRules(ctx, pool, rules, authz.EvaluateOptions{})
	// Set up a proj + parent_org tuple.
	projID := "proj_" + u.ID[4:] // reuse 32hex from the user; arbitrary
	_, err = tupStoreRules.CreateTuple(authz.CreateTupleInput{
		SubjectType: "org", SubjectID: orgRes.Org.ID,
		Relation:   "parent_org",
		ObjectType: "proj", ObjectID: projID,
	})
	if err != nil {
		t.Fatalf("CreateTuple parent_org: %v", err)
	}
	// Add usr→member on the org (already there from CreateOrg owner? Let's add member tuple explicitly for u2).
	_, _ = tupStoreRules.CreateTuple(authz.CreateTupleInput{
		SubjectType: "usr", SubjectID: u2.ID,
		Relation:   "member",
		ObjectType: "org", ObjectID: orgRes.Org.ID,
	})
	// Now check: does u2 have viewer on proj via the tuple_to_userset hop?
	r3, err := tupStoreRules.Check(authz.CheckInput{
		SubjectType: "usr", SubjectID: u2.ID,
		Relation:   "viewer",
		ObjectType: "proj", ObjectID: projID,
	})
	if err != nil {
		t.Fatalf("rule-eval Check: %v", err)
	}
	if !r3.Allowed {
		t.Error("tuple_to_userset hop should grant viewer on proj via parent_org → member")
	}

	t.Logf("Postgres integration smoke: 12 steps passed")
}
