// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Shared test suite for any TenancyStore implementation. Mirrors the
// identity package's store_suite_test.go: the same test bodies run
// against both InMemoryTenancyStore and PostgresTenancyStore through
// per-backend factory functions. The Postgres factory truncates the
// org/mem/inv/tup tables and seeds the `usr` rows that org foreign
// keys require.

package tenancy

import (
	"errors"
	"testing"
	"time"
)

// storeFactory returns a fresh TenancyStore + an opaque "seed user"
// hook the test calls before passing wire-format user IDs into the
// store. In-memory stores accept any wire-format ID without prior
// registration; the Postgres backend requires a row in `usr`.
type storeFactory func(t *testing.T) (TenancyStore, func(t *testing.T, usrID string), func())

func runTenancySuite(t *testing.T, newStore storeFactory) {
	t.Run("CreateOrg", func(t *testing.T) { testCreateOrg(t, newStore) })
	t.Run("GetOrg", func(t *testing.T) { testGetOrg(t, newStore) })
	t.Run("UpdateOrg", func(t *testing.T) { testUpdateOrg(t, newStore) })
	t.Run("OrgLifecycle", func(t *testing.T) { testOrgLifecycle(t, newStore) })
	t.Run("AddMember", func(t *testing.T) { testAddMember(t, newStore) })
	t.Run("ChangeRole", func(t *testing.T) { testChangeRole(t, newStore) })
	t.Run("MembershipLifecycle", func(t *testing.T) { testMembershipLifecycle(t, newStore) })
	t.Run("AdminRemove", func(t *testing.T) { testAdminRemove(t, newStore) })
	t.Run("SelfLeave", func(t *testing.T) { testSelfLeave(t, newStore) })
	t.Run("TransferOwnership", func(t *testing.T) { testTransferOwnership(t, newStore) })
	t.Run("Invitations", func(t *testing.T) { testInvitations(t, newStore) })
	t.Run("Tuples", func(t *testing.T) { testTuples(t, newStore) })
	t.Run("ListMembers", func(t *testing.T) { testListMembers(t, newStore) })
	t.Run("ListInvitations", func(t *testing.T) { testListInvitations(t, newStore) })
	t.Run("Errors", func(t *testing.T) { testErrorHelpers(t, newStore) })
	t.Run("AdminRank", func(t *testing.T) { testAdminRank(t) })
	t.Run("MoreLifecycle", func(t *testing.T) { testMoreLifecycle(t, newStore) })
}

// strP returns a pointer to v.
func strP[T any](v T) *T { return &v }

// genUsrID returns a deterministic wire-format user id with a 32-hex
// payload derived from idx. Used so tests can pre-seed users without
// colliding across sub-tests.
func genUsrID(idx int) string {
	const hex = "0123456789abcdef"
	out := []byte("usr_")
	// 32 hex chars, but with idx encoded in the last 4.
	base := "0190f2a81b3c7abc8123456789ab"
	out = append(out, []byte(base)...)
	out = append(out,
		hex[(idx>>12)&0xF],
		hex[(idx>>8)&0xF],
		hex[(idx>>4)&0xF],
		hex[idx&0xF],
	)
	return string(out)
}

func mustCreateOrg(t *testing.T, s TenancyStore, seed func(*testing.T, string), creator string) CreateOrgResult {
	t.Helper()
	seed(t, creator)
	r, err := s.CreateOrg(creator, CreateOrgOptions{})
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	return r
}

// ─── CreateOrg ───

func testCreateOrg(t *testing.T, newStore storeFactory) {
	t.Run("default_active_with_owner_mem", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		creator := genUsrID(1)
		seed(t, creator)
		r, err := s.CreateOrg(creator, CreateOrgOptions{})
		if err != nil {
			t.Fatalf("CreateOrg: %v", err)
		}
		if r.Org.Status != StatusActive {
			t.Errorf("org status = %q", r.Org.Status)
		}
		if r.OwnerMembership.Role != RoleOwner {
			t.Errorf("owner mem role = %q", r.OwnerMembership.Role)
		}
		if r.OwnerMembership.UsrID != creator {
			t.Errorf("owner mem usrID = %q; want %q", r.OwnerMembership.UsrID, creator)
		}
	})

	t.Run("withName_andSlug", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		creator := genUsrID(1)
		seed(t, creator)
		name, slug := "Acme Co", "acme-co"
		r, err := s.CreateOrg(creator, CreateOrgOptions{Name: &name, Slug: &slug})
		if err != nil {
			t.Fatalf("CreateOrg: %v", err)
		}
		if r.Org.Name == nil || *r.Org.Name != name {
			t.Errorf("name = %v", r.Org.Name)
		}
		if r.Org.Slug == nil || *r.Org.Slug != slug {
			t.Errorf("slug = %v", r.Org.Slug)
		}
	})

	t.Run("duplicateSlug_rejects", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		creator := genUsrID(1)
		other := genUsrID(2)
		seed(t, creator)
		seed(t, other)
		slug := "dup"
		if _, err := s.CreateOrg(creator, CreateOrgOptions{Slug: &slug}); err != nil {
			t.Fatalf("first CreateOrg: %v", err)
		}
		if _, err := s.CreateOrg(other, CreateOrgOptions{Slug: &slug}); err == nil {
			t.Error("duplicate slug should reject")
		}
	})

	t.Run("creates_owner_tuple", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		creator := genUsrID(1)
		seed(t, creator)
		r, _ := s.CreateOrg(creator, CreateOrgOptions{})
		ts, err := s.ListTuplesForObject("org", r.Org.ID, strP("owner"))
		if err != nil {
			t.Fatalf("ListTuplesForObject: %v", err)
		}
		if len(ts) != 1 {
			t.Errorf("expected 1 owner tuple, got %d", len(ts))
		}
	})
}

// ─── GetOrg ───

func testGetOrg(t *testing.T, newStore storeFactory) {
	t.Run("roundtrip", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		r := mustCreateOrg(t, s, seed, genUsrID(1))
		got, err := s.GetOrg(r.Org.ID)
		if err != nil {
			t.Fatalf("GetOrg: %v", err)
		}
		if got.ID != r.Org.ID || got.Status != StatusActive {
			t.Errorf("GetOrg returned %+v", got)
		}
	})

	t.Run("notFound", func(t *testing.T) {
		s, _, done := newStore(t)
		defer done()
		if _, err := s.GetOrg("org_00000000000000000000000000000001"); err == nil {
			t.Error("unknown org id should error")
		}
	})
}

// ─── UpdateOrg ───

func testUpdateOrg(t *testing.T, newStore storeFactory) {
	t.Run("setName", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		r := mustCreateOrg(t, s, seed, genUsrID(1))
		name := "Renamed"
		got, err := s.UpdateOrg(r.Org.ID, UpdateOrgInput{Name: &name})
		if err != nil {
			t.Fatalf("UpdateOrg: %v", err)
		}
		if got.Name == nil || *got.Name != name {
			t.Errorf("name = %v", got.Name)
		}
	})

	t.Run("clearName", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		creator := genUsrID(1)
		seed(t, creator)
		name := "Initial"
		r, _ := s.CreateOrg(creator, CreateOrgOptions{Name: &name})
		got, err := s.UpdateOrg(r.Org.ID, UpdateOrgInput{ClearName: true})
		if err != nil {
			t.Fatalf("UpdateOrg: %v", err)
		}
		if got.Name != nil {
			t.Errorf("name = %v; want nil", got.Name)
		}
	})

	t.Run("setSlug", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		r := mustCreateOrg(t, s, seed, genUsrID(1))
		slug := "renamed-slug"
		got, err := s.UpdateOrg(r.Org.ID, UpdateOrgInput{Slug: &slug})
		if err != nil {
			t.Fatalf("UpdateOrg: %v", err)
		}
		if got.Slug == nil || *got.Slug != slug {
			t.Errorf("slug = %v", got.Slug)
		}
	})
}

// ─── Org lifecycle ───

func testOrgLifecycle(t *testing.T, newStore storeFactory) {
	t.Run("Suspend_then_Reinstate", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		r := mustCreateOrg(t, s, seed, genUsrID(1))
		got, err := s.SuspendOrg(r.Org.ID)
		if err != nil {
			t.Fatalf("SuspendOrg: %v", err)
		}
		if got.Status != StatusSuspended {
			t.Errorf("status = %q", got.Status)
		}
		got, err = s.ReinstateOrg(r.Org.ID)
		if err != nil {
			t.Fatalf("ReinstateOrg: %v", err)
		}
		if got.Status != StatusActive {
			t.Errorf("status after reinstate = %q", got.Status)
		}
	})

	t.Run("RevokeOrg_isTerminal", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		r := mustCreateOrg(t, s, seed, genUsrID(1))
		got, err := s.RevokeOrg(r.Org.ID)
		if err != nil {
			t.Fatalf("RevokeOrg: %v", err)
		}
		if got.Status != StatusRevoked {
			t.Errorf("status = %q", got.Status)
		}
		// Cannot reinstate revoked.
		if _, err := s.ReinstateOrg(r.Org.ID); err == nil {
			t.Error("reinstate of revoked should error")
		}
	})
}

// ─── AddMember ───

func testAddMember(t *testing.T, newStore storeFactory) {
	t.Run("happy", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		creator := genUsrID(1)
		other := genUsrID(2)
		seed(t, creator)
		seed(t, other)
		r, _ := s.CreateOrg(creator, CreateOrgOptions{})
		mem, err := s.AddMember(r.Org.ID, other, RoleMember, &creator)
		if err != nil {
			t.Fatalf("AddMember: %v", err)
		}
		if mem.Role != RoleMember {
			t.Errorf("role = %q", mem.Role)
		}
		if mem.InvitedBy == nil || *mem.InvitedBy != creator {
			t.Errorf("invitedBy = %v", mem.InvitedBy)
		}
	})

	t.Run("duplicate_rejects", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		creator := genUsrID(1)
		other := genUsrID(2)
		seed(t, creator)
		seed(t, other)
		r, _ := s.CreateOrg(creator, CreateOrgOptions{})
		if _, err := s.AddMember(r.Org.ID, other, RoleMember, nil); err != nil {
			t.Fatalf("first add: %v", err)
		}
		if _, err := s.AddMember(r.Org.ID, other, RoleMember, nil); err == nil {
			t.Error("duplicate AddMember should reject")
		}
	})

	t.Run("GetMembership_roundtrip", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		creator := genUsrID(1)
		other := genUsrID(2)
		seed(t, creator)
		seed(t, other)
		r, _ := s.CreateOrg(creator, CreateOrgOptions{})
		mem, _ := s.AddMember(r.Org.ID, other, RoleAdmin, nil)
		got, err := s.GetMembership(mem.ID)
		if err != nil {
			t.Fatalf("GetMembership: %v", err)
		}
		if got.ID != mem.ID || got.Role != RoleAdmin {
			t.Errorf("got %+v", got)
		}
	})
}

// ─── ChangeRole ───

func testChangeRole(t *testing.T, newStore storeFactory) {
	t.Run("happy", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		creator := genUsrID(1)
		other := genUsrID(2)
		seed(t, creator)
		seed(t, other)
		r, _ := s.CreateOrg(creator, CreateOrgOptions{})
		mem, _ := s.AddMember(r.Org.ID, other, RoleMember, nil)
		newMem, err := s.ChangeRole(mem.ID, RoleAdmin)
		if err != nil {
			t.Fatalf("ChangeRole: %v", err)
		}
		if newMem.Role != RoleAdmin {
			t.Errorf("role = %q", newMem.Role)
		}
		if newMem.Replaces == nil || *newMem.Replaces != mem.ID {
			t.Errorf("replaces chain not populated")
		}
	})

	t.Run("solo_owner_demotion_rejects", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		r := mustCreateOrg(t, s, seed, genUsrID(1))
		if _, err := s.ChangeRole(r.OwnerMembership.ID, RoleMember); err == nil {
			t.Error("demoting sole owner should reject")
		}
	})
}

// ─── Membership lifecycle (suspend / reinstate) ───

func testMembershipLifecycle(t *testing.T, newStore storeFactory) {
	t.Run("Suspend_then_Reinstate", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		creator := genUsrID(1)
		other := genUsrID(2)
		seed(t, creator)
		seed(t, other)
		r, _ := s.CreateOrg(creator, CreateOrgOptions{})
		mem, _ := s.AddMember(r.Org.ID, other, RoleMember, nil)
		got, err := s.SuspendMembership(mem.ID)
		if err != nil {
			t.Fatalf("SuspendMembership: %v", err)
		}
		if got.Status != StatusSuspended {
			t.Errorf("status = %q", got.Status)
		}
		got, err = s.ReinstateMembership(mem.ID)
		if err != nil {
			t.Fatalf("ReinstateMembership: %v", err)
		}
		if got.Status != StatusActive {
			t.Errorf("status after reinstate = %q", got.Status)
		}
	})
}

// ─── AdminRemove ───

func testAdminRemove(t *testing.T, newStore storeFactory) {
	t.Run("admin_removes_member", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		owner := genUsrID(1)
		target := genUsrID(2)
		seed(t, owner)
		seed(t, target)
		r, _ := s.CreateOrg(owner, CreateOrgOptions{})
		mem, _ := s.AddMember(r.Org.ID, target, RoleMember, nil)
		got, err := s.AdminRemove(mem.ID, owner)
		if err != nil {
			t.Fatalf("AdminRemove: %v", err)
		}
		if got.Status != StatusRevoked {
			t.Errorf("status = %q", got.Status)
		}
	})
}

// ─── SelfLeave ───

func testSelfLeave(t *testing.T, newStore storeFactory) {
	t.Run("member_leaves", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		owner := genUsrID(1)
		other := genUsrID(2)
		seed(t, owner)
		seed(t, other)
		r, _ := s.CreateOrg(owner, CreateOrgOptions{})
		mem, _ := s.AddMember(r.Org.ID, other, RoleMember, nil)
		got, err := s.SelfLeave(mem.ID, nil)
		if err != nil {
			t.Fatalf("SelfLeave: %v", err)
		}
		if got.Status != StatusRevoked {
			t.Errorf("status = %q", got.Status)
		}
	})

	t.Run("solo_owner_must_transferTo", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		r := mustCreateOrg(t, s, seed, genUsrID(1))
		if _, err := s.SelfLeave(r.OwnerMembership.ID, nil); err == nil {
			t.Error("sole owner leaving without transferTo should reject")
		}
	})
}

// ─── TransferOwnership ───

func testTransferOwnership(t *testing.T, newStore storeFactory) {
	t.Run("happy", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		owner := genUsrID(1)
		next := genUsrID(2)
		seed(t, owner)
		seed(t, next)
		r, _ := s.CreateOrg(owner, CreateOrgOptions{})
		mem, _ := s.AddMember(r.Org.ID, next, RoleAdmin, nil)
		got, err := s.TransferOwnership(r.Org.ID, r.OwnerMembership.ID, mem.ID)
		if err != nil {
			t.Fatalf("TransferOwnership: %v", err)
		}
		if got.ToMembership.Role != RoleOwner {
			t.Errorf("to role = %q", got.ToMembership.Role)
		}
		if got.FromMembership.Role != RoleAdmin {
			t.Errorf("from role = %q", got.FromMembership.Role)
		}
	})
}

// ─── Invitations ───

func testInvitations(t *testing.T, newStore storeFactory) {
	t.Run("Create_pending", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		owner := genUsrID(1)
		seed(t, owner)
		r, _ := s.CreateOrg(owner, CreateOrgOptions{})
		exp := time.Now().UTC().Add(7 * 24 * time.Hour)
		inv, err := s.CreateInvitation(r.Org.ID, "alice@example.com", RoleMember, owner, exp, nil)
		if err != nil {
			t.Fatalf("CreateInvitation: %v", err)
		}
		if inv.Status != InvitationStatusPending {
			t.Errorf("status = %q", inv.Status)
		}
		if inv.Identifier != "alice@example.com" {
			t.Errorf("identifier = %q", inv.Identifier)
		}
	})

	t.Run("Get_roundtrip", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		owner := genUsrID(1)
		seed(t, owner)
		r, _ := s.CreateOrg(owner, CreateOrgOptions{})
		exp := time.Now().UTC().Add(24 * time.Hour)
		inv, _ := s.CreateInvitation(r.Org.ID, "a@b.com", RoleMember, owner, exp, nil)
		got, err := s.GetInvitation(inv.ID)
		if err != nil {
			t.Fatalf("GetInvitation: %v", err)
		}
		if got.ID != inv.ID {
			t.Errorf("ids differ")
		}
	})

	t.Run("Accept_without_acceptingIdentifier_rejects", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		owner := genUsrID(1)
		alice := genUsrID(2)
		seed(t, owner)
		seed(t, alice)
		r, _ := s.CreateOrg(owner, CreateOrgOptions{})
		exp := time.Now().UTC().Add(24 * time.Hour)
		inv, _ := s.CreateInvitation(r.Org.ID, "alice@example.com", RoleMember, owner, exp, nil)
		if _, err := s.AcceptInvitation(inv.ID, AcceptInvitationOptions{AsUsrID: &alice}); err == nil {
			t.Error("AcceptInvitation without accepting_identifier should reject")
		}
	})

	t.Run("Accept_identifier_mismatch_rejects", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		owner := genUsrID(1)
		alice := genUsrID(2)
		seed(t, owner)
		seed(t, alice)
		r, _ := s.CreateOrg(owner, CreateOrgOptions{})
		exp := time.Now().UTC().Add(24 * time.Hour)
		inv, _ := s.CreateInvitation(r.Org.ID, "alice@example.com", RoleMember, owner, exp, nil)
		wrong := "bob@example.com"
		if _, err := s.AcceptInvitation(inv.ID, AcceptInvitationOptions{AsUsrID: &alice, AcceptingIdentifier: &wrong}); err == nil {
			t.Error("identifier mismatch should reject")
		}
	})

	t.Run("Accept_happy", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		owner := genUsrID(1)
		alice := genUsrID(2)
		seed(t, owner)
		seed(t, alice)
		r, _ := s.CreateOrg(owner, CreateOrgOptions{})
		exp := time.Now().UTC().Add(24 * time.Hour)
		inv, _ := s.CreateInvitation(r.Org.ID, "alice@example.com", RoleMember, owner, exp, nil)
		ident := "alice@example.com"
		res, err := s.AcceptInvitation(inv.ID, AcceptInvitationOptions{AsUsrID: &alice, AcceptingIdentifier: &ident})
		if err != nil {
			t.Fatalf("AcceptInvitation: %v", err)
		}
		if res.Invitation.Status != InvitationStatusAccepted {
			t.Errorf("invitation status = %q", res.Invitation.Status)
		}
		if res.Membership.UsrID != alice {
			t.Errorf("membership usrID = %q", res.Membership.UsrID)
		}
	})

	t.Run("Accept_materializes_preTuples", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		owner := genUsrID(1)
		alice := genUsrID(2)
		seed(t, owner)
		seed(t, alice)
		r, _ := s.CreateOrg(owner, CreateOrgOptions{})
		exp := time.Now().UTC().Add(24 * time.Hour)
		pre := []PreTuple{{Relation: "editor", ObjectType: "doc", ObjectID: "doc_0190f2a81b3c7abc8123456789abcdef"}}
		inv, _ := s.CreateInvitation(r.Org.ID, "alice@example.com", RoleMember, owner, exp, pre)
		ident := "alice@example.com"
		res, err := s.AcceptInvitation(inv.ID, AcceptInvitationOptions{AsUsrID: &alice, AcceptingIdentifier: &ident})
		if err != nil {
			t.Fatalf("AcceptInvitation: %v", err)
		}
		if len(res.MaterializedTuples) == 0 {
			t.Error("expected materialized tuples")
		}
	})

	t.Run("Accept_second_time_rejects", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		owner := genUsrID(1)
		alice := genUsrID(2)
		seed(t, owner)
		seed(t, alice)
		r, _ := s.CreateOrg(owner, CreateOrgOptions{})
		exp := time.Now().UTC().Add(24 * time.Hour)
		inv, _ := s.CreateInvitation(r.Org.ID, "alice@example.com", RoleMember, owner, exp, nil)
		ident := "alice@example.com"
		_, _ = s.AcceptInvitation(inv.ID, AcceptInvitationOptions{AsUsrID: &alice, AcceptingIdentifier: &ident})
		if _, err := s.AcceptInvitation(inv.ID, AcceptInvitationOptions{AsUsrID: &alice, AcceptingIdentifier: &ident}); err == nil {
			t.Error("second accept should reject")
		}
	})

	t.Run("Decline", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		owner := genUsrID(1)
		seed(t, owner)
		r, _ := s.CreateOrg(owner, CreateOrgOptions{})
		exp := time.Now().UTC().Add(24 * time.Hour)
		inv, _ := s.CreateInvitation(r.Org.ID, "alice@example.com", RoleMember, owner, exp, nil)
		got, err := s.DeclineInvitation(inv.ID, nil)
		if err != nil {
			t.Fatalf("DeclineInvitation: %v", err)
		}
		if got.Status != InvitationStatusDeclined {
			t.Errorf("status = %q", got.Status)
		}
	})

	t.Run("Revoke", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		owner := genUsrID(1)
		seed(t, owner)
		r, _ := s.CreateOrg(owner, CreateOrgOptions{})
		exp := time.Now().UTC().Add(24 * time.Hour)
		inv, _ := s.CreateInvitation(r.Org.ID, "alice@example.com", RoleMember, owner, exp, nil)
		got, err := s.RevokeInvitation(inv.ID, owner)
		if err != nil {
			t.Fatalf("RevokeInvitation: %v", err)
		}
		if got.Status != InvitationStatusRevoked {
			t.Errorf("status = %q", got.Status)
		}
	})
}

// ─── Tuples ───

func testTuples(t *testing.T, newStore storeFactory) {
	t.Run("ListTuplesForSubject_includes_owner", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		creator := genUsrID(1)
		r := mustCreateOrg(t, s, seed, creator)
		ts, err := s.ListTuplesForSubject("usr", creator)
		if err != nil {
			t.Fatalf("ListTuplesForSubject: %v", err)
		}
		found := false
		for _, tup := range ts {
			if tup.Relation == "owner" && tup.ObjectType == "org" && tup.ObjectID == r.Org.ID {
				found = true
			}
		}
		if !found {
			t.Errorf("expected owner tuple for %s, got %+v", creator, ts)
		}
	})

	t.Run("ListTuplesForObject_filterByRelation", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		r := mustCreateOrg(t, s, seed, genUsrID(1))
		ts, err := s.ListTuplesForObject("org", r.Org.ID, strP("owner"))
		if err != nil {
			t.Fatalf("ListTuplesForObject: %v", err)
		}
		if len(ts) != 1 {
			t.Errorf("expected 1 owner tuple, got %d", len(ts))
		}
		// All relations.
		all, _ := s.ListTuplesForObject("org", r.Org.ID, nil)
		if len(all) < 1 {
			t.Error("expected ≥1 tuple")
		}
	})
}

// ─── List paginators ───

func testListMembers(t *testing.T, newStore storeFactory) {
	t.Run("paginates", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		creator := genUsrID(1)
		seed(t, creator)
		r, _ := s.CreateOrg(creator, CreateOrgOptions{})
		for i := 2; i < 6; i++ {
			u := genUsrID(i)
			seed(t, u)
			_, _ = s.AddMember(r.Org.ID, u, RoleMember, nil)
		}
		page1, err := s.ListMembers(r.Org.ID, ListMembersOptions{Limit: 2})
		if err != nil {
			t.Fatalf("ListMembers: %v", err)
		}
		if len(page1.Data) != 2 {
			t.Errorf("page1 len = %d; want 2", len(page1.Data))
		}
		if page1.NextCursor == nil {
			t.Error("expected next cursor")
		}
	})
}

func testListInvitations(t *testing.T, newStore storeFactory) {
	t.Run("paginates", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		creator := genUsrID(1)
		seed(t, creator)
		r, _ := s.CreateOrg(creator, CreateOrgOptions{})
		exp := time.Now().UTC().Add(24 * time.Hour)
		for i := 0; i < 4; i++ {
			ident := "a" + string(rune('a'+i)) + "@example.com"
			_, _ = s.CreateInvitation(r.Org.ID, ident, RoleMember, creator, exp, nil)
		}
		page1, err := s.ListInvitations(r.Org.ID, ListInvitationsOptions{Limit: 2})
		if err != nil {
			t.Fatalf("ListInvitations: %v", err)
		}
		if len(page1.Data) != 2 {
			t.Errorf("page1 len = %d; want 2", len(page1.Data))
		}
		if page1.NextCursor == nil {
			t.Error("expected next cursor")
		}
	})
}

// ─── Error helpers + uncommon paths ───

func testErrorHelpers(t *testing.T, newStore storeFactory) {
	t.Run("IsNotFound_for_unknown_org", func(t *testing.T) {
		s, _, done := newStore(t)
		defer done()
		_, err := s.GetOrg("org_00000000000000000000000000000001")
		if !IsNotFound(err) {
			t.Errorf("IsNotFound(%v) = false; want true", err)
		}
		if ErrorCode(err) == "" {
			t.Error("ErrorCode empty")
		}
	})

	t.Run("IsOrgSlugConflict_for_duplicate_slug", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		owner1 := genUsrID(1)
		owner2 := genUsrID(2)
		seed(t, owner1)
		seed(t, owner2)
		slug := "dup-helper"
		if _, err := s.CreateOrg(owner1, CreateOrgOptions{Slug: &slug}); err != nil {
			t.Fatalf("first CreateOrg: %v", err)
		}
		_, err := s.CreateOrg(owner2, CreateOrgOptions{Slug: &slug})
		if !IsOrgSlugConflict(err) {
			t.Errorf("IsOrgSlugConflict(%v) = false; want true", err)
		}
	})

	t.Run("IsDuplicateMembership_for_duplicate_add", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		creator := genUsrID(1)
		other := genUsrID(2)
		seed(t, creator)
		seed(t, other)
		r, _ := s.CreateOrg(creator, CreateOrgOptions{})
		if _, err := s.AddMember(r.Org.ID, other, RoleMember, nil); err != nil {
			t.Fatalf("first add: %v", err)
		}
		_, err := s.AddMember(r.Org.ID, other, RoleMember, nil)
		if !IsDuplicateMembership(err) {
			t.Errorf("IsDuplicateMembership(%v) = false; want true", err)
		}
	})

	t.Run("PreconditionError_methods", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		r := mustCreateOrg(t, s, seed, genUsrID(1))
		// Reinstate of an active org raises PreconditionError.
		_, err := s.ReinstateOrg(r.Org.ID)
		var pre *PreconditionError
		if !errors.As(err, &pre) {
			t.Fatalf("err = %v; want *PreconditionError", err)
		}
		if pre.Error() == "" {
			t.Error("PreconditionError.Error() empty")
		}
		if pre.Code() == "" {
			t.Error("PreconditionError.Code() empty")
		}
	})

	t.Run("GetMembership_notFound", func(t *testing.T) {
		s, _, done := newStore(t)
		defer done()
		if _, err := s.GetMembership("mem_00000000000000000000000000000001"); err == nil {
			t.Error("unknown mem id should error")
		}
	})

	t.Run("GetInvitation_notFound", func(t *testing.T) {
		s, _, done := newStore(t)
		defer done()
		if _, err := s.GetInvitation("inv_00000000000000000000000000000001"); err == nil {
			t.Error("unknown inv id should error")
		}
	})
}

func testAdminRank(t *testing.T) {
	cases := []struct {
		role Role
		rank int
	}{
		{RoleOwner, 4},
		{RoleAdmin, 3},
		{RoleMember, 2},
		{RoleGuest, 1},
		{RoleViewer, 0},
		{RoleEditor, 0},
		{Role("unknown"), 0},
	}
	for _, c := range cases {
		if got := c.role.AdminRank(); got != c.rank {
			t.Errorf("%s.AdminRank() = %d; want %d", c.role, got, c.rank)
		}
	}
}

func testMoreLifecycle(t *testing.T, newStore storeFactory) {
	t.Run("SelfLeave_solo_owner_with_transferTo", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		owner := genUsrID(1)
		next := genUsrID(2)
		seed(t, owner)
		seed(t, next)
		r, _ := s.CreateOrg(owner, CreateOrgOptions{})
		_, _ = s.AddMember(r.Org.ID, next, RoleAdmin, nil)
		// transferTo takes a user-id (not a mem-id).
		got, err := s.SelfLeave(r.OwnerMembership.ID, &next)
		if err != nil {
			t.Fatalf("SelfLeave: %v", err)
		}
		if got.Status != StatusRevoked {
			t.Errorf("status = %q", got.Status)
		}
	})

	t.Run("ListMembers_filterByStatus", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		creator := genUsrID(1)
		other := genUsrID(2)
		seed(t, creator)
		seed(t, other)
		r, _ := s.CreateOrg(creator, CreateOrgOptions{})
		mem, _ := s.AddMember(r.Org.ID, other, RoleMember, nil)
		_, _ = s.SuspendMembership(mem.ID)
		susp := StatusSuspended
		page, err := s.ListMembers(r.Org.ID, ListMembersOptions{Status: &susp, Limit: 10})
		if err != nil {
			t.Fatalf("ListMembers: %v", err)
		}
		if len(page.Data) != 1 || page.Data[0].Status != StatusSuspended {
			t.Errorf("filter returned %+v", page.Data)
		}
	})

	t.Run("ListInvitations_filterByStatus", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		creator := genUsrID(1)
		seed(t, creator)
		r, _ := s.CreateOrg(creator, CreateOrgOptions{})
		exp := time.Now().UTC().Add(24 * time.Hour)
		inv, _ := s.CreateInvitation(r.Org.ID, "a@b.com", RoleMember, creator, exp, nil)
		_, _ = s.RevokeInvitation(inv.ID, creator)
		rev := InvitationStatusRevoked
		page, err := s.ListInvitations(r.Org.ID, ListInvitationsOptions{Status: &rev, Limit: 10})
		if err != nil {
			t.Fatalf("ListInvitations: %v", err)
		}
		if len(page.Data) != 1 || page.Data[0].Status != InvitationStatusRevoked {
			t.Errorf("filter returned %+v", page.Data)
		}
	})

	t.Run("ListMembers_cursorContinuation", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		creator := genUsrID(1)
		seed(t, creator)
		r, _ := s.CreateOrg(creator, CreateOrgOptions{})
		for i := 2; i < 6; i++ {
			u := genUsrID(i)
			seed(t, u)
			_, _ = s.AddMember(r.Org.ID, u, RoleMember, nil)
		}
		page1, _ := s.ListMembers(r.Org.ID, ListMembersOptions{Limit: 2})
		if page1.NextCursor == nil {
			t.Fatal("expected next cursor on page1")
		}
		page2, err := s.ListMembers(r.Org.ID, ListMembersOptions{Limit: 10, Cursor: page1.NextCursor})
		if err != nil {
			t.Fatalf("ListMembers page2: %v", err)
		}
		if len(page2.Data) == 0 {
			t.Error("expected page2 data")
		}
	})

	t.Run("UpdateOrg_clearSlug", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		creator := genUsrID(1)
		seed(t, creator)
		slug := "before-clear"
		r, _ := s.CreateOrg(creator, CreateOrgOptions{Slug: &slug})
		got, err := s.UpdateOrg(r.Org.ID, UpdateOrgInput{ClearSlug: true})
		if err != nil {
			t.Fatalf("UpdateOrg: %v", err)
		}
		if got.Slug != nil {
			t.Errorf("slug = %v; want nil", got.Slug)
		}
	})

	t.Run("AdminRemove_admin_cannot_remove_owner", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		owner := genUsrID(1)
		admin := genUsrID(2)
		seed(t, owner)
		seed(t, admin)
		r, _ := s.CreateOrg(owner, CreateOrgOptions{})
		_, _ = s.AddMember(r.Org.ID, admin, RoleAdmin, nil)
		// Admin attempting to remove the sole owner — must reject
		// because rank(admin)=3 ≤ rank(owner)=4.
		if _, err := s.AdminRemove(r.OwnerMembership.ID, admin); err == nil {
			t.Error("admin removing owner should reject")
		}
	})

	t.Run("DeclineInvitation_on_non_pending_rejects", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		creator := genUsrID(1)
		seed(t, creator)
		r, _ := s.CreateOrg(creator, CreateOrgOptions{})
		exp := time.Now().UTC().Add(24 * time.Hour)
		inv, _ := s.CreateInvitation(r.Org.ID, "a@b.com", RoleMember, creator, exp, nil)
		_, _ = s.DeclineInvitation(inv.ID, nil)
		if _, err := s.DeclineInvitation(inv.ID, nil); err == nil {
			t.Error("second decline should reject")
		}
	})

	t.Run("RevokeInvitation_on_accepted_rejects", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		owner := genUsrID(1)
		alice := genUsrID(2)
		seed(t, owner)
		seed(t, alice)
		r, _ := s.CreateOrg(owner, CreateOrgOptions{})
		exp := time.Now().UTC().Add(24 * time.Hour)
		inv, _ := s.CreateInvitation(r.Org.ID, "a@b.com", RoleMember, owner, exp, nil)
		ident := "a@b.com"
		_, _ = s.AcceptInvitation(inv.ID, AcceptInvitationOptions{AsUsrID: &alice, AcceptingIdentifier: &ident})
		if _, err := s.RevokeInvitation(inv.ID, owner); err == nil {
			t.Error("revoke of accepted invitation should reject")
		}
	})

	t.Run("ChangeRole_unknown_mem_rejects", func(t *testing.T) {
		s, _, done := newStore(t)
		defer done()
		if _, err := s.ChangeRole("mem_00000000000000000000000000000001", RoleAdmin); err == nil {
			t.Error("unknown mem id should reject")
		}
	})

	t.Run("SuspendMembership_unknown_rejects", func(t *testing.T) {
		s, _, done := newStore(t)
		defer done()
		if _, err := s.SuspendMembership("mem_00000000000000000000000000000001"); err == nil {
			t.Error("unknown mem id should reject")
		}
	})

	t.Run("DeclineInvitation_byUser", func(t *testing.T) {
		s, seed, done := newStore(t)
		defer done()
		creator := genUsrID(1)
		alice := genUsrID(2)
		seed(t, creator)
		seed(t, alice)
		r, _ := s.CreateOrg(creator, CreateOrgOptions{})
		exp := time.Now().UTC().Add(24 * time.Hour)
		inv, _ := s.CreateInvitation(r.Org.ID, "a@b.com", RoleMember, creator, exp, nil)
		got, err := s.DeclineInvitation(inv.ID, &alice)
		if err != nil {
			t.Fatalf("DeclineInvitation: %v", err)
		}
		if got.Status != InvitationStatusDeclined {
			t.Errorf("status = %q", got.Status)
		}
		if got.TerminalBy == nil || *got.TerminalBy != alice {
			t.Errorf("TerminalBy = %v", got.TerminalBy)
		}
	})
}

// ─── Bind to InMemoryTenancyStore ───

func TestInMemoryTenancySuite(t *testing.T) {
	runTenancySuite(t, func(t *testing.T) (TenancyStore, func(*testing.T, string), func()) {
		s := NewInMemoryTenancyStore()
		// In-mem accepts any wire-format string ID without prior
		// registration; the seed hook is a no-op.
		return s, func(t *testing.T, _ string) {}, func() {}
	})
}
