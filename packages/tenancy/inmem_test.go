// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
package tenancy

import (
	"testing"
	"time"
)

func ptr[T any](v T) *T { return &v }

func TestInMemCreateOrgWithOwner(t *testing.T) {
	s := NewInMemoryTenancyStore()
	creatorID := "usr_0190f2a81b3c7abc8123456789abcdef"
	name, slug := "Acme", "acme"
	r, err := s.CreateOrg(creatorID, CreateOrgOptions{Name: &name, Slug: &slug})
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	if r.Org.Status != StatusActive {
		t.Errorf("org status = %q", r.Org.Status)
	}
	if r.OwnerMembership.Role != RoleOwner {
		t.Errorf("owner mem role = %q", r.OwnerMembership.Role)
	}

	// Tuple created.
	ts, _ := s.ListTuplesForObject("org", r.Org.ID, ptr("owner"))
	if len(ts) != 1 {
		t.Errorf("expected 1 owner tuple, got %d", len(ts))
	}

	// Duplicate slug rejects.
	if _, err := s.CreateOrg("usr_other", CreateOrgOptions{Slug: &slug}); err == nil {
		t.Error("duplicate slug should reject")
	}
}

func TestInMemAddMemberAndChangeRole(t *testing.T) {
	s := NewInMemoryTenancyStore()
	owner := "usr_0190f2a81b3c7abc8123456789abcdef"
	r, _ := s.CreateOrg(owner, CreateOrgOptions{})
	orgID := r.Org.ID

	other := "usr_0190f2a81b3c7abc8123456789aaaaaa"
	mem, err := s.AddMember(orgID, other, RoleMember, nil)
	if err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	if mem.Role != RoleMember {
		t.Errorf("role mismatch")
	}

	// Duplicate add rejects.
	if _, err := s.AddMember(orgID, other, RoleMember, nil); err == nil {
		t.Error("duplicate AddMember should reject")
	}

	// Change role to admin.
	newMem, err := s.ChangeRole(mem.ID, RoleAdmin)
	if err != nil {
		t.Fatalf("ChangeRole: %v", err)
	}
	if newMem.Role != RoleAdmin {
		t.Errorf("new role = %q", newMem.Role)
	}
	if newMem.Replaces == nil || *newMem.Replaces != mem.ID {
		t.Errorf("replaces chain not populated")
	}

	// Sole-owner protection: cannot ChangeRole the only owner.
	if _, err := s.ChangeRole(r.OwnerMembership.ID, RoleMember); err == nil {
		t.Error("demoting sole owner should reject")
	}
}

func TestInMemInvitationLifecycle(t *testing.T) {
	s := NewInMemoryTenancyStore()
	owner := "usr_0190f2a81b3c7abc8123456789abcdef"
	r, _ := s.CreateOrg(owner, CreateOrgOptions{})
	exp := time.Now().UTC().Add(7 * 24 * time.Hour)
	inv, err := s.CreateInvitation(r.Org.ID, "alice@example.com", RoleMember, owner, exp, nil)
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}
	if inv.Status != InvitationStatusPending {
		t.Errorf("invitation status = %q", inv.Status)
	}

	// ADR 0009: as_usr_id without accepting_identifier rejects.
	asUsr := "usr_alice0000000000000000000000000"
	if _, err := s.AcceptInvitation(inv.ID, AcceptInvitationOptions{AsUsrID: &asUsr}); err == nil {
		t.Error("AcceptInvitation without accepting_identifier should reject")
	}

	// ADR 0009: identifier mismatch rejects.
	wrong := "bob@example.com"
	if _, err := s.AcceptInvitation(inv.ID, AcceptInvitationOptions{AsUsrID: &asUsr, AcceptingIdentifier: &wrong}); err == nil {
		t.Error("AcceptInvitation with mismatched identifier should reject")
	}

	// Correct: as_usr_id + matching identifier.
	right := "alice@example.com"
	res, err := s.AcceptInvitation(inv.ID, AcceptInvitationOptions{AsUsrID: &asUsr, AcceptingIdentifier: &right})
	if err != nil {
		t.Fatalf("AcceptInvitation: %v", err)
	}
	if res.Membership.UsrID != asUsr {
		t.Errorf("accepted as wrong user")
	}
	if res.Invitation.Status != InvitationStatusAccepted {
		t.Errorf("invitation not accepted")
	}
	if len(res.MaterializedTuples) < 1 {
		t.Errorf("no materialized tuples")
	}

	// Cannot accept twice.
	if _, err := s.AcceptInvitation(inv.ID, AcceptInvitationOptions{AsUsrID: &asUsr, AcceptingIdentifier: &right}); err == nil {
		t.Error("second AcceptInvitation should reject")
	}
}

func TestInMemTransferOwnership(t *testing.T) {
	s := NewInMemoryTenancyStore()
	owner := "usr_0190f2a81b3c7abc8123456789abcdef"
	other := "usr_0190f2a81b3c7abc8123456789aaaaaa"
	r, _ := s.CreateOrg(owner, CreateOrgOptions{})
	mem, _ := s.AddMember(r.Org.ID, other, RoleAdmin, nil)

	result, err := s.TransferOwnership(r.Org.ID, r.OwnerMembership.ID, mem.ID)
	if err != nil {
		t.Fatalf("TransferOwnership: %v", err)
	}
	if result.ToMembership.Role != RoleOwner {
		t.Errorf("to role = %q", result.ToMembership.Role)
	}
	if result.FromMembership.Role != RoleMember {
		t.Errorf("from role = %q", result.FromMembership.Role)
	}
}
