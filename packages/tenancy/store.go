// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package tenancy

import "time"

// TenancyStore is the contract every tenancy backend implements.
//
// Atomicity guarantees per the Flametrench v0.1 specification:
//
//   - ChangeRole updates the old mem, inserts a new mem, deletes the
//     old tuple, inserts the new tuple — all in one transaction.
//   - AcceptInvitation creates a user if needed, inserts mem, inserts
//     the membership tuple, expands pre_tuples into tuples, transitions
//     the invitation — all in one transaction.
//   - TransferOwnership demotes the old owner's mem, promotes the
//     target, swaps both tuples — one transaction.
type TenancyStore interface {
	// ─── Organizations ───

	CreateOrg(creator string, opts CreateOrgOptions) (CreateOrgResult, error)
	GetOrg(orgID string) (Organization, error)
	UpdateOrg(orgID string, in UpdateOrgInput) (Organization, error)
	SuspendOrg(orgID string) (Organization, error)
	ReinstateOrg(orgID string) (Organization, error)
	RevokeOrg(orgID string) (Organization, error)
	ListOrgs(opts ListOrgsOptions) (Page[Organization], error) // ADR 0025

	// ─── Memberships ───

	AddMember(orgID, usrID string, role Role, invitedBy *string) (Membership, error)
	GetMembership(memID string) (Membership, error)
	ListMembers(orgID string, opts ListMembersOptions) (Page[Membership], error)
	ChangeRole(memID string, newRole Role) (Membership, error)
	SuspendMembership(memID string) (Membership, error)
	ReinstateMembership(memID string) (Membership, error)
	SelfLeave(memID string, transferTo *string) (Membership, error)
	AdminRemove(memID, adminUsrID string) (Membership, error)
	TransferOwnership(orgID, fromMemID, toMemID string) (TransferOwnershipResult, error)

	// ─── Invitations ───

	CreateInvitation(orgID, identifier string, role Role, invitedBy string, expiresAt time.Time, preTuples []PreTuple) (Invitation, error)
	GetInvitation(invID string) (Invitation, error)
	ListInvitations(orgID string, opts ListInvitationsOptions) (Page[Invitation], error)
	AcceptInvitation(invID string, opts AcceptInvitationOptions) (AcceptInvitationResult, error)
	DeclineInvitation(invID string, asUsrID *string) (Invitation, error)
	RevokeInvitation(invID, adminUsrID string) (Invitation, error)

	// ─── Tuple accessors ───

	ListTuplesForSubject(subjectType, subjectID string) ([]Tuple, error)
	ListTuplesForObject(objectType, objectID string, relation *string) ([]Tuple, error)
}

// CreateOrgOptions carries optional metadata fields for CreateOrg.
type CreateOrgOptions struct {
	Name *string
	Slug *string
}

// ListMembersOptions is the input to TenancyStore.ListMembers.
type ListMembersOptions struct {
	Cursor *string
	Limit  int
	Status *Status
}

// ListInvitationsOptions is the input to TenancyStore.ListInvitations.
type ListInvitationsOptions struct {
	Cursor *string
	Limit  int
	Status *InvitationStatus
}

// AcceptInvitationOptions carries the ADR 0009 binding fields. If
// AsUsrID is non-nil, AcceptingIdentifier MUST also be non-nil and the
// SDK enforces byte-equality with the invitation's identifier.
type AcceptInvitationOptions struct {
	AsUsrID             *string
	AcceptingIdentifier *string
}

// ListOrgsOptions is the input to TenancyStore.ListOrgs (ADR 0025).
type ListOrgsOptions struct {
	Cursor *string
	Limit  int
	Query  *string // case-insensitive substring over org name or slug
	Status *Status // org-status filter; nil = all statuses
}
