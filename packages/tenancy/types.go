// Package tenancy provides the Flametrench tenancy layer in Go.
//
// Organizations, memberships, invitations, and the revoke-and-re-add
// lifecycle (ADR 0005). Mirrors flametrench-tenancy (Python) and
// @flametrench/tenancy (Node); the cross-SDK conformance fixture
// corpus at github.com/flametrench/spec gates every visible behavior.
//
// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
package tenancy

import "time"

// Role is one of the six built-in relations registered in Flametrench v0.1.
type Role string

const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
	RoleGuest  Role = "guest"
	RoleViewer Role = "viewer"
	RoleEditor Role = "editor"
)

// AdminRank returns the admin-hierarchy rank used by the admin_remove
// precondition. Higher rank removes lower or equal rank. Viewer / editor
// are object-scoped and do not participate; they return 0.
func (r Role) AdminRank() int {
	switch r {
	case RoleOwner:
		return 4
	case RoleAdmin:
		return 3
	case RoleMember:
		return 2
	case RoleGuest:
		return 1
	}
	return 0
}

// Status is the lifecycle status shared by organizations and memberships.
type Status string

const (
	StatusActive    Status = "active"
	StatusSuspended Status = "suspended"
	StatusRevoked   Status = "revoked"
)

// InvitationStatus is the five-state invitation lifecycle. Pending is
// the only non-terminal state.
type InvitationStatus string

const (
	InvitationStatusPending  InvitationStatus = "pending"
	InvitationStatusAccepted InvitationStatus = "accepted"
	InvitationStatusDeclined InvitationStatus = "declined"
	InvitationStatusRevoked  InvitationStatus = "revoked"
	InvitationStatusExpired  InvitationStatus = "expired"
)

// Organization is the team / workspace entity.
type Organization struct {
	ID        string
	Status    Status
	CreatedAt time.Time
	UpdatedAt time.Time
	Name      *string // v0.2 (ADR 0011)
	Slug      *string // v0.2 (ADR 0011)
}

// WithStatus returns a copy with status + updated_at replaced.
func (o Organization) WithStatus(s Status, at time.Time) Organization {
	o.Status = s
	o.UpdatedAt = at
	return o
}

// Membership is a user's role in an org. The replaces chain implements
// ADR 0005 revoke-and-re-add lifecycle.
type Membership struct {
	ID         string
	UsrID      string
	OrgID      string
	Role       Role
	Status     Status
	Replaces   *string
	InvitedBy  *string
	RemovedBy  *string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// Tuple is an authorization tuple. In v0.1+ all `subject_type` is
// "usr"; v0.3 ADR 0017 relaxes this to ^[a-z]{2,6}$ for `tuple_to_userset`
// rule eval.
type Tuple struct {
	SubjectType string
	SubjectID   string
	Relation    string
	ObjectType  string
	ObjectID    string
}

// PreTuple is a resource-scoped grant pre-declared on an invitation.
// Materialized as a tup_ row at accept time with the accepting user as
// the subject.
type PreTuple struct {
	Relation   string
	ObjectType string
	ObjectID   string
}

// Invitation tracks a pending or terminal invitation to an org.
type Invitation struct {
	ID            string
	OrgID         string
	Identifier    string
	Role          Role
	Status        InvitationStatus
	PreTuples     []PreTuple
	InvitedBy     string
	InvitedUserID *string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	TerminalAt    *time.Time
	TerminalBy    *string
}

// Page is a cursor-paginated result page.
type Page[T any] struct {
	Data       []T
	NextCursor *string
}

// CreateOrgResult is the output of TenancyStore.CreateOrg.
type CreateOrgResult struct {
	Org             Organization
	OwnerMembership Membership
}

// TransferOwnershipResult is the output of TenancyStore.TransferOwnership.
type TransferOwnershipResult struct {
	FromMembership Membership
	ToMembership   Membership
}

// AcceptInvitationResult is the output of TenancyStore.AcceptInvitation.
type AcceptInvitationResult struct {
	Invitation         Invitation
	Membership         Membership
	MaterializedTuples []Tuple
}

// UpdateOrgInput is the partial-update payload for TenancyStore.UpdateOrg.
type UpdateOrgInput struct {
	Name      *string
	Slug      *string
	ClearName bool
	ClearSlug bool
}
