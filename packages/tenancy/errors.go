// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package tenancy

import "errors"

// Error is the base type for every tenancy-layer error.
type Error struct {
	Msg  string
	Code string
}

func (e *Error) Error() string { return e.Msg }

func ErrorCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

var (
	ErrNotFound                  = &Error{Msg: "not found", Code: "not_found"}
	ErrDuplicateMembership       = &Error{Msg: "user already has an active membership in this org", Code: "conflict.duplicate_membership"}
	ErrOrgSlugConflict           = &Error{Msg: "org slug already in use", Code: "conflict.slug_taken"}
	ErrSoleOwner                 = &Error{Msg: "cannot remove the sole owner of an org", Code: "precondition.sole_owner"}
	ErrAlreadyTerminal           = &Error{Msg: "entity is already in a terminal state", Code: "already_terminal"}
	ErrInvitationNotPending      = &Error{Msg: "invitation is not in pending state", Code: "invitation_not_pending"}
	ErrInvitationExpired         = &Error{Msg: "invitation expired", Code: "invitation_expired"}
	ErrForbidden                 = &Error{Msg: "forbidden", Code: "forbidden"}
	ErrIdentifierBindingRequired = &Error{Msg: "accepting_identifier is required when as_usr_id is provided (ADR 0009)", Code: "identifier_binding_required"}
	ErrIdentifierMismatch        = &Error{Msg: "accepting_identifier does not match invitation.identifier (ADR 0009)", Code: "identifier_mismatch"}
	ErrRoleHierarchy             = &Error{Msg: "admin role hierarchy violated", Code: "precondition.role_hierarchy"}
)

// PreconditionError is raised when a precondition fails.
type PreconditionError struct {
	Msg    string
	Reason string
}

func (e *PreconditionError) Error() string { return e.Msg }
func (e *PreconditionError) Code() string  { return "precondition." + e.Reason }

// IsNotFound reports whether err is or wraps ErrNotFound.
func IsNotFound(err error) bool { return errors.Is(err, ErrNotFound) }

// IsOrgSlugConflict reports whether err is or wraps ErrOrgSlugConflict.
func IsOrgSlugConflict(err error) bool { return errors.Is(err, ErrOrgSlugConflict) }

// IsDuplicateMembership reports whether err is or wraps ErrDuplicateMembership.
func IsDuplicateMembership(err error) bool { return errors.Is(err, ErrDuplicateMembership) }
