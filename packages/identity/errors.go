// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
package identity

import (
	"errors"
	"fmt"
)

// Error is the base type for every identity-layer error. Code is a
// stable string matching the OpenAPI error envelope code field.
type Error struct {
	Msg  string
	Code string
}

func (e *Error) Error() string { return e.Msg }

// ErrorCode returns the stable code if err is or wraps an *Error.
// Returns "" otherwise.
func ErrorCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// Sentinel error constructors — return *Error values that satisfy the
// error interface and carry the stable code. Use `errors.Is(err,
// ErrNotFound)` for sentinel comparisons; the sentinel itself is the
// canonical instance.

var (
	ErrNotFound             = &Error{Msg: "not found", Code: "not_found"}
	ErrDuplicateCredential  = &Error{Msg: "credential already exists for that identifier", Code: "conflict.duplicate_credential"}
	ErrInvalidCredential    = &Error{Msg: "invalid credential", Code: "invalid_credential"}
	ErrInvalidToken         = &Error{Msg: "invalid token", Code: "invalid_token"}
	ErrSessionExpired       = &Error{Msg: "session expired", Code: "session_expired"}
	ErrCredentialNotActive  = &Error{Msg: "credential is not active", Code: "cred_not_active"}
	ErrCredentialTypeMismatch = &Error{Msg: "credential type mismatch", Code: "cred_type_mismatch"}
	ErrAlreadyTerminal      = &Error{Msg: "entity is already in a terminal state", Code: "already_terminal"}
	ErrInvalidPatToken      = &Error{Msg: "invalid personal access token", Code: "pat.invalid"}
)

// PreconditionError is raised when a precondition fails. Reason
// disambiguates (e.g. "user_not_active", "invalid_transition").
type PreconditionError struct {
	Msg    string
	Reason string
}

func (e *PreconditionError) Error() string { return e.Msg }
func (e *PreconditionError) Unwrap() error { return &Error{Msg: e.Msg, Code: "precondition." + e.Reason} }

// PatExpiredError is raised by VerifyPatToken when a pat row exists,
// has not been revoked, but is past its expires_at (ADR 0016).
type PatExpiredError struct{ PatID string }

func (e *PatExpiredError) Error() string {
	return fmt.Sprintf("personal access token %s is expired", e.PatID)
}
func (e *PatExpiredError) Code() string { return "pat.expired" }

// PatRevokedError is raised by VerifyPatToken when a pat row has been
// explicitly revoked via RevokePat (ADR 0016). Terminal.
type PatRevokedError struct{ PatID string }

func (e *PatRevokedError) Error() string {
	return fmt.Sprintf("personal access token %s is revoked", e.PatID)
}
func (e *PatRevokedError) Code() string { return "pat.revoked" }

// IsInvalidPatToken returns true if err is or wraps ErrInvalidPatToken.
// Use this in HTTP middleware to map the missing-row + wrong-secret
// conflated case (ADR 0016 §"Verification semantics") to 401.
func IsInvalidPatToken(err error) bool {
	return errors.Is(err, ErrInvalidPatToken)
}

// IsNotFound reports whether err is or wraps ErrNotFound.
func IsNotFound(err error) bool { return errors.Is(err, ErrNotFound) }

// IsDuplicateCredential reports whether err is or wraps ErrDuplicateCredential.
func IsDuplicateCredential(err error) bool { return errors.Is(err, ErrDuplicateCredential) }
