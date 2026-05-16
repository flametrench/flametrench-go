// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
package authz

import "errors"

// Error is the base type for every authz-layer error.
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
	ErrTupleNotFound      = &Error{Msg: "tuple not found", Code: "not_found"}
	ErrDuplicateTuple     = &Error{Msg: "tuple already exists", Code: "conflict.duplicate_tuple"}
	ErrEmptyRelationSet   = &Error{Msg: "relations list is empty", Code: "invalid_request.empty_relation_set"}
	ErrInvalidFormat      = &Error{Msg: "invalid format", Code: "invalid_format"}
	ErrShareNotFound      = &Error{Msg: "share not found", Code: "share.not_found"}
	ErrInvalidShareToken  = &Error{Msg: "invalid share token", Code: "share.invalid_token"}
	ErrShareExpired       = &Error{Msg: "share expired", Code: "share.expired"}
	ErrShareRevoked       = &Error{Msg: "share revoked", Code: "share.revoked"}
	ErrShareConsumed      = &Error{Msg: "share already consumed", Code: "share.consumed"}
	ErrEvaluationLimit    = &Error{Msg: "rewrite-rule evaluation limit exceeded", Code: "authz.evaluation_limit"}
)

// IsTupleNotFound reports whether err is or wraps ErrTupleNotFound.
func IsTupleNotFound(err error) bool { return errors.Is(err, ErrTupleNotFound) }

// IsDuplicateTuple reports whether err is or wraps ErrDuplicateTuple.
func IsDuplicateTuple(err error) bool { return errors.Is(err, ErrDuplicateTuple) }

// IsInvalidShareToken reports whether err is or wraps any of the share-
// token failure modes that legitimately collapse to a 401 unauthorized.
func IsInvalidShareToken(err error) bool {
	return errors.Is(err, ErrInvalidShareToken) ||
		errors.Is(err, ErrShareNotFound) ||
		errors.Is(err, ErrShareExpired) ||
		errors.Is(err, ErrShareRevoked) ||
		errors.Is(err, ErrShareConsumed)
}
