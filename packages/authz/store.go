// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
package authz

// TupleStore is the contract every tuple backend implements.
//
// Exact-match semantics by default: Check returns true iff a tuple
// with the exact 5-tuple key exists. No derivation, no inheritance, no
// group expansion. Rewrite rules (ADR 0007 / 0017) are opt-in via a
// constructor-time `rules` parameter; absent rules, Check is byte-
// identical to v0.1 semantics.
type TupleStore interface {
	CreateTuple(in CreateTupleInput) (Tuple, error)
	DeleteTuple(tupleID string) error
	CascadeRevokeSubject(subjectType, subjectID string) (int, error)

	Check(in CheckInput) (CheckResult, error)
	CheckAny(in CheckAnyInput) (CheckResult, error)

	GetTuple(tupleID string) (Tuple, error)
	ListTuplesBySubject(subjectType, subjectID string, opts ListTuplesOptions) (Page[Tuple], error)
	ListTuplesByObject(objectType, objectID string, opts ListByObjectOptions) (Page[Tuple], error)
}

// CreateTupleInput is the input to TupleStore.CreateTuple.
type CreateTupleInput struct {
	SubjectType string
	SubjectID   string
	Relation    string
	ObjectType  string
	ObjectID    string
	CreatedBy   *string
}

// CheckInput is the input to TupleStore.Check.
type CheckInput struct {
	SubjectType string
	SubjectID   string
	Relation    string
	ObjectType  string
	ObjectID    string
}

// CheckAnyInput is the input to TupleStore.CheckAny.
type CheckAnyInput struct {
	SubjectType string
	SubjectID   string
	Relations   []string
	ObjectType  string
	ObjectID    string
}

// ListTuplesOptions is the input to TupleStore.ListTuplesBySubject.
type ListTuplesOptions struct {
	Cursor *string
	Limit  int
}

// ListByObjectOptions is the input to TupleStore.ListTuplesByObject.
type ListByObjectOptions struct {
	Cursor   *string
	Limit    int
	Relation *string
}

// ShareStore is the contract every share-token backend implements.
//
// Verification ordering is normative (per ADR 0012):
//
//  1. Hash input via SHA-256.
//  2. Look up by token_hash; missing → ErrInvalidShareToken.
//  3. Constant-time-compare; mismatch → ErrInvalidShareToken.
//  4. revoked_at non-nil → ErrShareRevoked.
//  5. single_use && consumed_at non-nil → ErrShareConsumed.
//  6. expires_at <= now → ErrShareExpired.
//  7. If single_use: transactionally set consumed_at = now.
type ShareStore interface {
	CreateShare(in CreateShareInput) (CreateShareResult, error)
	GetShare(shareID string) (Share, error)
	VerifyShareToken(token string) (VerifiedShare, error)
	RevokeShare(shareID string) (Share, error)
	ListSharesForObject(objectType, objectID string, opts ListSharesOptions) (Page[Share], error)
}

// CreateShareInput is the input to ShareStore.CreateShare.
type CreateShareInput struct {
	ObjectType        string
	ObjectID          string
	Relation          string
	CreatedBy         string
	ExpiresInSeconds  int
	SingleUse         bool
}

// ListSharesOptions is the input to ShareStore.ListSharesForObject.
type ListSharesOptions struct {
	Cursor *string
	Limit  int
}
