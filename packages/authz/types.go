// Package authz provides the Flametrench authorization layer in Go.
//
// Relational tuples + exact-match check() with optional rewrite rules
// (v0.2 ADR 0007), share tokens (v0.2 ADR 0012), and Postgres-backed
// rule evaluation (v0.3 ADR 0017). Cross-SDK conformance fixture
// corpus at github.com/flametrench/spec gates every visible behavior.
//
// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
package authz

import "time"

// Tuple is the sole authz primitive. Natural key is
// (subject_type, subject_id, relation, object_type, object_id).
type Tuple struct {
	ID          string
	SubjectType string
	SubjectID   string
	Relation    string
	ObjectType  string
	ObjectID    string
	CreatedAt   time.Time
	CreatedBy   *string
}

// CheckResult is the outcome of Check / CheckAny.
type CheckResult struct {
	Allowed         bool
	MatchedTupleID  *string
}

// Page is a cursor-paginated result page.
type Page[T any] struct {
	Data       []T
	NextCursor *string
}

// Share is the public share-token record. The SHA-256 token hash is
// internal; the plaintext bearer credential is returned ONCE on
// CreateShare and never re-exposed.
type Share struct {
	ID         string
	ObjectType string
	ObjectID   string
	Relation   string
	CreatedBy  string
	ExpiresAt  time.Time
	SingleUse  bool
	ConsumedAt *time.Time
	RevokedAt  *time.Time
	CreatedAt  time.Time
}

// CreateShareResult is returned by ShareStore.CreateShare. Token is the
// plaintext bearer — the only chance to capture it.
type CreateShareResult struct {
	Share Share
	Token string
}

// VerifiedShare is returned by ShareStore.VerifyShareToken on success.
// Enough information to render the resource at the given relation;
// NOT an authenticated principal.
type VerifiedShare struct {
	ShareID    string
	ObjectType string
	ObjectID   string
	Relation   string
}

// ShareMaxTTLSeconds is the spec-mandated upper bound on share
// lifetime: 365 days.
const ShareMaxTTLSeconds = 365 * 24 * 60 * 60
