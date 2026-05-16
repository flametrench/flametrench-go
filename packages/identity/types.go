// Package identity provides the Flametrench identity layer in Go.
//
// Users, credentials (password / passkey / OIDC + v0.2 MFA factors),
// user-bound sessions with rotation on refresh, and v0.3 personal
// access tokens. Mirrors flametrench-identity (Python) and
// @flametrench/identity (Node); the cross-SDK conformance fixture
// corpus at github.com/flametrench/spec gates every visible behavior.
//
// Argon2id is pinned at the OWASP floor (m=19456 KiB, t=2, p=1).
// PHC-encoded hashes produced by this SDK verify identically under
// the Node, PHP, Python, and Java SDKs.
//
// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
package identity

import "time"

// Status is the lifecycle status of a user or credential entity.
type Status string

const (
	StatusActive    Status = "active"
	StatusSuspended Status = "suspended"
	StatusRevoked   Status = "revoked"
)

// CredentialType discriminates the three credential variants supported in v0.1.
type CredentialType string

const (
	CredentialTypePassword CredentialType = "password"
	CredentialTypePasskey  CredentialType = "passkey"
	CredentialTypeOIDC     CredentialType = "oidc"
)

// Argon2idFloor is the minimum Argon2id parameter set every SDK MUST
// use for password hashing. See `spec/docs/identity.md` §"Hashing
// requirements" and ADR 0004.
var Argon2idFloor = struct {
	MemoryKiB   uint32
	TimeCost    uint32
	Parallelism uint8
}{
	MemoryKiB:   19456, // 19 MiB
	TimeCost:    2,
	Parallelism: 1,
}

// User is the principal entity. ID is wire-format (`usr_<32hex>`).
type User struct {
	ID          string
	Status      Status
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DisplayName *string // ADR 0014 (v0.2)
}

// WithStatus returns a copy of u with status + updated_at replaced.
func (u User) WithStatus(s Status, updatedAt time.Time) User {
	u.Status = s
	u.UpdatedAt = updatedAt
	return u
}

// Credential is the union of the three credential variants. Use the
// Type field to discriminate; the variant-specific fields are populated
// on the relevant Credential method paths.
//
// The Go SDK collapses Python's separate PasswordCredential /
// PasskeyCredential / OidcCredential dataclasses into a tagged union.
// Variant-specific fields are zero when not applicable; the Type field
// is the source of truth.
type Credential struct {
	ID         string
	UsrID      string
	Type       CredentialType
	Identifier string
	Status     Status
	Replaces   *string
	CreatedAt  time.Time
	UpdatedAt  time.Time

	// Passkey-specific (zero when Type != Passkey).
	PasskeySignCount int64
	PasskeyRPID      string

	// OIDC-specific (zero when Type != OIDC).
	OIDCIssuer  string
	OIDCSubject string
}

// Session is a user-bound bearer record. The opaque bearer token is
// SessionWithToken.Token at creation/refresh; afterwards only its
// SHA-256 hash is persisted.
type Session struct {
	ID        string
	UsrID     string
	CredID    string
	CreatedAt time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
}

// WithRevokedAt returns a copy of s with revoked_at set.
func (s Session) WithRevokedAt(at time.Time) Session {
	s.RevokedAt = &at
	return s
}

// SessionWithToken is returned by CreateSession / RefreshSession. Token
// is the opaque bearer credential — the only chance to capture it.
type SessionWithToken struct {
	Session Session
	Token   string
}

// VerifiedCredential is the success outcome of VerifyPassword. When
// MfaRequired is true, the application MUST call VerifyMfa before
// CreateSession (ADR 0008).
type VerifiedCredential struct {
	UsrID       string
	CredID      string
	MfaRequired bool
}

// Page is a cursor-paginated result page (ADR 0015).
type Page[T any] struct {
	Data       []T
	NextCursor *string
}

// UpdateUserInput carries optional updates to a user record. ADR 0014
// partial-update semantics: nil means "do not change"; a non-nil value
// is applied (use SetDisplayNameToNull for the explicit nullification
// case).
type UpdateUserInput struct {
	DisplayName       *string
	ClearDisplayName  bool // set true to NULL the display_name column
}
