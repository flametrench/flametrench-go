// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"regexp"
	"time"
)

// PatStatus is the lifecycle state of a personal access token.
//
//   - PatStatusActive   — present, not expired, not revoked.
//   - PatStatusExpired  — past expires_at. Terminal.
//   - PatStatusRevoked  — RevokePat called. Terminal.
//
// A PAT cannot return to active once it leaves it; re-issuance creates
// a new pat row, NOT a replaces-chain entry.
type PatStatus string

const (
	PatStatusActive  PatStatus = "active"
	PatStatusExpired PatStatus = "expired"
	PatStatusRevoked PatStatus = "revoked"
)

// PersonalAccessToken is the server-persisted PAT record. The secret
// hash is never returned to callers — only metadata. To obtain the
// plaintext token call IdentityStore.CreatePat; thereafter only the
// owner's local copy holds the secret.
type PersonalAccessToken struct {
	ID         string
	UsrID      string
	Name       string    // Human-readable label; 1–120 chars.
	Scope      []string  // App-defined scope claims; may be empty.
	Status     PatStatus
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// VerifiedPat is the success outcome of IdentityStore.VerifyPatToken.
// Carries only the fields a request-handling middleware needs to
// populate audit + authz context.
type VerifiedPat struct {
	PatID string
	UsrID string
	Scope []string
}

// CreatePatInput is the request payload for IdentityStore.CreatePat.
type CreatePatInput struct {
	UsrID     string
	Name      string
	Scope     []string
	ExpiresAt *time.Time
}

// CreatePatResult is the success outcome of IdentityStore.CreatePat.
// Token is the plaintext bearer — the only chance to capture it.
type CreatePatResult struct {
	Pat   PersonalAccessToken
	Token string
}

// PatMaxLifetimeSeconds is the spec-floor cap on PAT expires_at (ADR
// 0016 §"Constraints"). When set, ExpiresAt MUST be ≤ CreatedAt + this.
// 365 days = 31_536_000 seconds.
const PatMaxLifetimeSeconds = 365 * 24 * 60 * 60

// PatMaxSecretLength is the pre-rejection cap on the secret-segment
// length before the SDK invokes Argon2id (security-audit-v0.3.md H6).
// Real PAT secrets are 43 chars (32 random bytes base64url-encoded);
// 256 leaves a generous margin while bounding the DoS attack surface.
const PatMaxSecretLength = 256

// PatDummyPHCHash is the canonical dummy Argon2id PHC string used by
// VerifyPatToken on the missing-row path so the wall-clock time of "no
// such pat_id" is indistinguishable from "row exists but wrong secret"
// (security-audit-v0.3.md H2).
//
// The hash verifies against the plaintext "correcthorsebatterystaple"
// at the spec floor parameters (m=19456, t=2, p=1). Conformance fixture
// at spec/conformance/fixtures/identity/argon2id.json pins this value.
const PatDummyPHCHash = "$argon2id$v=19$m=19456,t=2,p=1$" +
	"779z4UHkLWR4w0TEo9gcHg$" +
	"Gz0+nGnpokhsKi1cPlx8i74FBN1Nq0OURZ3xso1AHMU"

// patWireFormat matches the canonical PAT bearer shape per ADR 0016
// §"Wire format": pat_<32-hex-id>_<base64url-secret>.
var patWireFormat = regexp.MustCompile(`^pat_[0-9a-f]{32}_[A-Za-z0-9_-]+$`)

// IsStructurallyValidPatToken is a pure structural check per ADR 0016
// §"Wire format". Returns true iff token matches
// pat_<32hex>_<base64url>. Does NOT hit the database or Argon2id
// verifier — adopters that pre-screen bearers before dispatch can use
// this to short-circuit obviously-bogus PATs.
func IsStructurallyValidPatToken(token string) bool {
	return patWireFormat.MatchString(token)
}

// AuthKind is the audit `auth.kind` discriminator per ADR 0016
// §"Bearer routing". Adopters writing system / cron jobs use
// AuthKindSystem; the bearer dispatcher / verifiers populate the other
// three.
//
// Pre-fix this discriminator lived only in spec prose with no SDK
// constant; F3 in the v0.3 audit centralized the values so adopters
// can use AuthKindSystem instead of stringly-typing through their
// audit pipeline.
type AuthKind string

const (
	AuthKindPat     AuthKind = "pat"
	AuthKindShare   AuthKind = "share"
	AuthKindSession AuthKind = "session"
	AuthKindSystem  AuthKind = "system"
)

// ClassifyBearer is a pure prefix classifier per ADR 0016 §"Bearer
// routing". Returns the auth.kind discriminator without invoking any
// verifier or DB lookup. The cross-SDK conformance contract — see
// spec/conformance/fixtures/identity/pat/bearer-prefix-routing.json —
// pins the rules every SDK MUST produce identically.
func ClassifyBearer(token string) AuthKind {
	switch {
	case len(token) >= 4 && token[:4] == "pat_":
		return AuthKindPat
	case len(token) >= 4 && token[:4] == "shr_":
		return AuthKindShare
	default:
		return AuthKindSession
	}
}
