// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package identity

import "time"

// IdentityStore is the contract every identity backend implements.
//
// Cascade guarantees (spec-required):
//
//   - Revoking a user revokes every active credential AND terminates
//     every active session.
//   - Suspending a user terminates active sessions but preserves credentials.
//   - Rotating a credential terminates every session bound to the old one.
//   - Revoking or suspending a credential terminates every session bound to it.
type IdentityStore interface {
	// ─── Users ───

	CreateUser(displayName *string) (User, error)
	GetUser(usrID string) (User, error)
	UpdateUser(usrID string, in UpdateUserInput) (User, error)
	ListUsers(opts ListUsersOptions) (Page[User], error)
	SuspendUser(usrID string) (User, error)
	ReinstateUser(usrID string) (User, error)
	RevokeUser(usrID string) (User, error)

	// ─── Credentials ───

	CreatePasswordCredential(usrID, identifier, password string) (Credential, error)
	CreatePasskeyCredential(usrID, identifier string, publicKey []byte, signCount int64, rpID string) (Credential, error)
	CreateOIDCCredential(usrID, identifier, issuer, subject string) (Credential, error)

	GetCredential(credID string) (Credential, error)
	ListCredentialsForUser(usrID string) ([]Credential, error)
	FindCredentialByIdentifier(t CredentialType, identifier string) (*Credential, error)

	RotatePassword(credID, newPassword string) (Credential, error)
	RotatePasskey(credID string, publicKey []byte, signCount int64, rpID string) (Credential, error)
	RotateOIDC(credID, issuer, subject string) (Credential, error)

	SuspendCredential(credID string) (Credential, error)
	ReinstateCredential(credID string) (Credential, error)
	RevokeCredential(credID string) (Credential, error)

	VerifyPassword(identifier, password string) (VerifiedCredential, error)

	// ─── Sessions ───

	CreateSession(usrID, credID string, ttlSeconds int) (SessionWithToken, error)
	GetSession(sesID string) (Session, error)
	ListSessionsForUser(usrID string, opts ListSessionsOptions) (Page[Session], error)
	VerifySessionToken(token string) (Session, error)
	RefreshSession(sesID string) (SessionWithToken, error)
	RevokeSession(sesID string) (Session, error)

	// ─── Multi-factor authentication (v0.2, ADR 0008) ───

	EnrollTotpFactor(usrID, label string, opts TotpComputeOptions) (TotpEnrollmentResult, error)
	EnrollWebAuthnFactor(usrID, credentialID string, publicKey []byte, signCount int64, rpID string) (WebAuthnEnrollmentResult, error)
	EnrollRecoveryFactor(usrID string) (RecoveryEnrollmentResult, error)

	ConfirmTotpFactor(mfaID, code string) (Factor, error)
	ConfirmWebAuthnFactor(mfaID string, proof WebAuthnProof) (Factor, error)

	GetFactor(mfaID string) (Factor, error)
	ListFactorsForUser(usrID string) ([]Factor, error)
	SuspendFactor(mfaID string) (Factor, error)
	ReinstateFactor(mfaID string) (Factor, error)
	RevokeFactor(mfaID string) (Factor, error)

	VerifyMfa(usrID string, proof MfaProof) (MfaVerifyResult, error)

	GetUserMfaPolicy(usrID string) (UserMfaPolicy, error)
	SetUserMfaPolicy(usrID string, required bool, graceUntil *time.Time) (UserMfaPolicy, error)

	// ─── Personal access tokens (v0.3, ADR 0016) ───

	CreatePat(in CreatePatInput) (CreatePatResult, error)
	GetPat(patID string) (PersonalAccessToken, error)
	ListPatsForUser(usrID string, opts ListPatsOptions) (Page[PersonalAccessToken], error)
	VerifyPatToken(token string) (VerifiedPat, error)
	RevokePat(patID string) (PersonalAccessToken, error)
}

// ListUsersOptions is the input to IdentityStore.ListUsers (ADR 0015).
type ListUsersOptions struct {
	Cursor *string
	Limit  int
	Query  *string // case-insensitive credential-identifier substring filter
	Status *Status // user-status filter
}

// ListSessionsOptions is the input to IdentityStore.ListSessionsForUser.
type ListSessionsOptions struct {
	Cursor *string
	Limit  int
}

// ListPatsOptions is the input to IdentityStore.ListPatsForUser.
type ListPatsOptions struct {
	Cursor *string
	Limit  int
}
