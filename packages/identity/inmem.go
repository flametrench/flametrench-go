// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

// InMemoryIdentityStore — reference in-memory implementation of the
// IdentityStore interface. Mirrors the Python and Node reference
// implementations behavior-for-behavior; the conformance fixture corpus
// at github.com/flametrench/spec gates every visible behavior.
//
// This file is the spec-correctness reference; PostgresIdentityStore
// (postgres.go) mirrors it operation-for-operation against a real DB.

package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	flametrenchids "github.com/flametrench/flametrench-go/packages/ids"
)

// Compile-time guarantee: InMemoryIdentityStore satisfies IdentityStore.
var _ IdentityStore = (*InMemoryIdentityStore)(nil)

// InMemoryIdentityStore is the reference in-memory implementation of
// the spec contract. Safe for concurrent use.
type InMemoryIdentityStore struct {
	mu sync.Mutex

	clock                       func() time.Time
	patLastUsedCoalesceSeconds  int

	// users / credentials / sessions
	users               map[string]User
	credentials         map[string]Credential
	passwordHashes      map[string]string // cred_id → PHC
	passkeyPublicKeys   map[string][]byte
	activeCredByIdent   map[string]string // "type|identifier" → cred_id (active only)
	sessions            map[string]Session
	sessionTokenHash    map[string]string // ses_id → sha256 hex
	sessionByTokenHash  map[string]string // sha256 hex → ses_id

	// MFA
	factors                map[string]Factor
	totpSecrets            map[string][]byte    // mfa_id → raw secret
	webauthnPublicKeys     map[string][]byte    // mfa_id → COSE pubkey
	recoveryHashes         map[string][]string  // mfa_id → 10 PHC hashes
	recoveryConsumed       map[string][]bool    // parallel array
	mfaSingleton           map[string]string    // "usr|type" → mfa_id (singleton totp/recovery)
	mfaPolicies            map[string]UserMfaPolicy

	// PATs
	pats               map[string]PersonalAccessToken
	patSecretHashes    map[string]string // pat_id → PHC
	patLastUsedPersist map[string]time.Time
}

// NewInMemoryIdentityStore returns a fresh in-memory identity store.
func NewInMemoryIdentityStore() *InMemoryIdentityStore {
	return &InMemoryIdentityStore{
		clock:                      func() time.Time { return time.Now().UTC() },
		patLastUsedCoalesceSeconds: 60,
		users:                      map[string]User{},
		credentials:                map[string]Credential{},
		passwordHashes:             map[string]string{},
		passkeyPublicKeys:          map[string][]byte{},
		activeCredByIdent:          map[string]string{},
		sessions:                   map[string]Session{},
		sessionTokenHash:           map[string]string{},
		sessionByTokenHash:         map[string]string{},
		factors:                    map[string]Factor{},
		totpSecrets:                map[string][]byte{},
		webauthnPublicKeys:         map[string][]byte{},
		recoveryHashes:             map[string][]string{},
		recoveryConsumed:           map[string][]bool{},
		mfaSingleton:               map[string]string{},
		mfaPolicies:                map[string]UserMfaPolicy{},
		pats:                       map[string]PersonalAccessToken{},
		patSecretHashes:            map[string]string{},
		patLastUsedPersist:         map[string]time.Time{},
	}
}

// WithClock overrides the default UTC-now clock. Useful for tests +
// conformance fixtures that pin timestamps.
func (s *InMemoryIdentityStore) WithClock(clock func() time.Time) *InMemoryIdentityStore {
	s.clock = clock
	return s
}

// ─── Helpers ───

func (s *InMemoryIdentityStore) now() time.Time { return s.clock() }

func identKey(t CredentialType, identifier string) string {
	return string(t) + "|" + identifier
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func newOpaqueToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ─── Users ───

func (s *InMemoryIdentityStore) CreateUser(displayName *string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, err := flametrenchids.Generate("usr")
	if err != nil {
		return User{}, err
	}
	now := s.now()
	u := User{
		ID:          id,
		Status:      StatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
		DisplayName: displayName,
	}
	s.users[id] = u
	return u, nil
}

func (s *InMemoryIdentityStore) GetUser(usrID string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[usrID]
	if !ok {
		return User{}, fmt.Errorf("user %s: %w", usrID, ErrNotFound)
	}
	return u, nil
}

func (s *InMemoryIdentityStore) UpdateUser(usrID string, in UpdateUserInput) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[usrID]
	if !ok {
		return User{}, fmt.Errorf("user %s: %w", usrID, ErrNotFound)
	}
	if in.ClearDisplayName {
		u.DisplayName = nil
	} else if in.DisplayName != nil {
		u.DisplayName = in.DisplayName
	}
	u.UpdatedAt = s.now()
	s.users[usrID] = u
	return u, nil
}

func (s *InMemoryIdentityStore) ListUsers(opts ListUsersOptions) (Page[User], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	// Gather matching users, sorted by created_at ASC then id.
	var queryLower string
	if opts.Query != nil {
		queryLower = strings.ToLower(*opts.Query)
	}
	matched := make([]User, 0)
	for _, u := range s.users {
		if opts.Status != nil && u.Status != *opts.Status {
			continue
		}
		if queryLower != "" {
			// Filter by any active credential identifier matching query.
			match := false
			for _, c := range s.credentials {
				if c.UsrID != u.ID || c.Status != StatusActive {
					continue
				}
				if strings.Contains(strings.ToLower(c.Identifier), queryLower) {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}
		matched = append(matched, u)
	}
	sortUsersStable(matched)
	// Cursor handling: cursor is the last user id of the previous page.
	startIdx := 0
	if opts.Cursor != nil && *opts.Cursor != "" {
		for i, u := range matched {
			if u.ID == *opts.Cursor {
				startIdx = i + 1
				break
			}
		}
	}
	end := startIdx + limit
	if end > len(matched) {
		end = len(matched)
	}
	data := matched[startIdx:end]
	var next *string
	if end < len(matched) && len(data) > 0 {
		c := data[len(data)-1].ID
		next = &c
	}
	return Page[User]{Data: data, NextCursor: next}, nil
}

func sortUsersStable(us []User) {
	// Bubble-sort by created_at ASC then id — small lists, simplicity over speed.
	n := len(us)
	for i := 1; i < n; i++ {
		for j := i; j > 0; j-- {
			if us[j].CreatedAt.Before(us[j-1].CreatedAt) ||
				(us[j].CreatedAt.Equal(us[j-1].CreatedAt) && us[j].ID < us[j-1].ID) {
				us[j-1], us[j] = us[j], us[j-1]
			} else {
				break
			}
		}
	}
}

func (s *InMemoryIdentityStore) SuspendUser(usrID string) (User, error) {
	return s.transitionUser(usrID, StatusSuspended)
}
func (s *InMemoryIdentityStore) ReinstateUser(usrID string) (User, error) {
	return s.transitionUser(usrID, StatusActive)
}
func (s *InMemoryIdentityStore) RevokeUser(usrID string) (User, error) {
	return s.transitionUser(usrID, StatusRevoked)
}

func (s *InMemoryIdentityStore) transitionUser(usrID string, to Status) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[usrID]
	if !ok {
		return User{}, fmt.Errorf("user %s: %w", usrID, ErrNotFound)
	}
	if u.Status == StatusRevoked {
		return User{}, fmt.Errorf("user %s is revoked: %w", usrID, ErrAlreadyTerminal)
	}
	if u.Status == to {
		return u, nil
	}
	if to == StatusActive && u.Status != StatusSuspended {
		return User{}, &PreconditionError{Msg: "user not suspended", Reason: "invalid_transition"}
	}
	u = u.WithStatus(to, s.now())
	s.users[usrID] = u
	if to == StatusSuspended || to == StatusRevoked {
		s.cascadeRevokeSessionsForUser(usrID)
	}
	if to == StatusRevoked {
		// Cascade revoke active credentials.
		for cid, c := range s.credentials {
			if c.UsrID == usrID && c.Status == StatusActive {
				c.Status = StatusRevoked
				c.UpdatedAt = s.now()
				s.credentials[cid] = c
				delete(s.activeCredByIdent, identKey(c.Type, c.Identifier))
			}
		}
	}
	return u, nil
}

func (s *InMemoryIdentityStore) cascadeRevokeSessionsForUser(usrID string) {
	now := s.now()
	for sid, ss := range s.sessions {
		if ss.UsrID == usrID && ss.RevokedAt == nil {
			ss.RevokedAt = &now
			s.sessions[sid] = ss
			if th, ok := s.sessionTokenHash[sid]; ok {
				delete(s.sessionTokenHash, sid)
				delete(s.sessionByTokenHash, th)
			}
		}
	}
}

func (s *InMemoryIdentityStore) cascadeRevokeSessionsForCredential(credID string) {
	now := s.now()
	for sid, ss := range s.sessions {
		if ss.CredID == credID && ss.RevokedAt == nil {
			ss.RevokedAt = &now
			s.sessions[sid] = ss
			if th, ok := s.sessionTokenHash[sid]; ok {
				delete(s.sessionTokenHash, sid)
				delete(s.sessionByTokenHash, th)
			}
		}
	}
}

// ─── Credentials ───

func (s *InMemoryIdentityStore) CreatePasswordCredential(usrID, identifier, password string) (Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[usrID]; !ok {
		return Credential{}, fmt.Errorf("user %s: %w", usrID, ErrNotFound)
	}
	if _, taken := s.activeCredByIdent[identKey(CredentialTypePassword, identifier)]; taken {
		return Credential{}, fmt.Errorf("password+%s: %w", identifier, ErrDuplicateCredential)
	}
	hash, err := HashPassword(password)
	if err != nil {
		return Credential{}, err
	}
	id, err := flametrenchids.Generate("cred")
	if err != nil {
		return Credential{}, err
	}
	now := s.now()
	c := Credential{
		ID: id, UsrID: usrID, Type: CredentialTypePassword,
		Identifier: identifier, Status: StatusActive,
		CreatedAt: now, UpdatedAt: now,
	}
	s.credentials[id] = c
	s.passwordHashes[id] = hash
	s.activeCredByIdent[identKey(CredentialTypePassword, identifier)] = id
	return c, nil
}

func (s *InMemoryIdentityStore) CreatePasskeyCredential(usrID, identifier string, publicKey []byte, signCount int64, rpID string) (Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[usrID]; !ok {
		return Credential{}, fmt.Errorf("user %s: %w", usrID, ErrNotFound)
	}
	if _, taken := s.activeCredByIdent[identKey(CredentialTypePasskey, identifier)]; taken {
		return Credential{}, fmt.Errorf("passkey+%s: %w", identifier, ErrDuplicateCredential)
	}
	id, err := flametrenchids.Generate("cred")
	if err != nil {
		return Credential{}, err
	}
	now := s.now()
	c := Credential{
		ID: id, UsrID: usrID, Type: CredentialTypePasskey,
		Identifier: identifier, Status: StatusActive,
		PasskeySignCount: signCount, PasskeyRPID: rpID,
		CreatedAt: now, UpdatedAt: now,
	}
	s.credentials[id] = c
	s.passkeyPublicKeys[id] = publicKey
	s.activeCredByIdent[identKey(CredentialTypePasskey, identifier)] = id
	return c, nil
}

func (s *InMemoryIdentityStore) CreateOIDCCredential(usrID, identifier, issuer, subject string) (Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[usrID]; !ok {
		return Credential{}, fmt.Errorf("user %s: %w", usrID, ErrNotFound)
	}
	if _, taken := s.activeCredByIdent[identKey(CredentialTypeOIDC, identifier)]; taken {
		return Credential{}, fmt.Errorf("oidc+%s: %w", identifier, ErrDuplicateCredential)
	}
	id, err := flametrenchids.Generate("cred")
	if err != nil {
		return Credential{}, err
	}
	now := s.now()
	c := Credential{
		ID: id, UsrID: usrID, Type: CredentialTypeOIDC,
		Identifier: identifier, Status: StatusActive,
		OIDCIssuer: issuer, OIDCSubject: subject,
		CreatedAt: now, UpdatedAt: now,
	}
	s.credentials[id] = c
	s.activeCredByIdent[identKey(CredentialTypeOIDC, identifier)] = id
	return c, nil
}

func (s *InMemoryIdentityStore) GetCredential(credID string) (Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.credentials[credID]
	if !ok {
		return Credential{}, fmt.Errorf("credential %s: %w", credID, ErrNotFound)
	}
	return c, nil
}

func (s *InMemoryIdentityStore) ListCredentialsForUser(usrID string) ([]Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[usrID]; !ok {
		return nil, fmt.Errorf("user %s: %w", usrID, ErrNotFound)
	}
	out := make([]Credential, 0)
	for _, c := range s.credentials {
		if c.UsrID == usrID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (s *InMemoryIdentityStore) FindCredentialByIdentifier(t CredentialType, identifier string) (*Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.activeCredByIdent[identKey(t, identifier)]
	if !ok {
		return nil, nil
	}
	c := s.credentials[id]
	return &c, nil
}

// rotate implements the revoke-and-re-add lifecycle pattern (ADR 0005)
// for credential rotation. The old credential is marked revoked with
// the new credential's ID in its Replaces chain.
func (s *InMemoryIdentityStore) rotate(credID string, mutate func(now time.Time, oldCred Credential) (Credential, error)) (Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.credentials[credID]
	if !ok {
		return Credential{}, fmt.Errorf("credential %s: %w", credID, ErrNotFound)
	}
	if old.Status != StatusActive {
		return Credential{}, fmt.Errorf("credential %s: %w", credID, ErrCredentialNotActive)
	}
	now := s.now()
	newCred, err := mutate(now, old)
	if err != nil {
		return Credential{}, err
	}
	newCred.Replaces = &credID
	// Old → revoked.
	old.Status = StatusRevoked
	old.UpdatedAt = now
	s.credentials[credID] = old
	delete(s.activeCredByIdent, identKey(old.Type, old.Identifier))
	s.credentials[newCred.ID] = newCred
	s.activeCredByIdent[identKey(newCred.Type, newCred.Identifier)] = newCred.ID
	s.cascadeRevokeSessionsForCredential(credID)
	return newCred, nil
}

func (s *InMemoryIdentityStore) RotatePassword(credID, newPassword string) (Credential, error) {
	return s.rotate(credID, func(now time.Time, old Credential) (Credential, error) {
		if old.Type != CredentialTypePassword {
			return Credential{}, fmt.Errorf("expected password: %w", ErrCredentialTypeMismatch)
		}
		hash, err := HashPassword(newPassword)
		if err != nil {
			return Credential{}, err
		}
		id, err := flametrenchids.Generate("cred")
		if err != nil {
			return Credential{}, err
		}
		s.passwordHashes[id] = hash
		return Credential{
			ID: id, UsrID: old.UsrID, Type: CredentialTypePassword,
			Identifier: old.Identifier, Status: StatusActive,
			CreatedAt: now, UpdatedAt: now,
		}, nil
	})
}

func (s *InMemoryIdentityStore) RotatePasskey(credID string, publicKey []byte, signCount int64, rpID string) (Credential, error) {
	return s.rotate(credID, func(now time.Time, old Credential) (Credential, error) {
		if old.Type != CredentialTypePasskey {
			return Credential{}, fmt.Errorf("expected passkey: %w", ErrCredentialTypeMismatch)
		}
		id, err := flametrenchids.Generate("cred")
		if err != nil {
			return Credential{}, err
		}
		s.passkeyPublicKeys[id] = publicKey
		return Credential{
			ID: id, UsrID: old.UsrID, Type: CredentialTypePasskey,
			Identifier: old.Identifier, Status: StatusActive,
			PasskeySignCount: signCount, PasskeyRPID: rpID,
			CreatedAt: now, UpdatedAt: now,
		}, nil
	})
}

func (s *InMemoryIdentityStore) RotateOIDC(credID, issuer, subject string) (Credential, error) {
	return s.rotate(credID, func(now time.Time, old Credential) (Credential, error) {
		if old.Type != CredentialTypeOIDC {
			return Credential{}, fmt.Errorf("expected oidc: %w", ErrCredentialTypeMismatch)
		}
		id, err := flametrenchids.Generate("cred")
		if err != nil {
			return Credential{}, err
		}
		return Credential{
			ID: id, UsrID: old.UsrID, Type: CredentialTypeOIDC,
			Identifier: old.Identifier, Status: StatusActive,
			OIDCIssuer: issuer, OIDCSubject: subject,
			CreatedAt: now, UpdatedAt: now,
		}, nil
	})
}

func (s *InMemoryIdentityStore) SuspendCredential(credID string) (Credential, error) {
	return s.transitionCredential(credID, StatusSuspended)
}
func (s *InMemoryIdentityStore) ReinstateCredential(credID string) (Credential, error) {
	return s.transitionCredential(credID, StatusActive)
}
func (s *InMemoryIdentityStore) RevokeCredential(credID string) (Credential, error) {
	return s.transitionCredential(credID, StatusRevoked)
}

func (s *InMemoryIdentityStore) transitionCredential(credID string, to Status) (Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.credentials[credID]
	if !ok {
		return Credential{}, fmt.Errorf("credential %s: %w", credID, ErrNotFound)
	}
	if c.Status == StatusRevoked {
		return Credential{}, fmt.Errorf("credential %s: %w", credID, ErrAlreadyTerminal)
	}
	if c.Status == to {
		return c, nil
	}
	if to == StatusActive {
		if c.Status != StatusSuspended {
			return Credential{}, &PreconditionError{Msg: "credential not suspended", Reason: "invalid_transition"}
		}
		// Reinstate restores the natural-key index if free.
		k := identKey(c.Type, c.Identifier)
		if _, taken := s.activeCredByIdent[k]; taken {
			return Credential{}, fmt.Errorf("identifier in use: %w", ErrDuplicateCredential)
		}
		s.activeCredByIdent[k] = credID
	} else {
		// Drop from natural-key index.
		delete(s.activeCredByIdent, identKey(c.Type, c.Identifier))
	}
	c.Status = to
	c.UpdatedAt = s.now()
	s.credentials[credID] = c
	if to == StatusSuspended || to == StatusRevoked {
		s.cascadeRevokeSessionsForCredential(credID)
	}
	return c, nil
}

func (s *InMemoryIdentityStore) VerifyPassword(identifier, password string) (VerifiedCredential, error) {
	s.mu.Lock()
	credID, ok := s.activeCredByIdent[identKey(CredentialTypePassword, identifier)]
	if !ok {
		s.mu.Unlock()
		// Constant-time decoy verify to avoid timing oracle.
		_, _ = VerifyPasswordHash(PatDummyPHCHash, password)
		return VerifiedCredential{}, ErrInvalidCredential
	}
	hash := s.passwordHashes[credID]
	cred := s.credentials[credID]
	policy, hasPolicy := s.mfaPolicies[cred.UsrID]
	s.mu.Unlock()

	ok, err := VerifyPasswordHash(hash, password)
	if err != nil {
		return VerifiedCredential{}, err
	}
	if !ok {
		return VerifiedCredential{}, ErrInvalidCredential
	}
	mfaRequired := false
	if hasPolicy {
		mfaRequired = policy.IsActiveNow(s.now())
	}
	return VerifiedCredential{UsrID: cred.UsrID, CredID: credID, MfaRequired: mfaRequired}, nil
}

// ─── Sessions ───

func (s *InMemoryIdentityStore) CreateSession(usrID, credID string, ttlSeconds int) (SessionWithToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[usrID]; !ok {
		return SessionWithToken{}, fmt.Errorf("user %s: %w", usrID, ErrNotFound)
	}
	c, ok := s.credentials[credID]
	if !ok {
		return SessionWithToken{}, fmt.Errorf("credential %s: %w", credID, ErrNotFound)
	}
	if c.UsrID != usrID {
		return SessionWithToken{}, &PreconditionError{Msg: "credential not owned by user", Reason: "cred_user_mismatch"}
	}
	if c.Status != StatusActive {
		return SessionWithToken{}, ErrCredentialNotActive
	}
	id, err := flametrenchids.Generate("ses")
	if err != nil {
		return SessionWithToken{}, err
	}
	token, err := newOpaqueToken()
	if err != nil {
		return SessionWithToken{}, err
	}
	now := s.now()
	ses := Session{
		ID: id, UsrID: usrID, CredID: credID,
		CreatedAt: now, ExpiresAt: now.Add(time.Duration(ttlSeconds) * time.Second),
	}
	s.sessions[id] = ses
	th := hashToken(token)
	s.sessionTokenHash[id] = th
	s.sessionByTokenHash[th] = id
	return SessionWithToken{Session: ses, Token: token}, nil
}

func (s *InMemoryIdentityStore) GetSession(sesID string) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ss, ok := s.sessions[sesID]
	if !ok {
		return Session{}, fmt.Errorf("session %s: %w", sesID, ErrNotFound)
	}
	return ss, nil
}

func (s *InMemoryIdentityStore) ListSessionsForUser(usrID string, opts ListSessionsOptions) (Page[Session], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[usrID]; !ok {
		return Page[Session]{}, fmt.Errorf("user %s: %w", usrID, ErrNotFound)
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	matched := make([]Session, 0)
	for _, ss := range s.sessions {
		if ss.UsrID == usrID {
			matched = append(matched, ss)
		}
	}
	// Sort by created_at ASC then id.
	for i := 1; i < len(matched); i++ {
		for j := i; j > 0; j-- {
			if matched[j].CreatedAt.Before(matched[j-1].CreatedAt) ||
				(matched[j].CreatedAt.Equal(matched[j-1].CreatedAt) && matched[j].ID < matched[j-1].ID) {
				matched[j-1], matched[j] = matched[j], matched[j-1]
			} else {
				break
			}
		}
	}
	startIdx := 0
	if opts.Cursor != nil && *opts.Cursor != "" {
		for i, ss := range matched {
			if ss.ID == *opts.Cursor {
				startIdx = i + 1
				break
			}
		}
	}
	end := startIdx + limit
	if end > len(matched) {
		end = len(matched)
	}
	data := matched[startIdx:end]
	var next *string
	if end < len(matched) && len(data) > 0 {
		c := data[len(data)-1].ID
		next = &c
	}
	return Page[Session]{Data: data, NextCursor: next}, nil
}

func (s *InMemoryIdentityStore) VerifySessionToken(token string) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	th := hashToken(token)
	sid, ok := s.sessionByTokenHash[th]
	if !ok {
		return Session{}, ErrInvalidToken
	}
	ss := s.sessions[sid]
	if ss.RevokedAt != nil {
		return Session{}, ErrSessionExpired
	}
	if !s.now().Before(ss.ExpiresAt) {
		return Session{}, ErrSessionExpired
	}
	return ss, nil
}

func (s *InMemoryIdentityStore) RefreshSession(sesID string) (SessionWithToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.sessions[sesID]
	if !ok {
		return SessionWithToken{}, fmt.Errorf("session %s: %w", sesID, ErrNotFound)
	}
	if old.RevokedAt != nil {
		return SessionWithToken{}, ErrSessionExpired
	}
	if !s.now().Before(old.ExpiresAt) {
		return SessionWithToken{}, ErrSessionExpired
	}
	// Revoke old, mint new.
	now := s.now()
	old.RevokedAt = &now
	s.sessions[sesID] = old
	if th, hadTok := s.sessionTokenHash[sesID]; hadTok {
		delete(s.sessionTokenHash, sesID)
		delete(s.sessionByTokenHash, th)
	}
	ttl := old.ExpiresAt.Sub(old.CreatedAt)
	newID, err := flametrenchids.Generate("ses")
	if err != nil {
		return SessionWithToken{}, err
	}
	token, err := newOpaqueToken()
	if err != nil {
		return SessionWithToken{}, err
	}
	ns := Session{
		ID: newID, UsrID: old.UsrID, CredID: old.CredID,
		CreatedAt: now, ExpiresAt: now.Add(ttl),
	}
	s.sessions[newID] = ns
	nth := hashToken(token)
	s.sessionTokenHash[newID] = nth
	s.sessionByTokenHash[nth] = newID
	return SessionWithToken{Session: ns, Token: token}, nil
}

func (s *InMemoryIdentityStore) RevokeSession(sesID string) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ss, ok := s.sessions[sesID]
	if !ok {
		return Session{}, fmt.Errorf("session %s: %w", sesID, ErrNotFound)
	}
	if ss.RevokedAt != nil {
		return ss, nil
	}
	now := s.now()
	ss.RevokedAt = &now
	s.sessions[sesID] = ss
	if th, ok := s.sessionTokenHash[sesID]; ok {
		delete(s.sessionTokenHash, sesID)
		delete(s.sessionByTokenHash, th)
	}
	return ss, nil
}

// ─── MFA ───

func (s *InMemoryIdentityStore) EnrollTotpFactor(usrID, label string, opts TotpComputeOptions) (TotpEnrollmentResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[usrID]; !ok {
		return TotpEnrollmentResult{}, fmt.Errorf("user %s: %w", usrID, ErrNotFound)
	}
	mfaID, err := flametrenchids.Generate("mfa")
	if err != nil {
		return TotpEnrollmentResult{}, err
	}
	secret, err := GenerateTotpSecret(20)
	if err != nil {
		return TotpEnrollmentResult{}, err
	}
	now := s.now()
	f := Factor{
		ID: mfaID, UsrID: usrID, Type: FactorTypeTotp,
		Identifier: label, Status: FactorStatusPending,
		CreatedAt: now, UpdatedAt: now,
	}
	s.factors[mfaID] = f
	s.totpSecrets[mfaID] = secret
	b32 := base64.StdEncoding.EncodeToString(secret)
	_ = b32 // not used directly; otpauth URI uses base32 of secret
	return TotpEnrollmentResult{
		Factor:     f,
		SecretB32:  strings.TrimRight(base64SecretB32(secret), "="),
		OtpauthURI: TotpOtpauthURI(secret, label, "Flametrench", opts),
	}, nil
}

func base64SecretB32(secret []byte) string {
	// Standard base32 (Google Authenticator format).
	enc := base32StdEncodeNoPad(secret)
	return enc
}

// base32 std encoding without padding (Google Authenticator format).
func base32StdEncodeNoPad(b []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	var sb strings.Builder
	// Encode 5 bytes → 8 chars.
	for i := 0; i < len(b); i += 5 {
		var chunk [5]byte
		copy(chunk[:], b[i:])
		// Pack into uint64.
		var v uint64
		for j := 0; j < 5; j++ {
			v = (v << 8) | uint64(chunk[j])
		}
		for j := 7; j >= 0; j-- {
			idx := (v >> (uint(j) * 5)) & 0x1F
			sb.WriteByte(alphabet[idx])
		}
	}
	// Trim trailing chars based on byte count.
	out := sb.String()
	switch len(b) % 5 {
	case 1:
		out = out[:len(out)-6]
	case 2:
		out = out[:len(out)-4]
	case 3:
		out = out[:len(out)-3]
	case 4:
		out = out[:len(out)-1]
	}
	return out
}

func (s *InMemoryIdentityStore) EnrollWebAuthnFactor(usrID, credentialID string, publicKey []byte, signCount int64, rpID string) (WebAuthnEnrollmentResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[usrID]; !ok {
		return WebAuthnEnrollmentResult{}, fmt.Errorf("user %s: %w", usrID, ErrNotFound)
	}
	mfaID, err := flametrenchids.Generate("mfa")
	if err != nil {
		return WebAuthnEnrollmentResult{}, err
	}
	now := s.now()
	f := Factor{
		ID: mfaID, UsrID: usrID, Type: FactorTypeWebAuthn,
		Identifier: credentialID, Status: FactorStatusPending,
		RpID: rpID, SignCount: signCount,
		CreatedAt: now, UpdatedAt: now,
	}
	s.factors[mfaID] = f
	s.webauthnPublicKeys[mfaID] = publicKey
	return WebAuthnEnrollmentResult{Factor: f}, nil
}

func (s *InMemoryIdentityStore) EnrollRecoveryFactor(usrID string) (RecoveryEnrollmentResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[usrID]; !ok {
		return RecoveryEnrollmentResult{}, fmt.Errorf("user %s: %w", usrID, ErrNotFound)
	}
	codes, err := GenerateRecoveryCodes()
	if err != nil {
		return RecoveryEnrollmentResult{}, err
	}
	hashes := make([]string, len(codes))
	for i, c := range codes {
		h, err := HashPassword(c)
		if err != nil {
			return RecoveryEnrollmentResult{}, err
		}
		hashes[i] = h
	}
	mfaID, err := flametrenchids.Generate("mfa")
	if err != nil {
		return RecoveryEnrollmentResult{}, err
	}
	now := s.now()
	f := Factor{
		ID: mfaID, UsrID: usrID, Type: FactorTypeRecovery,
		Status: FactorStatusActive,
		Remaining: len(codes),
		CreatedAt: now, UpdatedAt: now,
	}
	s.factors[mfaID] = f
	s.recoveryHashes[mfaID] = hashes
	s.recoveryConsumed[mfaID] = make([]bool, len(codes))
	return RecoveryEnrollmentResult{Factor: f, Codes: codes}, nil
}

func (s *InMemoryIdentityStore) ConfirmTotpFactor(mfaID, code string) (Factor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.factors[mfaID]
	if !ok {
		return Factor{}, fmt.Errorf("factor %s: %w", mfaID, ErrNotFound)
	}
	if f.Type != FactorTypeTotp || f.Status != FactorStatusPending {
		return Factor{}, &PreconditionError{Msg: "factor not in pending TOTP state", Reason: "invalid_transition"}
	}
	secret := s.totpSecrets[mfaID]
	ok2, err := TotpVerify(secret, code, s.now().Unix(), 1, TotpComputeOptions{})
	if err != nil {
		return Factor{}, err
	}
	if !ok2 {
		return Factor{}, ErrInvalidCredential
	}
	f.Status = FactorStatusActive
	f.UpdatedAt = s.now()
	s.factors[mfaID] = f
	s.mfaSingleton[f.UsrID+"|totp"] = mfaID
	return f, nil
}

func (s *InMemoryIdentityStore) ConfirmWebAuthnFactor(mfaID string, proof WebAuthnProof) (Factor, error) {
	s.mu.Lock()
	f, ok := s.factors[mfaID]
	if !ok {
		s.mu.Unlock()
		return Factor{}, fmt.Errorf("factor %s: %w", mfaID, ErrNotFound)
	}
	if f.Type != FactorTypeWebAuthn || f.Status != FactorStatusPending {
		s.mu.Unlock()
		return Factor{}, &PreconditionError{Msg: "factor not in pending WebAuthn state", Reason: "invalid_transition"}
	}
	if f.Identifier != proof.CredentialID {
		s.mu.Unlock()
		return Factor{}, &PreconditionError{Msg: "credential id mismatch", Reason: "cred_id_mismatch"}
	}
	publicKey := s.webauthnPublicKeys[mfaID]
	storedRpID := f.RpID
	storedCount := f.SignCount
	s.mu.Unlock()

	result, err := WebAuthnVerifyAssertion(WebAuthnVerifyOptions{
		CosePublicKey:       publicKey,
		StoredSignCount:     storedCount,
		StoredRpID:          storedRpID,
		ExpectedChallenge:   proof.ExpectedChallenge,
		ExpectedOrigin:      proof.ExpectedOrigin,
		AuthenticatorData:   proof.AuthenticatorData,
		ClientDataJSON:      proof.ClientDataJSON,
		Signature:           proof.Signature,
		RequireUserVerified: true,
		RequireUserPresent:  true,
	})
	if err != nil {
		return Factor{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	f = s.factors[mfaID]
	f.Status = FactorStatusActive
	f.SignCount = result.NewSignCount
	f.UpdatedAt = s.now()
	s.factors[mfaID] = f
	return f, nil
}

func (s *InMemoryIdentityStore) GetFactor(mfaID string) (Factor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.factors[mfaID]
	if !ok {
		return Factor{}, fmt.Errorf("factor %s: %w", mfaID, ErrNotFound)
	}
	return f, nil
}

func (s *InMemoryIdentityStore) ListFactorsForUser(usrID string) ([]Factor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[usrID]; !ok {
		return nil, fmt.Errorf("user %s: %w", usrID, ErrNotFound)
	}
	out := make([]Factor, 0)
	for _, f := range s.factors {
		if f.UsrID == usrID {
			out = append(out, f)
		}
	}
	return out, nil
}

func (s *InMemoryIdentityStore) SuspendFactor(mfaID string) (Factor, error) {
	return s.transitionFactor(mfaID, FactorStatusSuspended)
}
func (s *InMemoryIdentityStore) ReinstateFactor(mfaID string) (Factor, error) {
	return s.transitionFactor(mfaID, FactorStatusActive)
}
func (s *InMemoryIdentityStore) RevokeFactor(mfaID string) (Factor, error) {
	return s.transitionFactor(mfaID, FactorStatusRevoked)
}

func (s *InMemoryIdentityStore) transitionFactor(mfaID string, to FactorStatus) (Factor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.factors[mfaID]
	if !ok {
		return Factor{}, fmt.Errorf("factor %s: %w", mfaID, ErrNotFound)
	}
	if f.Status == FactorStatusRevoked {
		return Factor{}, fmt.Errorf("factor %s: %w", mfaID, ErrAlreadyTerminal)
	}
	f.Status = to
	f.UpdatedAt = s.now()
	s.factors[mfaID] = f
	if to != FactorStatusActive {
		delete(s.mfaSingleton, f.UsrID+"|"+string(f.Type))
	}
	return f, nil
}

func (s *InMemoryIdentityStore) VerifyMfa(usrID string, proof MfaProof) (MfaVerifyResult, error) {
	switch {
	case proof.Totp != nil:
		return s.verifyTotpProof(usrID, *proof.Totp)
	case proof.Recovery != nil:
		return s.verifyRecoveryProof(usrID, *proof.Recovery)
	case proof.WebAuthn != nil:
		return s.verifyWebAuthnProof(usrID, *proof.WebAuthn)
	}
	return MfaVerifyResult{}, errors.New("empty MFA proof")
}

func (s *InMemoryIdentityStore) verifyWebAuthnProof(usrID string, proof WebAuthnProof) (MfaVerifyResult, error) {
	s.mu.Lock()
	var mfaID string
	for id, f := range s.factors {
		if f.UsrID == usrID && f.Type == FactorTypeWebAuthn && f.Status == FactorStatusActive && f.Identifier == proof.CredentialID {
			mfaID = id
			break
		}
	}
	if mfaID == "" {
		s.mu.Unlock()
		return MfaVerifyResult{}, fmt.Errorf("no active WebAuthn factor for credential: %w", ErrNotFound)
	}
	f := s.factors[mfaID]
	publicKey := s.webauthnPublicKeys[mfaID]
	storedRpID := f.RpID
	storedCount := f.SignCount
	s.mu.Unlock()

	result, err := WebAuthnVerifyAssertion(WebAuthnVerifyOptions{
		CosePublicKey:       publicKey,
		StoredSignCount:     storedCount,
		StoredRpID:          storedRpID,
		ExpectedChallenge:   proof.ExpectedChallenge,
		ExpectedOrigin:      proof.ExpectedOrigin,
		AuthenticatorData:   proof.AuthenticatorData,
		ClientDataJSON:      proof.ClientDataJSON,
		Signature:           proof.Signature,
		RequireUserVerified: true,
		RequireUserPresent:  true,
	})
	if err != nil {
		return MfaVerifyResult{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	f = s.factors[mfaID]
	f.SignCount = result.NewSignCount
	f.UpdatedAt = s.now()
	s.factors[mfaID] = f
	newSC := result.NewSignCount
	return MfaVerifyResult{
		MfaID:         mfaID,
		Type:          FactorTypeWebAuthn,
		MfaVerifiedAt: s.now(),
		NewSignCount:  &newSC,
	}, nil
}

func (s *InMemoryIdentityStore) verifyTotpProof(usrID string, proof TotpProof) (MfaVerifyResult, error) {
	s.mu.Lock()
	mfaID, ok := s.mfaSingleton[usrID+"|totp"]
	if !ok {
		s.mu.Unlock()
		return MfaVerifyResult{}, fmt.Errorf("no active TOTP factor for user: %w", ErrNotFound)
	}
	f := s.factors[mfaID]
	if f.Status != FactorStatusActive {
		s.mu.Unlock()
		return MfaVerifyResult{}, ErrInvalidCredential
	}
	secret := s.totpSecrets[mfaID]
	s.mu.Unlock()
	ok2, err := TotpVerify(secret, proof.Code, s.now().Unix(), 1, TotpComputeOptions{})
	if err != nil {
		return MfaVerifyResult{}, err
	}
	if !ok2 {
		return MfaVerifyResult{}, ErrInvalidCredential
	}
	return MfaVerifyResult{MfaID: mfaID, Type: FactorTypeTotp, MfaVerifiedAt: s.now()}, nil
}

func (s *InMemoryIdentityStore) verifyRecoveryProof(usrID string, proof RecoveryProof) (MfaVerifyResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate := NormalizeRecoveryInput(proof.Code)
	if !IsValidRecoveryCode(candidate) {
		return MfaVerifyResult{}, ErrInvalidCredential
	}
	// Find any active recovery factor for the user.
	var mfaID string
	for id, f := range s.factors {
		if f.UsrID == usrID && f.Type == FactorTypeRecovery && f.Status == FactorStatusActive {
			mfaID = id
			break
		}
	}
	if mfaID == "" {
		return MfaVerifyResult{}, fmt.Errorf("no active recovery factor: %w", ErrNotFound)
	}
	hashes := s.recoveryHashes[mfaID]
	consumed := s.recoveryConsumed[mfaID]
	for i, h := range hashes {
		if consumed[i] {
			continue
		}
		ok, err := VerifyPasswordHash(h, candidate)
		if err != nil {
			return MfaVerifyResult{}, err
		}
		if ok {
			consumed[i] = true
			s.recoveryConsumed[mfaID] = consumed
			// Update Remaining count on the factor.
			f := s.factors[mfaID]
			remaining := 0
			for _, c := range consumed {
				if !c {
					remaining++
				}
			}
			f.Remaining = remaining
			f.UpdatedAt = s.now()
			s.factors[mfaID] = f
			return MfaVerifyResult{MfaID: mfaID, Type: FactorTypeRecovery, MfaVerifiedAt: s.now()}, nil
		}
	}
	return MfaVerifyResult{}, ErrInvalidCredential
}

func (s *InMemoryIdentityStore) GetUserMfaPolicy(usrID string) (UserMfaPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[usrID]; !ok {
		return UserMfaPolicy{}, fmt.Errorf("user %s: %w", usrID, ErrNotFound)
	}
	if p, ok := s.mfaPolicies[usrID]; ok {
		return p, nil
	}
	return UserMfaPolicy{UsrID: usrID, Required: false, UpdatedAt: s.now()}, nil
}

func (s *InMemoryIdentityStore) SetUserMfaPolicy(usrID string, required bool, graceUntil *time.Time) (UserMfaPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[usrID]; !ok {
		return UserMfaPolicy{}, fmt.Errorf("user %s: %w", usrID, ErrNotFound)
	}
	p := UserMfaPolicy{UsrID: usrID, Required: required, GraceUntil: graceUntil, UpdatedAt: s.now()}
	s.mfaPolicies[usrID] = p
	return p, nil
}

// ─── PATs ───

func (s *InMemoryIdentityStore) CreatePat(in CreatePatInput) (CreatePatResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[in.UsrID]; !ok {
		return CreatePatResult{}, fmt.Errorf("user %s: %w", in.UsrID, ErrNotFound)
	}
	if len(in.Name) < 1 || len(in.Name) > 120 {
		return CreatePatResult{}, &PreconditionError{Msg: "name must be 1-120 chars", Reason: "invalid_name"}
	}
	if in.ExpiresAt != nil {
		max := s.now().Add(time.Duration(PatMaxLifetimeSeconds) * time.Second)
		if in.ExpiresAt.After(max) {
			return CreatePatResult{}, &PreconditionError{Msg: "expires_at exceeds 365-day cap", Reason: "expires_too_late"}
		}
	}
	patID, err := flametrenchids.Generate("pat")
	if err != nil {
		return CreatePatResult{}, err
	}
	// Mint 32-byte secret, base64url-encode.
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return CreatePatResult{}, err
	}
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	hash, err := HashPassword(secret)
	if err != nil {
		return CreatePatResult{}, err
	}
	// Wire format: pat_<32hex>_<base64url-secret>.
	// patID is "pat_<32hex>" already.
	token := patID + "_" + secret
	now := s.now()
	scope := append([]string{}, in.Scope...)
	pat := PersonalAccessToken{
		ID: patID, UsrID: in.UsrID, Name: in.Name, Scope: scope,
		Status: PatStatusActive, ExpiresAt: in.ExpiresAt,
		CreatedAt: now, UpdatedAt: now,
	}
	s.pats[patID] = pat
	s.patSecretHashes[patID] = hash
	return CreatePatResult{Pat: pat, Token: token}, nil
}

func (s *InMemoryIdentityStore) GetPat(patID string) (PersonalAccessToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pats[patID]
	if !ok {
		return PersonalAccessToken{}, fmt.Errorf("pat %s: %w", patID, ErrNotFound)
	}
	return p, nil
}

func (s *InMemoryIdentityStore) ListPatsForUser(usrID string, opts ListPatsOptions) (Page[PersonalAccessToken], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[usrID]; !ok {
		return Page[PersonalAccessToken]{}, fmt.Errorf("user %s: %w", usrID, ErrNotFound)
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	matched := make([]PersonalAccessToken, 0)
	for _, p := range s.pats {
		if p.UsrID == usrID {
			matched = append(matched, p)
		}
	}
	// Sort by created_at ASC then id.
	for i := 1; i < len(matched); i++ {
		for j := i; j > 0; j-- {
			if matched[j].CreatedAt.Before(matched[j-1].CreatedAt) ||
				(matched[j].CreatedAt.Equal(matched[j-1].CreatedAt) && matched[j].ID < matched[j-1].ID) {
				matched[j-1], matched[j] = matched[j], matched[j-1]
			} else {
				break
			}
		}
	}
	startIdx := 0
	if opts.Cursor != nil && *opts.Cursor != "" {
		for i, p := range matched {
			if p.ID == *opts.Cursor {
				startIdx = i + 1
				break
			}
		}
	}
	end := startIdx + limit
	if end > len(matched) {
		end = len(matched)
	}
	data := matched[startIdx:end]
	var next *string
	if end < len(matched) && len(data) > 0 {
		c := data[len(data)-1].ID
		next = &c
	}
	return Page[PersonalAccessToken]{Data: data, NextCursor: next}, nil
}

// VerifyPatToken implements the 8-step ADR 0016 §"Verification semantics"
// sequence, including the H2 timing-oracle defense (a dummy Argon2id
// verify on every missing-row path) and the H6 secret-length cap
// (rejection before Argon2id is invoked).
func (s *InMemoryIdentityStore) VerifyPatToken(token string) (VerifiedPat, error) {
	// Step 1: structural check.
	if !IsStructurallyValidPatToken(token) {
		// Still run a dummy verify to keep wall-clock indistinguishable
		// from the row-not-found path.
		_, _ = VerifyPasswordHash(PatDummyPHCHash, token)
		return VerifiedPat{}, ErrInvalidPatToken
	}
	// Step 2: split prefix + secret.
	// Wire format: pat_<32hex>_<base64url-secret>
	// patID = pat_<32hex>
	parts := strings.SplitN(token, "_", 3)
	if len(parts) != 3 {
		_, _ = VerifyPasswordHash(PatDummyPHCHash, token)
		return VerifiedPat{}, ErrInvalidPatToken
	}
	patID := parts[0] + "_" + parts[1]
	secret := parts[2]

	// Step 3: H6 length cap before Argon2id.
	if len(secret) > PatMaxSecretLength {
		_, _ = VerifyPasswordHash(PatDummyPHCHash, "")
		return VerifiedPat{}, ErrInvalidPatToken
	}

	s.mu.Lock()
	pat, ok := s.pats[patID]
	if !ok {
		s.mu.Unlock()
		_, _ = VerifyPasswordHash(PatDummyPHCHash, secret)
		return VerifiedPat{}, ErrInvalidPatToken
	}
	if pat.RevokedAt != nil {
		s.mu.Unlock()
		return VerifiedPat{}, &PatRevokedError{PatID: patID}
	}
	if pat.ExpiresAt != nil && !s.now().Before(*pat.ExpiresAt) {
		s.mu.Unlock()
		return VerifiedPat{}, &PatExpiredError{PatID: patID}
	}
	hash := s.patSecretHashes[patID]
	scope := append([]string(nil), pat.Scope...)
	s.mu.Unlock()

	ok2, err := VerifyPasswordHash(hash, secret)
	if err != nil {
		return VerifiedPat{}, err
	}
	if !ok2 {
		return VerifiedPat{}, ErrInvalidPatToken
	}

	// Update last_used_at with coalescing.
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	prev, hadPrev := s.patLastUsedPersist[patID]
	if !hadPrev || now.Sub(prev) >= time.Duration(s.patLastUsedCoalesceSeconds)*time.Second {
		if p, ok := s.pats[patID]; ok && p.RevokedAt == nil {
			p.LastUsedAt = &now
			p.UpdatedAt = now
			s.pats[patID] = p
			s.patLastUsedPersist[patID] = now
		}
	}
	return VerifiedPat{PatID: patID, UsrID: pat.UsrID, Scope: scope}, nil
}

func (s *InMemoryIdentityStore) RevokePat(patID string) (PersonalAccessToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pats[patID]
	if !ok {
		return PersonalAccessToken{}, fmt.Errorf("pat %s: %w", patID, ErrNotFound)
	}
	if p.RevokedAt != nil {
		return p, nil
	}
	now := s.now()
	p.RevokedAt = &now
	p.Status = PatStatusRevoked
	p.UpdatedAt = now
	s.pats[patID] = p
	return p, nil
}
