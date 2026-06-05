// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

// PostgresIdentityStore — Postgres-backed IdentityStore using jackc/pgx/v5.
//
// Mirrors flametrench_identity.postgres (Python) and
// @flametrench/identity/postgres (Node) against a real database. ADR
// 0013 caller-owned-connection pattern: the constructor accepts a
// PgxExecutor satisfied by *pgxpool.Pool, *pgx.Conn, and pgx.Tx.
// Multi-statement operations open a transaction or savepoint depending
// on the executor; adopters plumbing an outer transaction in get
// atomic cooperation with their own writes.

package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func pgSha256Sum(s string) [32]byte { return sha256.Sum256([]byte(s)) }

// PgxExecutor is the minimal interface the Postgres adapter needs.
// *pgxpool.Pool, *pgx.Conn, and pgx.Tx all satisfy it.
type PgxExecutor interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Begin(ctx context.Context) (pgx.Tx, error)
}

// PostgresIdentityStore is the Postgres-backed identity store.
type PostgresIdentityStore struct {
	exec                       PgxExecutor
	clock                      func() time.Time
	patLastUsedCoalesceSeconds int
	ctx                        context.Context
}

var _ IdentityStore = (*PostgresIdentityStore)(nil)

func NewPostgresIdentityStore(ctx context.Context, exec PgxExecutor) *PostgresIdentityStore {
	return &PostgresIdentityStore{
		exec:                       exec,
		clock:                      func() time.Time { return time.Now().UTC() },
		patLastUsedCoalesceSeconds: 60,
		ctx:                        ctx,
	}
}

func (s *PostgresIdentityStore) WithClock(c func() time.Time) *PostgresIdentityStore { s.clock = c; return s }
func (s *PostgresIdentityStore) WithContext(ctx context.Context) *PostgresIdentityStore {
	c := *s
	c.ctx = ctx
	return &c
}

// ─── Wire-format ↔ UUID ───

func wireToUUID(id string) (uuid.UUID, error) {
	sep := strings.IndexByte(id, '_')
	if sep == -1 {
		return uuid.UUID{}, fmt.Errorf("malformed wire id: %q", id)
	}
	h := id[sep+1:]
	if len(h) != 32 {
		return uuid.UUID{}, fmt.Errorf("malformed wire id payload: %q", id)
	}
	return uuid.Parse(fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32]))
}

func uuidToWire(prefix string, u uuid.UUID) string {
	return prefix + "_" + strings.ReplaceAll(u.String(), "-", "")
}

func mustWireToUUID(s string) uuid.UUID {
	u, err := wireToUUID(s)
	if err != nil {
		panic(err)
	}
	return u
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == "23505"
}

func (s *PostgresIdentityStore) inTx(fn func(tx pgx.Tx) error) error {
	tx, err := s.exec.Begin(s.ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback(s.ctx)
		return err
	}
	return tx.Commit(s.ctx)
}

func newPgToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// hashTokenBytes returns the raw 32-byte SHA-256 of the token. Matches
// the spec's ses.token_hash / shr.token_hash BYTEA(32) constraint.
// The in-memory store uses hex strings for map-key convenience; the
// Postgres adapter uses raw bytes.
func hashTokenBytes(token string) []byte {
	h := pgSha256(token)
	return h[:]
}

func pgSha256(s string) [32]byte {
	return pgSha256Sum(s)
}

// ─── Users ───

func (s *PostgresIdentityStore) CreateUser(displayName *string) (User, error) {
	var u User
	newID := uuid.Must(uuid.NewV7())
	var resID uuid.UUID
	var dbName *string
	err := s.exec.QueryRow(s.ctx, `
		INSERT INTO usr (id, display_name) VALUES ($1, $2)
		RETURNING id, status, display_name, created_at, updated_at`,
		newID, displayName,
	).Scan(&resID, &u.Status, &dbName, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return User{}, fmt.Errorf("create_user: %w", err)
	}
	u.ID = uuidToWire("usr", resID)
	u.DisplayName = dbName
	return u, nil
}

func (s *PostgresIdentityStore) GetUser(usrID string) (User, error) {
	u, err := wireToUUID(usrID)
	if err != nil {
		return User{}, err
	}
	var out User
	var resID uuid.UUID
	var dbName *string
	err = s.exec.QueryRow(s.ctx,
		`SELECT id, status, display_name, created_at, updated_at FROM usr WHERE id = $1`, u,
	).Scan(&resID, &out.Status, &dbName, &out.CreatedAt, &out.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, fmt.Errorf("user %s: %w", usrID, ErrNotFound)
	}
	if err != nil {
		return User{}, err
	}
	out.ID = uuidToWire("usr", resID)
	out.DisplayName = dbName
	return out, nil
}

func (s *PostgresIdentityStore) UpdateUser(usrID string, in UpdateUserInput) (User, error) {
	u, err := wireToUUID(usrID)
	if err != nil {
		return User{}, err
	}
	var out User
	var dbName *string
	err = s.inTx(func(tx pgx.Tx) error {
		var status Status
		var name *string
		var c, up time.Time
		err := tx.QueryRow(s.ctx,
			`SELECT status, display_name, created_at, updated_at FROM usr WHERE id = $1 FOR UPDATE`, u,
		).Scan(&status, &name, &c, &up)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("user %s: %w", usrID, ErrNotFound)
		}
		if err != nil {
			return err
		}
		if status == StatusRevoked {
			return fmt.Errorf("user %s is revoked: %w", usrID, ErrAlreadyTerminal)
		}
		next := name
		if in.ClearDisplayName {
			next = nil
		} else if in.DisplayName != nil {
			next = in.DisplayName
		}
		var resID uuid.UUID
		return tx.QueryRow(s.ctx, `
			UPDATE usr SET display_name = $2, updated_at = now() WHERE id = $1
			RETURNING id, status, display_name, created_at, updated_at`,
			u, next,
		).Scan(&resID, &out.Status, &dbName, &out.CreatedAt, &out.UpdatedAt)
	})
	if err != nil {
		return User{}, err
	}
	out.ID = uuidToWire("usr", u)
	out.DisplayName = dbName
	return out, nil
}

func (s *PostgresIdentityStore) ListUsers(opts ListUsersOptions) (Page[User], error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	args := []any{}
	conds := []string{}
	idx := 1
	if opts.Status != nil {
		conds = append(conds, fmt.Sprintf("usr.status = $%d", idx))
		args = append(args, *opts.Status)
		idx++
	}
	if opts.Query != nil && *opts.Query != "" {
		conds = append(conds, fmt.Sprintf(`EXISTS (
			SELECT 1 FROM cred WHERE cred.usr_id = usr.id
			AND cred.status = 'active' AND cred.identifier ILIKE $%d)`, idx))
		args = append(args, "%"+*opts.Query+"%")
		idx++
	}
	if opts.Cursor != nil && *opts.Cursor != "" {
		curU, err := wireToUUID(*opts.Cursor)
		if err != nil {
			return Page[User]{}, err
		}
		conds = append(conds, fmt.Sprintf(
			"(usr.created_at, usr.id) > (SELECT created_at, id FROM usr WHERE id = $%d)", idx))
		args = append(args, curU)
		idx++
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}
	q := fmt.Sprintf(`SELECT id, status, display_name, created_at, updated_at FROM usr%s
		ORDER BY usr.created_at ASC, usr.id ASC LIMIT $%d`, where, idx)
	args = append(args, limit+1)
	rows, err := s.exec.Query(s.ctx, q, args...)
	if err != nil {
		return Page[User]{}, err
	}
	defer rows.Close()
	out := make([]User, 0, limit)
	for rows.Next() {
		var id uuid.UUID
		var u User
		var name *string
		if err := rows.Scan(&id, &u.Status, &name, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return Page[User]{}, err
		}
		u.ID = uuidToWire("usr", id)
		u.DisplayName = name
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return Page[User]{}, err
	}
	var next *string
	if len(out) > limit {
		c := out[limit-1].ID
		next = &c
		out = out[:limit]
	}
	return Page[User]{Data: out, NextCursor: next}, nil
}

func (s *PostgresIdentityStore) SuspendUser(usrID string) (User, error) {
	return s.transUser(usrID, StatusSuspended)
}
func (s *PostgresIdentityStore) ReinstateUser(usrID string) (User, error) {
	return s.transUser(usrID, StatusActive)
}
func (s *PostgresIdentityStore) RevokeUser(usrID string) (User, error) {
	return s.transUser(usrID, StatusRevoked)
}

func (s *PostgresIdentityStore) transUser(usrID string, to Status) (User, error) {
	u, err := wireToUUID(usrID)
	if err != nil {
		return User{}, err
	}
	var out User
	var dbName *string
	err = s.inTx(func(tx pgx.Tx) error {
		var status Status
		var name *string
		var c, up time.Time
		err := tx.QueryRow(s.ctx,
			`SELECT status, display_name, created_at, updated_at FROM usr WHERE id = $1 FOR UPDATE`, u,
		).Scan(&status, &name, &c, &up)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("user %s: %w", usrID, ErrNotFound)
		}
		if err != nil {
			return err
		}
		if status == StatusRevoked {
			return fmt.Errorf("user %s: %w", usrID, ErrAlreadyTerminal)
		}
		if status == to {
			out.Status = status
			out.CreatedAt = c
			out.UpdatedAt = up
			dbName = name
			return nil
		}
		if to == StatusActive && status != StatusSuspended {
			return &PreconditionError{Msg: "user not suspended", Reason: "invalid_transition"}
		}
		var resID uuid.UUID
		err = tx.QueryRow(s.ctx, `
			UPDATE usr SET status = $2, updated_at = now() WHERE id = $1
			RETURNING id, status, display_name, created_at, updated_at`,
			u, to,
		).Scan(&resID, &out.Status, &dbName, &out.CreatedAt, &out.UpdatedAt)
		if err != nil {
			return err
		}
		now := s.clock()
		if to == StatusSuspended || to == StatusRevoked {
			if _, err := tx.Exec(s.ctx,
				`UPDATE ses SET revoked_at = $1 WHERE usr_id = $2 AND revoked_at IS NULL`, now, u); err != nil {
				return err
			}
		}
		if to == StatusRevoked {
			if _, err := tx.Exec(s.ctx,
				`UPDATE cred SET status = 'revoked', updated_at = now() WHERE usr_id = $1 AND status = 'active'`, u); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return User{}, err
	}
	out.ID = uuidToWire("usr", u)
	out.DisplayName = dbName
	return out, nil
}

// ─── Credentials ───

const credCols = `id, usr_id, type, identifier, status, replaces,
	passkey_sign_count, passkey_rp_id, oidc_issuer, oidc_subject,
	created_at, updated_at`

func scanCredentialRow(row pgx.Row) (Credential, error) {
	var (
		id, usrID            uuid.UUID
		typ, identifier      string
		status               Status
		replaces             *uuid.UUID
		passkeySignCount     *int64
		passkeyRPID          *string
		oidcIssuer, oidcSubj *string
		createdAt, updatedAt time.Time
	)
	if err := row.Scan(&id, &usrID, &typ, &identifier, &status, &replaces,
		&passkeySignCount, &passkeyRPID, &oidcIssuer, &oidcSubj,
		&createdAt, &updatedAt); err != nil {
		return Credential{}, err
	}
	c := Credential{
		ID: uuidToWire("cred", id), UsrID: uuidToWire("usr", usrID),
		Type: CredentialType(typ), Identifier: identifier, Status: status,
		CreatedAt: createdAt, UpdatedAt: updatedAt,
	}
	if replaces != nil {
		s := uuidToWire("cred", *replaces)
		c.Replaces = &s
	}
	if passkeySignCount != nil {
		c.PasskeySignCount = *passkeySignCount
	}
	if passkeyRPID != nil {
		c.PasskeyRPID = *passkeyRPID
	}
	if oidcIssuer != nil {
		c.OIDCIssuer = *oidcIssuer
	}
	if oidcSubj != nil {
		c.OIDCSubject = *oidcSubj
	}
	return c, nil
}

func (s *PostgresIdentityStore) CreatePasswordCredential(usrID, identifier, password string) (Credential, error) {
	usrU, err := wireToUUID(usrID)
	if err != nil {
		return Credential{}, err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return Credential{}, err
	}
	newID := uuid.Must(uuid.NewV7())
	var c Credential
	err = s.inTx(func(tx pgx.Tx) error {
		var status Status
		if err := tx.QueryRow(s.ctx, `SELECT status FROM usr WHERE id = $1`, usrU).Scan(&status); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("user %s: %w", usrID, ErrNotFound)
			}
			return err
		}
		_, err := tx.Exec(s.ctx, `
			INSERT INTO cred (id, usr_id, type, identifier, status, password_hash)
			VALUES ($1, $2, 'password', $3, 'active', $4)`,
			newID, usrU, identifier, hash,
		)
		if err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("password+%s: %w", identifier, ErrDuplicateCredential)
			}
			return err
		}
		row := tx.QueryRow(s.ctx, `SELECT `+credCols+` FROM cred WHERE id = $1`, newID)
		got, err := scanCredentialRow(row)
		if err != nil {
			return err
		}
		c = got
		return nil
	})
	return c, err
}

func (s *PostgresIdentityStore) CreatePasskeyCredential(usrID, identifier string, publicKey []byte, signCount int64, rpID string) (Credential, error) {
	usrU, err := wireToUUID(usrID)
	if err != nil {
		return Credential{}, err
	}
	newID := uuid.Must(uuid.NewV7())
	var c Credential
	err = s.inTx(func(tx pgx.Tx) error {
		var status Status
		if err := tx.QueryRow(s.ctx, `SELECT status FROM usr WHERE id = $1`, usrU).Scan(&status); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("user %s: %w", usrID, ErrNotFound)
			}
			return err
		}
		_, err := tx.Exec(s.ctx, `
			INSERT INTO cred (id, usr_id, type, identifier, status, passkey_public_key, passkey_sign_count, passkey_rp_id)
			VALUES ($1, $2, 'passkey', $3, 'active', $4, $5, $6)`,
			newID, usrU, identifier, publicKey, signCount, rpID,
		)
		if err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("passkey+%s: %w", identifier, ErrDuplicateCredential)
			}
			return err
		}
		row := tx.QueryRow(s.ctx, `SELECT `+credCols+` FROM cred WHERE id = $1`, newID)
		got, err := scanCredentialRow(row)
		if err != nil {
			return err
		}
		c = got
		return nil
	})
	return c, err
}

func (s *PostgresIdentityStore) CreateOIDCCredential(usrID, identifier, issuer, subject string) (Credential, error) {
	usrU, err := wireToUUID(usrID)
	if err != nil {
		return Credential{}, err
	}
	newID := uuid.Must(uuid.NewV7())
	var c Credential
	err = s.inTx(func(tx pgx.Tx) error {
		var status Status
		if err := tx.QueryRow(s.ctx, `SELECT status FROM usr WHERE id = $1`, usrU).Scan(&status); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("user %s: %w", usrID, ErrNotFound)
			}
			return err
		}
		_, err := tx.Exec(s.ctx, `
			INSERT INTO cred (id, usr_id, type, identifier, status, oidc_issuer, oidc_subject)
			VALUES ($1, $2, 'oidc', $3, 'active', $4, $5)`,
			newID, usrU, identifier, issuer, subject,
		)
		if err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("oidc+%s: %w", identifier, ErrDuplicateCredential)
			}
			return err
		}
		row := tx.QueryRow(s.ctx, `SELECT `+credCols+` FROM cred WHERE id = $1`, newID)
		got, err := scanCredentialRow(row)
		if err != nil {
			return err
		}
		c = got
		return nil
	})
	return c, err
}

func (s *PostgresIdentityStore) GetCredential(credID string) (Credential, error) {
	u, err := wireToUUID(credID)
	if err != nil {
		return Credential{}, err
	}
	row := s.exec.QueryRow(s.ctx, `SELECT `+credCols+` FROM cred WHERE id = $1`, u)
	c, err := scanCredentialRow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Credential{}, fmt.Errorf("credential %s: %w", credID, ErrNotFound)
	}
	return c, err
}

func (s *PostgresIdentityStore) ListCredentialsForUser(usrID string) ([]Credential, error) {
	u, err := wireToUUID(usrID)
	if err != nil {
		return nil, err
	}
	rows, err := s.exec.Query(s.ctx, `SELECT `+credCols+` FROM cred WHERE usr_id = $1 ORDER BY created_at ASC`, u)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Credential, 0)
	for rows.Next() {
		c, err := scanCredentialRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *PostgresIdentityStore) FindCredentialByIdentifier(t CredentialType, identifier string) (*Credential, error) {
	row := s.exec.QueryRow(s.ctx,
		`SELECT `+credCols+` FROM cred WHERE type = $1 AND identifier = $2 AND status = 'active'`,
		t, identifier)
	c, err := scanCredentialRow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *PostgresIdentityStore) rotateInTx(credID string, expected CredentialType, mutate func(tx pgx.Tx, oldU uuid.UUID, old Credential) (uuid.UUID, error)) (Credential, error) {
	credU, err := wireToUUID(credID)
	if err != nil {
		return Credential{}, err
	}
	var newCred Credential
	err = s.inTx(func(tx pgx.Tx) error {
		row := tx.QueryRow(s.ctx, `SELECT `+credCols+` FROM cred WHERE id = $1 FOR UPDATE`, credU)
		old, err := scanCredentialRow(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("credential %s: %w", credID, ErrNotFound)
		}
		if err != nil {
			return err
		}
		if old.Status != StatusActive {
			return fmt.Errorf("credential %s: %w", credID, ErrCredentialNotActive)
		}
		if old.Type != expected {
			return fmt.Errorf("expected %s: %w", expected, ErrCredentialTypeMismatch)
		}
		if _, err := tx.Exec(s.ctx,
			`UPDATE cred SET status = 'revoked', updated_at = now() WHERE id = $1`, credU); err != nil {
			return err
		}
		newID, err := mutate(tx, credU, old)
		if err != nil {
			return err
		}
		now := s.clock()
		if _, err := tx.Exec(s.ctx,
			`UPDATE ses SET revoked_at = $1 WHERE cred_id = $2 AND revoked_at IS NULL`, now, credU); err != nil {
			return err
		}
		row = tx.QueryRow(s.ctx, `SELECT `+credCols+` FROM cred WHERE id = $1`, newID)
		nc, err := scanCredentialRow(row)
		if err != nil {
			return err
		}
		newCred = nc
		return nil
	})
	return newCred, err
}

func (s *PostgresIdentityStore) RotatePassword(credID, newPassword string) (Credential, error) {
	hash, err := HashPassword(newPassword)
	if err != nil {
		return Credential{}, err
	}
	return s.rotateInTx(credID, CredentialTypePassword, func(tx pgx.Tx, oldU uuid.UUID, old Credential) (uuid.UUID, error) {
		newID := uuid.Must(uuid.NewV7())
		_, err := tx.Exec(s.ctx, `
			INSERT INTO cred (id, usr_id, type, identifier, status, password_hash, replaces)
			VALUES ($1, $2, 'password', $3, 'active', $4, $5)`,
			newID, mustWireToUUID(old.UsrID), old.Identifier, hash, oldU,
		)
		return newID, err
	})
}

func (s *PostgresIdentityStore) RotatePasskey(credID string, publicKey []byte, signCount int64, rpID string) (Credential, error) {
	return s.rotateInTx(credID, CredentialTypePasskey, func(tx pgx.Tx, oldU uuid.UUID, old Credential) (uuid.UUID, error) {
		newID := uuid.Must(uuid.NewV7())
		_, err := tx.Exec(s.ctx, `
			INSERT INTO cred (id, usr_id, type, identifier, status,
			                  passkey_public_key, passkey_sign_count, passkey_rp_id, replaces)
			VALUES ($1, $2, 'passkey', $3, 'active', $4, $5, $6, $7)`,
			newID, mustWireToUUID(old.UsrID), old.Identifier, publicKey, signCount, rpID, oldU,
		)
		return newID, err
	})
}

func (s *PostgresIdentityStore) RotateOIDC(credID, issuer, subject string) (Credential, error) {
	return s.rotateInTx(credID, CredentialTypeOIDC, func(tx pgx.Tx, oldU uuid.UUID, old Credential) (uuid.UUID, error) {
		newID := uuid.Must(uuid.NewV7())
		_, err := tx.Exec(s.ctx, `
			INSERT INTO cred (id, usr_id, type, identifier, status, oidc_issuer, oidc_subject, replaces)
			VALUES ($1, $2, 'oidc', $3, 'active', $4, $5, $6)`,
			newID, mustWireToUUID(old.UsrID), old.Identifier, issuer, subject, oldU,
		)
		return newID, err
	})
}

func (s *PostgresIdentityStore) SuspendCredential(credID string) (Credential, error) {
	return s.transCred(credID, StatusSuspended)
}
func (s *PostgresIdentityStore) ReinstateCredential(credID string) (Credential, error) {
	return s.transCred(credID, StatusActive)
}
func (s *PostgresIdentityStore) RevokeCredential(credID string) (Credential, error) {
	return s.transCred(credID, StatusRevoked)
}

func (s *PostgresIdentityStore) transCred(credID string, to Status) (Credential, error) {
	u, err := wireToUUID(credID)
	if err != nil {
		return Credential{}, err
	}
	var out Credential
	err = s.inTx(func(tx pgx.Tx) error {
		row := tx.QueryRow(s.ctx, `SELECT `+credCols+` FROM cred WHERE id = $1 FOR UPDATE`, u)
		c, err := scanCredentialRow(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("credential %s: %w", credID, ErrNotFound)
		}
		if err != nil {
			return err
		}
		if c.Status == StatusRevoked {
			return fmt.Errorf("credential %s: %w", credID, ErrAlreadyTerminal)
		}
		if c.Status == to {
			out = c
			return nil
		}
		if to == StatusActive && c.Status != StatusSuspended {
			return &PreconditionError{Msg: "credential not suspended", Reason: "invalid_transition"}
		}
		if _, err := tx.Exec(s.ctx, `UPDATE cred SET status = $2, updated_at = now() WHERE id = $1`, u, to); err != nil {
			if isUniqueViolation(err) && to == StatusActive {
				return fmt.Errorf("identifier in use: %w", ErrDuplicateCredential)
			}
			return err
		}
		if to == StatusSuspended || to == StatusRevoked {
			if _, err := tx.Exec(s.ctx,
				`UPDATE ses SET revoked_at = $1 WHERE cred_id = $2 AND revoked_at IS NULL`, s.clock(), u); err != nil {
				return err
			}
		}
		row = tx.QueryRow(s.ctx, `SELECT `+credCols+` FROM cred WHERE id = $1`, u)
		out, err = scanCredentialRow(row)
		return err
	})
	return out, err
}

func (s *PostgresIdentityStore) VerifyPassword(identifier, password string) (VerifiedCredential, error) {
	var credU, usrU uuid.UUID
	var hash string
	var hasPol bool
	var required bool
	var grace *time.Time
	err := s.exec.QueryRow(s.ctx, `
		SELECT cred.id, cred.usr_id, cred.password_hash,
		       (mfa_pol.required IS NOT NULL) AS has_policy,
		       COALESCE(mfa_pol.required, false) AS required,
		       mfa_pol.grace_until
		FROM cred
		LEFT JOIN usr_mfa_policy AS mfa_pol ON mfa_pol.usr_id = cred.usr_id
		WHERE cred.type = 'password' AND cred.identifier = $1 AND cred.status = 'active'`,
		identifier,
	).Scan(&credU, &usrU, &hash, &hasPol, &required, &grace)
	if errors.Is(err, pgx.ErrNoRows) {
		_, _ = VerifyPasswordHash(PatDummyPHCHash, password)
		return VerifiedCredential{}, ErrInvalidCredential
	}
	if err != nil {
		return VerifiedCredential{}, err
	}
	ok, err := VerifyPasswordHash(hash, password)
	if err != nil {
		return VerifiedCredential{}, err
	}
	if !ok {
		return VerifiedCredential{}, ErrInvalidCredential
	}
	mfaReq := false
	if hasPol {
		mfaReq = UserMfaPolicy{Required: required, GraceUntil: grace}.IsActiveNow(s.clock())
	}
	return VerifiedCredential{UsrID: uuidToWire("usr", usrU), CredID: uuidToWire("cred", credU), MfaRequired: mfaReq}, nil
}

// ─── Sessions ───

func (s *PostgresIdentityStore) CreateSession(usrID, credID string, ttlSeconds int) (SessionWithToken, error) {
	usrU, err := wireToUUID(usrID)
	if err != nil {
		return SessionWithToken{}, err
	}
	credU, err := wireToUUID(credID)
	if err != nil {
		return SessionWithToken{}, err
	}
	token, err := newPgToken()
	if err != nil {
		return SessionWithToken{}, err
	}
	th := hashTokenBytes(token)
	var ses Session
	err = s.inTx(func(tx pgx.Tx) error {
		var credStatus Status
		var credUsr uuid.UUID
		if err := tx.QueryRow(s.ctx, `SELECT status, usr_id FROM cred WHERE id = $1`, credU).Scan(&credStatus, &credUsr); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("credential %s: %w", credID, ErrNotFound)
			}
			return err
		}
		if credUsr != usrU {
			return &PreconditionError{Msg: "credential not owned by user", Reason: "cred_user_mismatch"}
		}
		if credStatus != StatusActive {
			return ErrCredentialNotActive
		}
		newID := uuid.Must(uuid.NewV7())
		expiresAt := s.clock().Add(time.Duration(ttlSeconds) * time.Second)
		var resID uuid.UUID
		err := tx.QueryRow(s.ctx, `
			INSERT INTO ses (id, usr_id, cred_id, token_hash, expires_at)
			VALUES ($1, $2, $3, $4, $5)
			RETURNING id, created_at, expires_at, revoked_at`,
			newID, usrU, credU, []byte(th), expiresAt,
		).Scan(&resID, &ses.CreatedAt, &ses.ExpiresAt, &ses.RevokedAt)
		if err != nil {
			return err
		}
		ses.ID = uuidToWire("ses", resID)
		ses.UsrID = usrID
		ses.CredID = credID
		return nil
	})
	return SessionWithToken{Session: ses, Token: token}, err
}

func (s *PostgresIdentityStore) GetSession(sesID string) (Session, error) {
	u, err := wireToUUID(sesID)
	if err != nil {
		return Session{}, err
	}
	var ses Session
	var sid, usrU, credU uuid.UUID
	err = s.exec.QueryRow(s.ctx,
		`SELECT id, usr_id, cred_id, created_at, expires_at, revoked_at FROM ses WHERE id = $1`, u,
	).Scan(&sid, &usrU, &credU, &ses.CreatedAt, &ses.ExpiresAt, &ses.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, fmt.Errorf("session %s: %w", sesID, ErrNotFound)
	}
	if err != nil {
		return Session{}, err
	}
	ses.ID = uuidToWire("ses", sid)
	ses.UsrID = uuidToWire("usr", usrU)
	ses.CredID = uuidToWire("cred", credU)
	return ses, nil
}

func (s *PostgresIdentityStore) ListSessionsForUser(usrID string, opts ListSessionsOptions) (Page[Session], error) {
	u, err := wireToUUID(usrID)
	if err != nil {
		return Page[Session]{}, err
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	args := []any{u}
	q := `SELECT id, usr_id, cred_id, created_at, expires_at, revoked_at FROM ses WHERE usr_id = $1`
	idx := 2
	if opts.Cursor != nil && *opts.Cursor != "" {
		curU, err := wireToUUID(*opts.Cursor)
		if err != nil {
			return Page[Session]{}, err
		}
		q += fmt.Sprintf(` AND (created_at, id) > (SELECT created_at, id FROM ses WHERE id = $%d)`, idx)
		args = append(args, curU)
		idx++
	}
	q += fmt.Sprintf(` ORDER BY created_at ASC, id ASC LIMIT $%d`, idx)
	args = append(args, limit+1)
	rows, err := s.exec.Query(s.ctx, q, args...)
	if err != nil {
		return Page[Session]{}, err
	}
	defer rows.Close()
	out := make([]Session, 0, limit)
	for rows.Next() {
		var sid, usrU, credU uuid.UUID
		var ses Session
		if err := rows.Scan(&sid, &usrU, &credU, &ses.CreatedAt, &ses.ExpiresAt, &ses.RevokedAt); err != nil {
			return Page[Session]{}, err
		}
		ses.ID = uuidToWire("ses", sid)
		ses.UsrID = uuidToWire("usr", usrU)
		ses.CredID = uuidToWire("cred", credU)
		out = append(out, ses)
	}
	var next *string
	if len(out) > limit {
		c := out[limit-1].ID
		next = &c
		out = out[:limit]
	}
	return Page[Session]{Data: out, NextCursor: next}, nil
}

func (s *PostgresIdentityStore) VerifySessionToken(token string) (Session, error) {
	th := hashTokenBytes(token)
	var ses Session
	var sid, usrU, credU uuid.UUID
	err := s.exec.QueryRow(s.ctx,
		`SELECT id, usr_id, cred_id, created_at, expires_at, revoked_at FROM ses WHERE token_hash = $1`,
		[]byte(th),
	).Scan(&sid, &usrU, &credU, &ses.CreatedAt, &ses.ExpiresAt, &ses.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, ErrInvalidToken
	}
	if err != nil {
		return Session{}, err
	}
	if ses.RevokedAt != nil || !s.clock().Before(ses.ExpiresAt) {
		return Session{}, ErrSessionExpired
	}
	ses.ID = uuidToWire("ses", sid)
	ses.UsrID = uuidToWire("usr", usrU)
	ses.CredID = uuidToWire("cred", credU)
	return ses, nil
}

func (s *PostgresIdentityStore) RefreshSession(sesID string) (SessionWithToken, error) {
	oldU, err := wireToUUID(sesID)
	if err != nil {
		return SessionWithToken{}, err
	}
	newToken, err := newPgToken()
	if err != nil {
		return SessionWithToken{}, err
	}
	newHash := hashTokenBytes(newToken)
	var out SessionWithToken
	err = s.inTx(func(tx pgx.Tx) error {
		var oldUsr, oldCred uuid.UUID
		var revoked *time.Time
		var created, expires time.Time
		err := tx.QueryRow(s.ctx,
			`SELECT usr_id, cred_id, created_at, expires_at, revoked_at FROM ses WHERE id = $1 FOR UPDATE`, oldU,
		).Scan(&oldUsr, &oldCred, &created, &expires, &revoked)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("session %s: %w", sesID, ErrNotFound)
		}
		if err != nil {
			return err
		}
		now := s.clock()
		if revoked != nil || !now.Before(expires) {
			return ErrSessionExpired
		}
		if _, err := tx.Exec(s.ctx, `UPDATE ses SET revoked_at = $1 WHERE id = $2`, now, oldU); err != nil {
			return err
		}
		ttl := expires.Sub(created)
		newID := uuid.Must(uuid.NewV7())
		var ns Session
		err = tx.QueryRow(s.ctx, `
			INSERT INTO ses (id, usr_id, cred_id, token_hash, expires_at)
			VALUES ($1, $2, $3, $4, $5)
			RETURNING id, created_at, expires_at`,
			newID, oldUsr, oldCred, []byte(newHash), now.Add(ttl),
		).Scan(&newID, &ns.CreatedAt, &ns.ExpiresAt)
		if err != nil {
			return err
		}
		ns.ID = uuidToWire("ses", newID)
		ns.UsrID = uuidToWire("usr", oldUsr)
		ns.CredID = uuidToWire("cred", oldCred)
		out = SessionWithToken{Session: ns, Token: newToken}
		return nil
	})
	return out, err
}

func (s *PostgresIdentityStore) RevokeSession(sesID string) (Session, error) {
	u, err := wireToUUID(sesID)
	if err != nil {
		return Session{}, err
	}
	var ses Session
	var sid, usrU, credU uuid.UUID
	err = s.exec.QueryRow(s.ctx, `
		UPDATE ses SET revoked_at = COALESCE(revoked_at, $1) WHERE id = $2
		RETURNING id, usr_id, cred_id, created_at, expires_at, revoked_at`,
		s.clock(), u,
	).Scan(&sid, &usrU, &credU, &ses.CreatedAt, &ses.ExpiresAt, &ses.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, fmt.Errorf("session %s: %w", sesID, ErrNotFound)
	}
	if err != nil {
		return Session{}, err
	}
	ses.ID = uuidToWire("ses", sid)
	ses.UsrID = uuidToWire("usr", usrU)
	ses.CredID = uuidToWire("cred", credU)
	return ses, nil
}

// ─── MFA ───

// PendingFactorTTL is how long a TOTP/WebAuthn factor stays in 'pending'
// before the schema's CHECK constraint requires it to either confirm or
// expire out. Matches the Python SDK default.
const PendingFactorTTL = 24 * time.Hour

func (s *PostgresIdentityStore) EnrollTotpFactor(usrID, label string, opts TotpComputeOptions) (TotpEnrollmentResult, error) {
	usrU, err := wireToUUID(usrID)
	if err != nil {
		return TotpEnrollmentResult{}, err
	}
	secret, err := GenerateTotpSecret(20)
	if err != nil {
		return TotpEnrollmentResult{}, err
	}
	algorithm := opts.Algorithm
	if algorithm == "" {
		algorithm = DefaultTotpAlgorithm
	}
	digits := opts.Digits
	if digits == 0 {
		digits = DefaultTotpDigits
	}
	period := opts.Period
	if period == 0 {
		period = DefaultTotpPeriod
	}
	pendingExpiresAt := s.clock().Add(PendingFactorTTL)
	newID := uuid.Must(uuid.NewV7())
	var f Factor
	err = s.exec.QueryRow(s.ctx, `
		INSERT INTO mfa (id, usr_id, type, identifier, status,
		                 totp_secret, totp_algorithm, totp_digits, totp_period,
		                 pending_expires_at)
		VALUES ($1, $2, 'totp', $3, 'pending', $4, $5, $6, $7, $8)
		RETURNING id, created_at, updated_at`,
		newID, usrU, label, secret, algorithm, digits, period, pendingExpiresAt,
	).Scan(&newID, &f.CreatedAt, &f.UpdatedAt)
	if err != nil {
		return TotpEnrollmentResult{}, err
	}
	f.ID = uuidToWire("mfa", newID)
	f.UsrID = usrID
	f.Type = FactorTypeTotp
	f.Identifier = label
	f.Status = FactorStatusPending
	return TotpEnrollmentResult{
		Factor:     f,
		SecretB32:  base32StdEncodeNoPad(secret),
		OtpauthURI: TotpOtpauthURI(secret, label, "Flametrench", opts),
	}, nil
}

func (s *PostgresIdentityStore) EnrollWebAuthnFactor(usrID, credentialID string, publicKey []byte, signCount int64, rpID string) (WebAuthnEnrollmentResult, error) {
	usrU, err := wireToUUID(usrID)
	if err != nil {
		return WebAuthnEnrollmentResult{}, err
	}
	pendingExpiresAt := s.clock().Add(PendingFactorTTL)
	newID := uuid.Must(uuid.NewV7())
	var f Factor
	err = s.exec.QueryRow(s.ctx, `
		INSERT INTO mfa (id, usr_id, type, identifier, status,
		                 webauthn_public_key, webauthn_sign_count, webauthn_rp_id,
		                 pending_expires_at)
		VALUES ($1, $2, 'webauthn', $3, 'pending', $4, $5, $6, $7)
		RETURNING id, created_at, updated_at`,
		newID, usrU, credentialID, publicKey, signCount, rpID, pendingExpiresAt,
	).Scan(&newID, &f.CreatedAt, &f.UpdatedAt)
	if err != nil {
		return WebAuthnEnrollmentResult{}, err
	}
	f.ID = uuidToWire("mfa", newID)
	f.UsrID = usrID
	f.Type = FactorTypeWebAuthn
	f.Identifier = credentialID
	f.Status = FactorStatusPending
	f.RpID = rpID
	f.SignCount = signCount
	return WebAuthnEnrollmentResult{Factor: f}, nil
}

func (s *PostgresIdentityStore) EnrollRecoveryFactor(usrID string) (RecoveryEnrollmentResult, error) {
	usrU, err := wireToUUID(usrID)
	if err != nil {
		return RecoveryEnrollmentResult{}, err
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
	consumed := make([]bool, len(codes))
	newID := uuid.Must(uuid.NewV7())
	var f Factor
	err = s.exec.QueryRow(s.ctx, `
		INSERT INTO mfa (id, usr_id, type, status, recovery_hashes, recovery_consumed)
		VALUES ($1, $2, 'recovery', 'active', $3, $4)
		RETURNING id, created_at, updated_at`,
		newID, usrU, hashes, consumed,
	).Scan(&newID, &f.CreatedAt, &f.UpdatedAt)
	if err != nil {
		return RecoveryEnrollmentResult{}, err
	}
	f.ID = uuidToWire("mfa", newID)
	f.UsrID = usrID
	f.Type = FactorTypeRecovery
	f.Status = FactorStatusActive
	f.Remaining = len(codes)
	return RecoveryEnrollmentResult{Factor: f, Codes: codes}, nil
}

func (s *PostgresIdentityStore) ConfirmTotpFactor(mfaID, code string) (Factor, error) {
	u, err := wireToUUID(mfaID)
	if err != nil {
		return Factor{}, err
	}
	var f Factor
	err = s.inTx(func(tx pgx.Tx) error {
		var usrU uuid.UUID
		var typ string
		var label *string
		var status FactorStatus
		var secret []byte
		err := tx.QueryRow(s.ctx,
			`SELECT usr_id, type, identifier, status, totp_secret FROM mfa WHERE id = $1 FOR UPDATE`, u,
		).Scan(&usrU, &typ, &label, &status, &secret)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("factor %s: %w", mfaID, ErrNotFound)
		}
		if err != nil {
			return err
		}
		if typ != "totp" || status != FactorStatusPending {
			return &PreconditionError{Msg: "factor not in pending TOTP state", Reason: "invalid_transition"}
		}
		ok, err := TotpVerify(secret, code, s.clock().Unix(), 1, TotpComputeOptions{})
		if err != nil {
			return err
		}
		if !ok {
			return ErrInvalidCredential
		}
		var resID uuid.UUID
		err = tx.QueryRow(s.ctx,
			`UPDATE mfa SET status = 'active', pending_expires_at = NULL, updated_at = now() WHERE id = $1
			 RETURNING id, created_at, updated_at`, u,
		).Scan(&resID, &f.CreatedAt, &f.UpdatedAt)
		if err != nil {
			return err
		}
		f.ID = uuidToWire("mfa", resID)
		f.UsrID = uuidToWire("usr", usrU)
		f.Type = FactorTypeTotp
		if label != nil {
			f.Identifier = *label
		}
		f.Status = FactorStatusActive
		return nil
	})
	return f, err
}

func (s *PostgresIdentityStore) ConfirmWebAuthnFactor(mfaID string, proof WebAuthnProof) (Factor, error) {
	u, err := wireToUUID(mfaID)
	if err != nil {
		return Factor{}, err
	}
	var f Factor
	err = s.inTx(func(tx pgx.Tx) error {
		var (
			usrU                  uuid.UUID
			typ, credID, rpID     string
			status                FactorStatus
			publicKey             []byte
			signCount             int64
		)
		err := tx.QueryRow(s.ctx, `
			SELECT usr_id, type, identifier, status, webauthn_public_key,
			       webauthn_sign_count, webauthn_rp_id
			FROM mfa WHERE id = $1 FOR UPDATE`, u,
		).Scan(&usrU, &typ, &credID, &status, &publicKey, &signCount, &rpID)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("factor %s: %w", mfaID, ErrNotFound)
		}
		if err != nil {
			return err
		}
		if typ != "webauthn" || status != FactorStatusPending {
			return &PreconditionError{Msg: "factor not in pending WebAuthn state", Reason: "invalid_transition"}
		}
		if credID != proof.CredentialID {
			return &PreconditionError{Msg: "credential id mismatch", Reason: "cred_id_mismatch"}
		}
		result, err := WebAuthnVerifyAssertion(WebAuthnVerifyOptions{
			CosePublicKey:       publicKey,
			StoredSignCount:     signCount,
			StoredRpID:          rpID,
			ExpectedChallenge:   proof.ExpectedChallenge,
			ExpectedOrigin:      proof.ExpectedOrigin,
			AuthenticatorData:   proof.AuthenticatorData,
			ClientDataJSON:      proof.ClientDataJSON,
			Signature:           proof.Signature,
			RequireUserVerified: true,
			RequireUserPresent:  true,
		})
		if err != nil {
			return err
		}
		var resID uuid.UUID
		err = tx.QueryRow(s.ctx, `
			UPDATE mfa SET status = 'active', webauthn_sign_count = $2,
			       pending_expires_at = NULL, updated_at = now()
			WHERE id = $1 RETURNING id, created_at, updated_at`,
			u, result.NewSignCount,
		).Scan(&resID, &f.CreatedAt, &f.UpdatedAt)
		if err != nil {
			return err
		}
		f.ID = uuidToWire("mfa", resID)
		f.UsrID = uuidToWire("usr", usrU)
		f.Type = FactorTypeWebAuthn
		f.Identifier = credID
		f.Status = FactorStatusActive
		f.RpID = rpID
		f.SignCount = result.NewSignCount
		return nil
	})
	return f, err
}

func (s *PostgresIdentityStore) loadFactor(u uuid.UUID) (Factor, error) {
	var (
		f          Factor
		usrU       uuid.UUID
		typ        string
		identifier *string
		status     FactorStatus
		rpID       *string
		signCount  *int64
		recCons    []bool
	)
	err := s.exec.QueryRow(s.ctx, `
		SELECT id, usr_id, type, identifier, status,
		       webauthn_rp_id, webauthn_sign_count, recovery_consumed,
		       created_at, updated_at
		FROM mfa WHERE id = $1`, u,
	).Scan(&u, &usrU, &typ, &identifier, &status, &rpID, &signCount, &recCons, &f.CreatedAt, &f.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Factor{}, fmt.Errorf("factor %s: %w", uuidToWire("mfa", u), ErrNotFound)
	}
	if err != nil {
		return Factor{}, err
	}
	f.ID = uuidToWire("mfa", u)
	f.UsrID = uuidToWire("usr", usrU)
	f.Type = FactorType(typ)
	f.Status = status
	if identifier != nil {
		f.Identifier = *identifier
	}
	if rpID != nil {
		f.RpID = *rpID
	}
	if signCount != nil {
		f.SignCount = *signCount
	}
	if f.Type == FactorTypeRecovery {
		rem := 0
		for _, c := range recCons {
			if !c {
				rem++
			}
		}
		f.Remaining = rem
	}
	return f, nil
}

func (s *PostgresIdentityStore) GetFactor(mfaID string) (Factor, error) {
	u, err := wireToUUID(mfaID)
	if err != nil {
		return Factor{}, err
	}
	return s.loadFactor(u)
}

func (s *PostgresIdentityStore) ListFactorsForUser(usrID string) ([]Factor, error) {
	u, err := wireToUUID(usrID)
	if err != nil {
		return nil, err
	}
	rows, err := s.exec.Query(s.ctx, `SELECT id FROM mfa WHERE usr_id = $1 ORDER BY created_at ASC`, u)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]uuid.UUID, 0)
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	out := make([]Factor, 0, len(ids))
	for _, id := range ids {
		f, err := s.loadFactor(id)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

func (s *PostgresIdentityStore) SuspendFactor(mfaID string) (Factor, error) {
	return s.transFactor(mfaID, FactorStatusSuspended)
}
func (s *PostgresIdentityStore) ReinstateFactor(mfaID string) (Factor, error) {
	return s.transFactor(mfaID, FactorStatusActive)
}
func (s *PostgresIdentityStore) RevokeFactor(mfaID string) (Factor, error) {
	return s.transFactor(mfaID, FactorStatusRevoked)
}

func (s *PostgresIdentityStore) transFactor(mfaID string, to FactorStatus) (Factor, error) {
	u, err := wireToUUID(mfaID)
	if err != nil {
		return Factor{}, err
	}
	var f Factor
	err = s.inTx(func(tx pgx.Tx) error {
		var status FactorStatus
		err := tx.QueryRow(s.ctx, `SELECT status FROM mfa WHERE id = $1 FOR UPDATE`, u).Scan(&status)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("factor %s: %w", mfaID, ErrNotFound)
		}
		if err != nil {
			return err
		}
		if status == FactorStatusRevoked {
			return fmt.Errorf("factor %s: %w", mfaID, ErrAlreadyTerminal)
		}
		var (
			usrU       uuid.UUID
			typ        string
			identifier *string
			rpID       *string
			signCount  *int64
			recCons    []bool
		)
		err = tx.QueryRow(s.ctx, `
			UPDATE mfa SET status = $2, updated_at = now() WHERE id = $1
			RETURNING usr_id, type, identifier, status,
			          webauthn_rp_id, webauthn_sign_count, recovery_consumed,
			          created_at, updated_at`, u, to,
		).Scan(&usrU, &typ, &identifier, &f.Status, &rpID, &signCount, &recCons, &f.CreatedAt, &f.UpdatedAt)
		if err != nil {
			return err
		}
		f.ID = uuidToWire("mfa", u)
		f.UsrID = uuidToWire("usr", usrU)
		f.Type = FactorType(typ)
		if identifier != nil {
			f.Identifier = *identifier
		}
		if rpID != nil {
			f.RpID = *rpID
		}
		if signCount != nil {
			f.SignCount = *signCount
		}
		if f.Type == FactorTypeRecovery {
			rem := 0
			for _, c := range recCons {
				if !c {
					rem++
				}
			}
			f.Remaining = rem
		}
		return nil
	})
	return f, err
}

func (s *PostgresIdentityStore) VerifyMfa(usrID string, proof MfaProof) (MfaVerifyResult, error) {
	usrU, err := wireToUUID(usrID)
	if err != nil {
		return MfaVerifyResult{}, err
	}
	switch {
	case proof.Totp != nil:
		return s.vfyTotp(usrU, *proof.Totp)
	case proof.Recovery != nil:
		return s.vfyRecovery(usrU, *proof.Recovery)
	case proof.WebAuthn != nil:
		return s.vfyWebAuthn(usrU, *proof.WebAuthn)
	}
	return MfaVerifyResult{}, errors.New("empty MFA proof")
}

func (s *PostgresIdentityStore) vfyTotp(usrU uuid.UUID, p TotpProof) (MfaVerifyResult, error) {
	var mfaID uuid.UUID
	var secret []byte
	err := s.exec.QueryRow(s.ctx,
		`SELECT id, totp_secret FROM mfa WHERE usr_id = $1 AND type = 'totp' AND status = 'active' LIMIT 1`,
		usrU,
	).Scan(&mfaID, &secret)
	if errors.Is(err, pgx.ErrNoRows) {
		return MfaVerifyResult{}, fmt.Errorf("no active TOTP factor: %w", ErrNotFound)
	}
	if err != nil {
		return MfaVerifyResult{}, err
	}
	ok, err := TotpVerify(secret, p.Code, s.clock().Unix(), 1, TotpComputeOptions{})
	if err != nil {
		return MfaVerifyResult{}, err
	}
	if !ok {
		return MfaVerifyResult{}, ErrInvalidCredential
	}
	return MfaVerifyResult{MfaID: uuidToWire("mfa", mfaID), Type: FactorTypeTotp, MfaVerifiedAt: s.clock()}, nil
}

func (s *PostgresIdentityStore) vfyRecovery(usrU uuid.UUID, p RecoveryProof) (MfaVerifyResult, error) {
	candidate := NormalizeRecoveryInput(p.Code)
	if !IsValidRecoveryCode(candidate) {
		return MfaVerifyResult{}, ErrInvalidCredential
	}
	var out MfaVerifyResult
	err := s.inTx(func(tx pgx.Tx) error {
		var mfaID uuid.UUID
		var hashes []string
		var consumed []bool
		err := tx.QueryRow(s.ctx, `
			SELECT id, recovery_hashes, recovery_consumed
			FROM mfa WHERE usr_id = $1 AND type = 'recovery' AND status = 'active' LIMIT 1 FOR UPDATE`,
			usrU,
		).Scan(&mfaID, &hashes, &consumed)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("no active recovery factor: %w", ErrNotFound)
		}
		if err != nil {
			return err
		}
		for i, h := range hashes {
			if consumed[i] {
				continue
			}
			ok, err := VerifyPasswordHash(h, candidate)
			if err != nil {
				return err
			}
			if ok {
				consumed[i] = true
				if _, err := tx.Exec(s.ctx,
					`UPDATE mfa SET recovery_consumed = $2, updated_at = now() WHERE id = $1`,
					mfaID, consumed,
				); err != nil {
					return err
				}
				out = MfaVerifyResult{MfaID: uuidToWire("mfa", mfaID), Type: FactorTypeRecovery, MfaVerifiedAt: s.clock()}
				return nil
			}
		}
		return ErrInvalidCredential
	})
	return out, err
}

func (s *PostgresIdentityStore) vfyWebAuthn(usrU uuid.UUID, p WebAuthnProof) (MfaVerifyResult, error) {
	var out MfaVerifyResult
	err := s.inTx(func(tx pgx.Tx) error {
		var mfaID uuid.UUID
		var publicKey []byte
		var signCount int64
		var rpID string
		err := tx.QueryRow(s.ctx, `
			SELECT id, webauthn_public_key, webauthn_sign_count, webauthn_rp_id
			FROM mfa WHERE usr_id = $1 AND type = 'webauthn' AND status = 'active'
			       AND identifier = $2 LIMIT 1 FOR UPDATE`,
			usrU, p.CredentialID,
		).Scan(&mfaID, &publicKey, &signCount, &rpID)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("no active WebAuthn factor for credential: %w", ErrNotFound)
		}
		if err != nil {
			return err
		}
		result, err := WebAuthnVerifyAssertion(WebAuthnVerifyOptions{
			CosePublicKey:       publicKey,
			StoredSignCount:     signCount,
			StoredRpID:          rpID,
			ExpectedChallenge:   p.ExpectedChallenge,
			ExpectedOrigin:      p.ExpectedOrigin,
			AuthenticatorData:   p.AuthenticatorData,
			ClientDataJSON:      p.ClientDataJSON,
			Signature:           p.Signature,
			RequireUserVerified: true,
			RequireUserPresent:  true,
		})
		if err != nil {
			return err
		}
		if _, err := tx.Exec(s.ctx,
			`UPDATE mfa SET webauthn_sign_count = $2, updated_at = now() WHERE id = $1`,
			mfaID, result.NewSignCount,
		); err != nil {
			return err
		}
		newSC := result.NewSignCount
		out = MfaVerifyResult{MfaID: uuidToWire("mfa", mfaID), Type: FactorTypeWebAuthn, MfaVerifiedAt: s.clock(), NewSignCount: &newSC}
		return nil
	})
	return out, err
}

func (s *PostgresIdentityStore) GetUserMfaPolicy(usrID string) (UserMfaPolicy, error) {
	u, err := wireToUUID(usrID)
	if err != nil {
		return UserMfaPolicy{}, err
	}
	var p UserMfaPolicy
	p.UsrID = usrID
	err = s.exec.QueryRow(s.ctx,
		`SELECT required, grace_until, updated_at FROM usr_mfa_policy WHERE usr_id = $1`, u,
	).Scan(&p.Required, &p.GraceUntil, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return UserMfaPolicy{UsrID: usrID, Required: false, UpdatedAt: s.clock()}, nil
	}
	return p, err
}

func (s *PostgresIdentityStore) SetUserMfaPolicy(usrID string, required bool, graceUntil *time.Time) (UserMfaPolicy, error) {
	u, err := wireToUUID(usrID)
	if err != nil {
		return UserMfaPolicy{}, err
	}
	var p UserMfaPolicy
	p.UsrID = usrID
	err = s.exec.QueryRow(s.ctx, `
		INSERT INTO usr_mfa_policy (usr_id, required, grace_until)
		VALUES ($1, $2, $3)
		ON CONFLICT (usr_id) DO UPDATE SET
			required = EXCLUDED.required,
			grace_until = EXCLUDED.grace_until,
			updated_at = now()
		RETURNING required, grace_until, updated_at`,
		u, required, graceUntil,
	).Scan(&p.Required, &p.GraceUntil, &p.UpdatedAt)
	return p, err
}

// ─── PATs ───

func (s *PostgresIdentityStore) CreatePat(in CreatePatInput) (CreatePatResult, error) {
	usrU, err := wireToUUID(in.UsrID)
	if err != nil {
		return CreatePatResult{}, err
	}
	if len(in.Name) < 1 || len(in.Name) > 120 {
		return CreatePatResult{}, &PreconditionError{Msg: "name must be 1-120 chars", Reason: "invalid_name"}
	}
	now := s.clock()
	if in.ExpiresAt != nil {
		max := now.Add(time.Duration(PatMaxLifetimeSeconds) * time.Second)
		if in.ExpiresAt.After(max) {
			return CreatePatResult{}, &PreconditionError{Msg: "expires_at exceeds 365-day cap", Reason: "expires_too_late"}
		}
	}
	newID := uuid.Must(uuid.NewV7())
	patWire := uuidToWire("pat", newID)
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return CreatePatResult{}, err
	}
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	hash, err := HashPassword(secret)
	if err != nil {
		return CreatePatResult{}, err
	}
	token := patWire + "_" + secret
	// Postgres `scope TEXT[] NOT NULL DEFAULT '{}'` — a nil slice from
	// the Go caller must be normalized to an empty array, not NULL.
	scope := in.Scope
	if scope == nil {
		scope = []string{}
	}
	var pat PersonalAccessToken
	err = s.exec.QueryRow(s.ctx, `
		INSERT INTO pat (id, usr_id, name, scope, secret_hash, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING name, scope, expires_at, last_used_at, revoked_at, created_at, updated_at`,
		newID, usrU, in.Name, scope, hash, in.ExpiresAt,
	).Scan(&pat.Name, &pat.Scope, &pat.ExpiresAt, &pat.LastUsedAt, &pat.RevokedAt, &pat.CreatedAt, &pat.UpdatedAt)
	if err != nil {
		return CreatePatResult{}, err
	}
	pat.ID = patWire
	pat.UsrID = in.UsrID
	pat.Status = PatStatusActive
	return CreatePatResult{Pat: pat, Token: token}, nil
}

func (s *PostgresIdentityStore) GetPat(patID string) (PersonalAccessToken, error) {
	u, err := wireToUUID(patID)
	if err != nil {
		return PersonalAccessToken{}, err
	}
	var pat PersonalAccessToken
	var usrU uuid.UUID
	err = s.exec.QueryRow(s.ctx, `
		SELECT id, usr_id, name, scope, expires_at, last_used_at, revoked_at, created_at, updated_at
		FROM pat WHERE id = $1`, u,
	).Scan(&u, &usrU, &pat.Name, &pat.Scope, &pat.ExpiresAt, &pat.LastUsedAt, &pat.RevokedAt, &pat.CreatedAt, &pat.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return PersonalAccessToken{}, fmt.Errorf("pat %s: %w", patID, ErrNotFound)
	}
	if err != nil {
		return PersonalAccessToken{}, err
	}
	pat.ID = uuidToWire("pat", u)
	pat.UsrID = uuidToWire("usr", usrU)
	pat.Status = derivePatStatus(pat, s.clock())
	return pat, nil
}

func derivePatStatus(p PersonalAccessToken, now time.Time) PatStatus {
	if p.RevokedAt != nil {
		return PatStatusRevoked
	}
	if p.ExpiresAt != nil && !now.Before(*p.ExpiresAt) {
		return PatStatusExpired
	}
	return PatStatusActive
}

func (s *PostgresIdentityStore) ListPatsForUser(usrID string, opts ListPatsOptions) (Page[PersonalAccessToken], error) {
	u, err := wireToUUID(usrID)
	if err != nil {
		return Page[PersonalAccessToken]{}, err
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	args := []any{u}
	q := `SELECT id, usr_id, name, scope, expires_at, last_used_at, revoked_at, created_at, updated_at
	      FROM pat WHERE usr_id = $1`
	idx := 2
	if opts.Cursor != nil && *opts.Cursor != "" {
		curU, err := wireToUUID(*opts.Cursor)
		if err != nil {
			return Page[PersonalAccessToken]{}, err
		}
		q += fmt.Sprintf(` AND (created_at, id) > (SELECT created_at, id FROM pat WHERE id = $%d)`, idx)
		args = append(args, curU)
		idx++
	}
	q += fmt.Sprintf(` ORDER BY created_at ASC, id ASC LIMIT $%d`, idx)
	args = append(args, limit+1)
	rows, err := s.exec.Query(s.ctx, q, args...)
	if err != nil {
		return Page[PersonalAccessToken]{}, err
	}
	defer rows.Close()
	now := s.clock()
	out := make([]PersonalAccessToken, 0, limit)
	for rows.Next() {
		var pat PersonalAccessToken
		var pid, usrU uuid.UUID
		if err := rows.Scan(&pid, &usrU, &pat.Name, &pat.Scope, &pat.ExpiresAt, &pat.LastUsedAt, &pat.RevokedAt, &pat.CreatedAt, &pat.UpdatedAt); err != nil {
			return Page[PersonalAccessToken]{}, err
		}
		pat.ID = uuidToWire("pat", pid)
		pat.UsrID = uuidToWire("usr", usrU)
		pat.Status = derivePatStatus(pat, now)
		out = append(out, pat)
	}
	var next *string
	if len(out) > limit {
		c := out[limit-1].ID
		next = &c
		out = out[:limit]
	}
	return Page[PersonalAccessToken]{Data: out, NextCursor: next}, nil
}

func (s *PostgresIdentityStore) VerifyPatToken(token string) (VerifiedPat, error) {
	if !IsStructurallyValidPatToken(token) {
		_, _ = VerifyPasswordHash(PatDummyPHCHash, token)
		return VerifiedPat{}, ErrInvalidPatToken
	}
	parts := strings.SplitN(token, "_", 3)
	if len(parts) != 3 {
		_, _ = VerifyPasswordHash(PatDummyPHCHash, token)
		return VerifiedPat{}, ErrInvalidPatToken
	}
	patWire := parts[0] + "_" + parts[1]
	secret := parts[2]
	if len(secret) > PatMaxSecretLength {
		_, _ = VerifyPasswordHash(PatDummyPHCHash, "")
		return VerifiedPat{}, ErrInvalidPatToken
	}
	patU, err := wireToUUID(patWire)
	if err != nil {
		_, _ = VerifyPasswordHash(PatDummyPHCHash, secret)
		return VerifiedPat{}, ErrInvalidPatToken
	}
	var (
		usrU      uuid.UUID
		hash      string
		expiresAt *time.Time
		revokedAt *time.Time
		scope     []string
	)
	err = s.exec.QueryRow(s.ctx,
		`SELECT usr_id, secret_hash, expires_at, revoked_at, scope FROM pat WHERE id = $1`,
		patU,
	).Scan(&usrU, &hash, &expiresAt, &revokedAt, &scope)
	if errors.Is(err, pgx.ErrNoRows) {
		_, _ = VerifyPasswordHash(PatDummyPHCHash, secret)
		return VerifiedPat{}, ErrInvalidPatToken
	}
	if err != nil {
		return VerifiedPat{}, err
	}
	if revokedAt != nil {
		return VerifiedPat{}, &PatRevokedError{PatID: patWire}
	}
	now := s.clock()
	if expiresAt != nil && !now.Before(*expiresAt) {
		return VerifiedPat{}, &PatExpiredError{PatID: patWire}
	}
	ok, err := VerifyPasswordHash(hash, secret)
	if err != nil {
		return VerifiedPat{}, err
	}
	if !ok {
		return VerifiedPat{}, ErrInvalidPatToken
	}
	// Coalesced last_used_at update. We discard the error here: this
	// is a best-effort update on the success path, and surfacing a DB
	// error would invert "PAT verified successfully" into a failure.
	threshold := now.Add(-time.Duration(s.patLastUsedCoalesceSeconds) * time.Second)
	_, _ = s.exec.Exec(s.ctx, `
		UPDATE pat SET last_used_at = $2
		WHERE id = $1 AND revoked_at IS NULL
		  AND (last_used_at IS NULL OR last_used_at < $3)`,
		patU, now, threshold,
	)
	return VerifiedPat{PatID: patWire, UsrID: uuidToWire("usr", usrU), Scope: scope}, nil
}

func (s *PostgresIdentityStore) RevokePat(patID string) (PersonalAccessToken, error) {
	u, err := wireToUUID(patID)
	if err != nil {
		return PersonalAccessToken{}, err
	}
	var pat PersonalAccessToken
	var usrU uuid.UUID
	err = s.exec.QueryRow(s.ctx, `
		UPDATE pat SET revoked_at = COALESCE(revoked_at, $1), updated_at = $1 WHERE id = $2
		RETURNING name, scope, expires_at, last_used_at, revoked_at, created_at, updated_at`,
		s.clock(), u,
	).Scan(&pat.Name, &pat.Scope, &pat.ExpiresAt, &pat.LastUsedAt, &pat.RevokedAt, &pat.CreatedAt, &pat.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return PersonalAccessToken{}, fmt.Errorf("pat %s: %w", patID, ErrNotFound)
	}
	if err != nil {
		return PersonalAccessToken{}, err
	}
	// Re-load usr_id since we didn't select it.
	if err := s.exec.QueryRow(s.ctx, `SELECT usr_id FROM pat WHERE id = $1`, u).Scan(&usrU); err != nil {
		return PersonalAccessToken{}, err
	}
	pat.ID = patID
	pat.UsrID = uuidToWire("usr", usrU)
	pat.Status = PatStatusRevoked
	return pat, nil
}
