// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

// PostgresIdentityStore — Postgres-backed IdentityStore. Mirrors the
// in-memory store's spec contract against a real database.
//
// STATUS: scaffolded with the ADR 0013 caller-owned-connection pattern
// in place. Method implementations are STUBBED in this release —
// each method returns ErrPostgresNotImplemented to surface the
// completion gap clearly. The Python and Node SDKs at v0.3.0 have full
// Postgres adapters (~1700 LOC each); the Go port lands in a follow-up
// session that ports the full surface in one cohesive commit.
//
// To use a Go backend against Postgres TODAY: use InMemoryIdentityStore
// for tests + integration suites, and Hearth's M7 (Go backend) for
// real adopter usage which will land alongside the Postgres adapter.

package identity

import (
	"context"
	"errors"
	"time"
)

// ErrPostgresNotImplemented is returned by every PostgresIdentityStore
// method until the Postgres adapter lands. Adopters can switch their
// import to InMemoryIdentityStore while waiting on the Postgres impl.
var ErrPostgresNotImplemented = errors.New("PostgresIdentityStore is scaffolded in this Go SDK release; method implementations land in a follow-up session — see github.com/flametrench/flametrench-go/CHANGELOG.md")

// PostgresExecutor is the minimal interface for executing SQL against a
// caller-owned connection (ADR 0013). Both *sql.DB and *sql.Tx satisfy
// it; pgx adapters can wrap pgxpool.Pool / pgx.Conn to fit.
type PostgresExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) (any, error)
	QueryContext(ctx context.Context, query string, args ...any) (any, error)
	QueryRowContext(ctx context.Context, query string, args ...any) any
}

// PostgresIdentityStore is the Postgres-backed identity store. Caller-
// owned via the PostgresExecutor handle, matching the ADR 0013 pattern
// used by the other 4 SDK families.
type PostgresIdentityStore struct {
	exec                       PostgresExecutor
	clock                      func() time.Time
	patLastUsedCoalesceSeconds int
}

// NewPostgresIdentityStore returns a Postgres-backed store bound to the
// given executor. exec may be a *sql.DB, a *sql.Tx, or any caller
// adapter implementing PostgresExecutor.
//
// IMPORTANT: this constructor is scaffolded; every method on the
// returned store returns ErrPostgresNotImplemented until the Postgres
// adapter ports the in-memory implementation. See package doc.
func NewPostgresIdentityStore(exec PostgresExecutor) *PostgresIdentityStore {
	return &PostgresIdentityStore{
		exec:                       exec,
		clock:                      func() time.Time { return time.Now().UTC() },
		patLastUsedCoalesceSeconds: 60,
	}
}

// Compile-time check (commented out until methods land).
// var _ IdentityStore = (*PostgresIdentityStore)(nil)

// All methods below return ErrPostgresNotImplemented. Stubs are listed
// for documentation; once each method is implemented, uncomment the
// interface assertion above and run the conformance suite against a
// real database.

func (p *PostgresIdentityStore) CreateUser(displayName *string) (User, error) {
	return User{}, ErrPostgresNotImplemented
}
func (p *PostgresIdentityStore) GetUser(usrID string) (User, error) {
	return User{}, ErrPostgresNotImplemented
}
