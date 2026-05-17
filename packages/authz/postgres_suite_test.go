// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Postgres-backend bindings of the shared tuple + share suites.
// Skipped when FT_GO_POSTGRES_URL is unset. Each test gets a clean
// store; the share suite seeds `usr` rows because shr.created_by FKs
// to usr.

package authz

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func authzSeedUsr(t *testing.T, pool *pgxpool.Pool, ctx context.Context, wireID string) {
	t.Helper()
	parts := strings.SplitN(wireID, "_", 2)
	if len(parts) != 2 || len(parts[1]) != 32 {
		t.Fatalf("seed: malformed wireID %q", wireID)
	}
	h := parts[1]
	uStr := h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
	u, err := uuid.Parse(uStr)
	if err != nil {
		t.Fatalf("seed parse: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO usr (id, status) VALUES ($1, 'active') ON CONFLICT (id) DO NOTHING`, u,
	); err != nil {
		t.Fatalf("seed exec: %v", err)
	}
}

func authzTruncate(t *testing.T, pool *pgxpool.Pool, ctx context.Context) {
	t.Helper()
	// Drop dependents first.
	for _, tbl := range []string{
		"shr", "tup", "pat", "usr_mfa_policy", "mfa", "ses", "cred",
		"inv", "mem", "org", "usr",
	} {
		if _, err := pool.Exec(ctx, "TRUNCATE TABLE "+tbl+" CASCADE"); err != nil {
			t.Fatalf("truncate %s: %v", tbl, err)
		}
	}
}

func TestPostgresTupleSuite(t *testing.T) {
	url := os.Getenv("FT_GO_POSTGRES_URL")
	if url == "" {
		t.Skip("FT_GO_POSTGRES_URL not set; skipping Postgres suite")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Skipf("pgxpool.New: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("ping: %v", err)
	}

	runTupleSuite(t, func(t *testing.T, rules Rules, opts EvaluateOptions) (TupleStore, func(*testing.T, string), func()) {
		authzTruncate(t, pool, ctx)
		var s TupleStore
		if rules == nil {
			s = NewPostgresTupleStore(ctx, pool)
		} else {
			s = NewPostgresTupleStoreWithRules(ctx, pool, rules, opts)
		}
		seed := func(t *testing.T, wireID string) {
			authzSeedUsr(t, pool, ctx, wireID)
		}
		return s, seed, func() {}
	})
}

func TestPostgresShareSuite(t *testing.T) {
	url := os.Getenv("FT_GO_POSTGRES_URL")
	if url == "" {
		t.Skip("FT_GO_POSTGRES_URL not set; skipping Postgres suite")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Skipf("pgxpool.New: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("ping: %v", err)
	}

	runShareSuite(t, func(t *testing.T) (ShareStore, func(*testing.T, string), func()) {
		authzTruncate(t, pool, ctx)
		store := NewPostgresShareStore(ctx, pool)
		seed := func(t *testing.T, wireID string) {
			authzSeedUsr(t, pool, ctx, wireID)
		}
		return store, seed, func() {}
	})
}
