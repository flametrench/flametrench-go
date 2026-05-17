// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Postgres-backend binding of the shared tenancy suite. Skipped when
// FT_GO_POSTGRES_URL is unset. The seed hook inserts rows into the
// `usr` table because org/mem/inv foreign keys reference it.

package tenancy

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// seedUsr inserts a row into `usr` for the given wire-format user id.
// ON CONFLICT DO NOTHING — same id can be seeded multiple times across
// sub-tests sharing the same TRUNCATE epoch.
func seedUsr(t *testing.T, pool *pgxpool.Pool, ctx context.Context, wireID string) {
	t.Helper()
	parts := strings.SplitN(wireID, "_", 2)
	if len(parts) != 2 || len(parts[1]) != 32 {
		t.Fatalf("seedUsr: malformed wireID %q", wireID)
	}
	h := parts[1]
	uStr := h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
	u, err := uuid.Parse(uStr)
	if err != nil {
		t.Fatalf("seedUsr parse: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO usr (id, status) VALUES ($1, 'active') ON CONFLICT (id) DO NOTHING`, u,
	); err != nil {
		t.Fatalf("seedUsr exec: %v", err)
	}
}

func TestPostgresTenancySuite(t *testing.T) {
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

	runTenancySuite(t, func(t *testing.T) (TenancyStore, func(*testing.T, string), func()) {
		// Truncate tuple/inv/mem/org/usr tables for clean state. The
		// `pat`, `mfa`, `ses`, `cred` tables FK to `usr`, so we cascade
		// from `usr` to clear all dependent identity rows too. Order
		// matters: child tables first to avoid FK errors.
		for _, tbl := range []string{
			"tup", "inv", "mem", "org",
			"pat", "usr_mfa_policy", "mfa", "ses", "cred", "usr",
		} {
			if _, err := pool.Exec(ctx, "TRUNCATE TABLE "+tbl+" CASCADE"); err != nil {
				t.Fatalf("truncate %s: %v", tbl, err)
			}
		}
		store := NewPostgresTenancyStore(ctx, pool)
		seed := func(t *testing.T, wireID string) {
			seedUsr(t, pool, ctx, wireID)
		}
		return store, seed, func() {}
	})
}
