// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

// Postgres-backend binding of the shared identity suite. Skipped when
// FT_GO_POSTGRES_URL is unset or unreachable. Same test bodies as the
// in-memory binding — runs both backends through identical assertions
// so spec-divergence is caught immediately.

package identity

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresIdentitySuite(t *testing.T) {
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

	runIdentitySuite(t, func(t *testing.T) (IdentityStore, func()) {
		// Truncate all identity-relevant tables so each test gets a
		// clean state. The Postgres adapter writes to: usr, cred, ses,
		// mfa, usr_mfa_policy, pat. Some tables foreign-key into usr,
		// so TRUNCATE CASCADE clears the dependent rows.
		for _, tbl := range []string{"pat", "usr_mfa_policy", "mfa", "ses", "cred", "usr"} {
			if _, err := pool.Exec(ctx, "TRUNCATE TABLE "+tbl+" CASCADE"); err != nil {
				t.Fatalf("truncate %s: %v", tbl, err)
			}
		}
		store := NewPostgresIdentityStore(ctx, pool)
		return store, func() {}
	})
}
