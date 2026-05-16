// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

// PostgresTenancyStore — Postgres-backed TenancyStore.
//
// STATUS: scaffolded; full implementation lands in a follow-up
// session. See packages/identity/postgres.go for the same pattern.

package tenancy

import "errors"

// ErrPostgresNotImplemented is returned by every PostgresTenancyStore
// method until the Postgres adapter lands.
var ErrPostgresNotImplemented = errors.New("PostgresTenancyStore is scaffolded in this Go SDK release; implementation lands in a follow-up session")
