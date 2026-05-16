// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

// PostgresTupleStore + PostgresShareStore — Postgres-backed authz.
//
// STATUS: scaffolded; implementations land in a follow-up session
// (see packages/identity/postgres.go for the same pattern).

package authz

import "errors"

var ErrPostgresNotImplemented = errors.New("PostgresTupleStore + PostgresShareStore are scaffolded in this Go SDK release; implementations land in a follow-up session")
