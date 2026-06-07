// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package audit

// AuditStore is the contract every audit backend implements (ADR 0019).
//
// Operations are append-only: no update or delete.
// Write MUST be durable before it returns (fail-closed semantics).
//
// Query, Count, and Export are deferred pending the error-taxonomy
// and cursor/ordering spec (spec PRs #43 and #46).
type AuditStore interface {
	// Write appends an immutable audit event and returns the stored record
	// (including the server-authoritative id and recorded_at).
	Write(in WriteInput) (AuditEvent, error)

	// Get fetches an event by its aud_ id.
	Get(audID string) (AuditEvent, error)
}
