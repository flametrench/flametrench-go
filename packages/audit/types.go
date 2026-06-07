// Package audit provides the Flametrench audit primitive (v0.4, ADR 0019):
// an append-only, identity- and tenancy-aware log of significant actions.
//
// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
package audit

import "time"

// Outcome is the result of the audited operation per ADR 0019.
type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
	OutcomeDenied  Outcome = "denied"
	OutcomePending Outcome = "pending"
)

// AuthKind mirrors the ADR 0016 canonical discriminator vocabulary,
// fulfilled by ADR 0019.
type AuthKind string

const (
	AuthKindSession AuthKind = "session"
	AuthKindPat     AuthKind = "pat"
	AuthKindShare   AuthKind = "share"
	AuthKindSystem  AuthKind = "system"
)

// Auth carries the credential axis of the audit event (ADR 0019 §auth).
// Absent when there is no established principal (pre-auth / anonymous / failed login).
// When present, exactly one of SessionID/PatID/ShareID/SystemID is non-nil and
// matches Kind.
type Auth struct {
	Kind      AuthKind
	SessionID *string // IFF Kind = session
	PatID     *string // IFF Kind = pat
	ShareID   *string // IFF Kind = share
	SystemID  *string // IFF Kind = system; opaque adopter-defined principal
}

// OnBehalf carries the delegated non-human actor axis (ADR 0019 §on_behalf).
// Orthogonal to Auth — an agent typically authenticates with a session or PAT.
type OnBehalf struct {
	AgentID string // opaque, adopter-defined
}

// Target identifies the resource the action operated on (ADR 0019 §target).
// For Flametrench-managed entities, Kind is the entity type and ID is a
// Flametrench wire id. For adopter resources both fields are opaque strings.
type Target struct {
	Kind string
	ID   string
}

// Scope names the tenancy boundary the action occurred within (ADR 0019 §scope).
// Absent for global / non-org-scoped events.
type Scope struct {
	Kind string // e.g. "org"
	ID   string // e.g. org_<32hex>
}

// EventContext carries optional request metadata (ADR 0019 §context).
type EventContext struct {
	RequestID *string
	IP        *string
	UserAgent *string
}

// AuditEvent is the canonical immutable audit record (ADR 0019 §event shape).
type AuditEvent struct {
	ID         string     // aud_<32hex>
	OccurredAt time.Time  // emitter clock
	RecordedAt time.Time  // server-authoritative; set by Write, not the emitter
	ActorUsrID *string    // null when no human principal
	Auth       *Auth      // absent when no established principal
	OnBehalf   *OnBehalf  // absent unless a delegated non-human actor performed the action
	Action     string     // adopter-namespaced; opaque to the primitive
	Target     Target
	Scope      *Scope     // absent for global / system events
	Outcome    Outcome
	Metadata   map[string]any // free-form; protocol markers live here only
	Context    *EventContext  // optional request context
}

// WriteInput is the caller-supplied payload for AuditStore.Write.
// RecordedAt is set server-side and MUST NOT be supplied by the emitter.
type WriteInput struct {
	OccurredAt time.Time
	ActorUsrID *string   // nil = no human principal
	Auth       *Auth
	OnBehalf   *OnBehalf
	Action     string
	Target     Target
	Scope      *Scope
	Outcome    Outcome
	Metadata   map[string]any
	Context    *EventContext
}
