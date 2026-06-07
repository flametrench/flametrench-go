// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

// InMemoryAuditStore — reference in-memory implementation of AuditStore.
// Append-only; events are never mutated after Write returns.

package audit

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sync"
	"time"

	flametrenchids "github.com/flametrench/flametrench-go/packages/ids"
)

// adopterObjectTypeRe is the object_type pattern from ADR 0007 / docs/authorization.md.
// target.kind MUST be either a Flametrench entity type prefix (registered in ids.Types)
// or a string matching this regex — otherwise InvalidFormatError field=target.kind.
var adopterObjectTypeRe = regexp.MustCompile(`^[a-z]{2,6}$`)

// maxEventBytes is the 64 KB payload cap from ADR 0019 §Constraints.
const maxEventBytes = 64 * 1024

// Compile-time guarantee.
var _ AuditStore = (*InMemoryAuditStore)(nil)

// InMemoryAuditStore is the reference in-memory audit store.
// Safe for concurrent use.
type InMemoryAuditStore struct {
	mu     sync.Mutex
	clock  func() time.Time
	events map[string]AuditEvent
}

func NewInMemoryAuditStore() *InMemoryAuditStore {
	return &InMemoryAuditStore{
		clock:  func() time.Time { return time.Now().UTC() },
		events: map[string]AuditEvent{},
	}
}

func (s *InMemoryAuditStore) WithClock(clock func() time.Time) *InMemoryAuditStore {
	s.clock = clock
	return s
}

// validateWrite checks the event shape before writing (ADR 0019 §Errors).
func validateWrite(in WriteInput) error {
	// Validate outcome.
	switch in.Outcome {
	case OutcomeSuccess, OutcomeFailure, OutcomeDenied, OutcomePending:
	default:
		return &InvalidFormatError{Field: "outcome",
			Reason: fmt.Sprintf("must be success|failure|denied|pending, got %q", in.Outcome)}
	}

	// Validate actor_usr_id: if non-null, must be a valid usr_ id.
	if in.ActorUsrID != nil {
		if _, err := flametrenchids.Decode(*in.ActorUsrID); err != nil {
			return &InvalidFormatError{Field: "actor_usr_id",
				Reason: "must be a valid usr_<32hex> or null"}
		}
		decoded, _ := flametrenchids.Decode(*in.ActorUsrID)
		if decoded.Type != "usr" {
			return &InvalidFormatError{Field: "actor_usr_id",
				Reason: "must be a usr_ prefixed id or null"}
		}
	}

	// Validate auth: exactly one kind-specific id must be present and match kind.
	if in.Auth != nil {
		a := in.Auth
		var sidCount int
		if a.SessionID != nil {
			sidCount++
		}
		if a.PatID != nil {
			sidCount++
		}
		if a.ShareID != nil {
			sidCount++
		}
		if a.SystemID != nil {
			sidCount++
		}
		if sidCount != 1 {
			return &InvalidFormatError{Field: "auth",
				Reason: "exactly one of session_id/pat_id/share_id/system_id must be present"}
		}
		var mismatch bool
		switch a.Kind {
		case AuthKindSession:
			mismatch = a.SessionID == nil
		case AuthKindPat:
			mismatch = a.PatID == nil
		case AuthKindShare:
			mismatch = a.ShareID == nil
		case AuthKindSystem:
			mismatch = a.SystemID == nil
		default:
			return &InvalidFormatError{Field: "auth",
				Reason: fmt.Sprintf("unknown auth.kind %q", a.Kind)}
		}
		if mismatch {
			return &InvalidFormatError{Field: "auth",
				Reason: fmt.Sprintf("auth.kind=%q but matching id field is absent", a.Kind)}
		}
	}

	// Validate target.kind: Flametrench entity prefix OR adopter object_type pattern.
	if in.Target.Kind != "" {
		_, isFTType := flametrenchids.Types[in.Target.Kind]
		if !isFTType && !adopterObjectTypeRe.MatchString(in.Target.Kind) {
			return &InvalidFormatError{Field: "target.kind",
				Reason: fmt.Sprintf("%q is not a Flametrench entity type or valid object_type", in.Target.Kind)}
		}
	}

	// Validate size: the whole event must be <= 64 KB.
	sizeCheck := struct {
		Metadata any `json:"metadata"`
	}{Metadata: in.Metadata}
	raw, err := json.Marshal(sizeCheck)
	if err == nil && len(raw) > maxEventBytes {
		return &InvalidFormatError{Field: "size", Reason: "event exceeds 64 KB limit"}
	}

	return nil
}

func (s *InMemoryAuditStore) Write(in WriteInput) (AuditEvent, error) {
	if err := validateWrite(in); err != nil {
		return AuditEvent{}, err
	}

	audID, err := flametrenchids.Generate("aud")
	if err != nil {
		return AuditEvent{}, fmt.Errorf("audit: generate id: %w", err)
	}
	now := s.clock()

	// Deep-copy Metadata so the stored event is immutable.
	var meta map[string]any
	if in.Metadata != nil {
		meta = make(map[string]any, len(in.Metadata))
		for k, v := range in.Metadata {
			meta[k] = v
		}
	} else {
		meta = map[string]any{}
	}

	ev := AuditEvent{
		ID:         audID,
		OccurredAt: in.OccurredAt,
		RecordedAt: now,
		ActorUsrID: in.ActorUsrID,
		Auth:       in.Auth,
		OnBehalf:   in.OnBehalf,
		Action:     in.Action,
		Target:     in.Target,
		Scope:      in.Scope,
		Outcome:    in.Outcome,
		Metadata:   meta,
		Context:    in.Context,
	}

	s.mu.Lock()
	s.events[audID] = ev
	s.mu.Unlock()

	return ev, nil
}

func (s *InMemoryAuditStore) Get(audID string) (AuditEvent, error) {
	s.mu.Lock()
	ev, ok := s.events[audID]
	s.mu.Unlock()
	if !ok {
		return AuditEvent{}, fmt.Errorf("audit event %s: %w", audID, ErrNotFound)
	}
	return ev, nil
}
