// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

// InMemoryAuditStore — reference in-memory implementation of AuditStore.
// Append-only; events are never mutated after Write returns.

package audit

import (
	"fmt"
	"sync"
	"time"

	flametrenchids "github.com/flametrench/flametrench-go/packages/ids"
)

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

func (s *InMemoryAuditStore) Write(in WriteInput) (AuditEvent, error) {
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
