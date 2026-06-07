// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
package notify

import (
	"encoding/json"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/flametrench/flametrench-go/packages/ids"
)

var typeRe = regexp.MustCompile(`^[a-z0-9._\-]{1,64}$`)

func cloneData(d map[string]any) map[string]any {
	if d == nil {
		return nil
	}
	b, _ := json.Marshal(d)
	var out map[string]any
	json.Unmarshal(b, &out) //nolint:errcheck
	return out
}

func cloneNotification(n Notification) Notification {
	n.Data = cloneData(n.Data)
	return n
}

// InMemoryNotificationStore is a thread-safe in-process NotificationStore for
// testing and development (ADR 0022). Access is SDK-enforced: every
// per-notification operation requires the authenticated recipient_usr_id and
// scopes the lookup to it.
type InMemoryNotificationStore struct {
	mu     sync.RWMutex
	notifs map[string]*Notification // id → notification
}

// NewInMemoryNotificationStore returns an empty InMemoryNotificationStore.
func NewInMemoryNotificationStore() *InMemoryNotificationStore {
	return &InMemoryNotificationStore{
		notifs: make(map[string]*Notification),
	}
}

func (s *InMemoryNotificationStore) CreateNotification(in CreateNotificationInput) (Notification, error) {
	if !ids.IsValid(in.Scope, "org") {
		return Notification{}, &InvalidFormatError{Field: "scope", Reason: "must be a valid org_ id"}
	}
	if !ids.IsValid(in.RecipientUsrID, "usr") {
		return Notification{}, &InvalidFormatError{Field: "recipient_usr_id", Reason: "must be a valid usr_ id"}
	}
	if !typeRe.MatchString(in.Type) {
		return Notification{}, &InvalidFormatError{Field: "type", Reason: `must match ^[a-z0-9._-]{1,64}$`}
	}
	if in.Subject.Kind == "" || in.Subject.ID == "" {
		return Notification{}, &InvalidFormatError{Field: "subject", Reason: "must have non-empty kind and id"}
	}
	if in.Data != nil {
		b, err := json.Marshal(in.Data)
		if err != nil || len(b) > 16*1024 {
			return Notification{}, &InvalidFormatError{Field: "data", Reason: "must be a JSON object ≤ 16 KB"}
		}
	}

	id, err := ids.Generate("not")
	if err != nil {
		return Notification{}, err
	}
	now := time.Now().UTC()
	n := &Notification{
		ID:             id,
		Scope:          in.Scope,
		RecipientUsrID: in.RecipientUsrID,
		Type:           in.Type,
		Subject:        in.Subject,
		Data:           cloneData(in.Data),
		State:          StateUnread,
		CreatedAt:      now,
		StateChangedAt: now,
	}

	s.mu.Lock()
	s.notifs[id] = n
	s.mu.Unlock()

	return cloneNotification(*n), nil
}

func (s *InMemoryNotificationStore) GetNotification(recipientUsrID, id string) (Notification, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n, ok := s.notifs[id]
	// Ownership check: cross-recipient and non-existent are indistinguishable.
	if !ok || n.RecipientUsrID != recipientUsrID {
		return Notification{}, ErrNotFound
	}
	return cloneNotification(*n), nil
}

func (s *InMemoryNotificationStore) MarkRead(recipientUsrID, id string) (Notification, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.notifs[id]
	if !ok || n.RecipientUsrID != recipientUsrID {
		return Notification{}, ErrNotFound
	}
	if n.State == StateDismissed {
		return Notification{}, &PreconditionError{Reason: "cannot modify a dismissed notification"}
	}
	if n.State != StateRead {
		n.State = StateRead
		n.StateChangedAt = time.Now().UTC()
	}
	return cloneNotification(*n), nil
}

func (s *InMemoryNotificationStore) MarkUnread(recipientUsrID, id string) (Notification, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.notifs[id]
	if !ok || n.RecipientUsrID != recipientUsrID {
		return Notification{}, ErrNotFound
	}
	if n.State == StateDismissed {
		return Notification{}, &PreconditionError{Reason: "cannot modify a dismissed notification"}
	}
	if n.State != StateUnread {
		n.State = StateUnread
		n.StateChangedAt = time.Now().UTC()
	}
	return cloneNotification(*n), nil
}

func (s *InMemoryNotificationStore) Dismiss(recipientUsrID, id string) (Notification, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.notifs[id]
	// ADR 0022 §Errors: ownership check BEFORE state-machine check.
	// A foreign-caller dismiss on an already-dismissed notification MUST raise
	// NotFoundError, not PreconditionError — to avoid leaking existence + state.
	if !ok || n.RecipientUsrID != recipientUsrID {
		return Notification{}, ErrNotFound
	}
	if n.State == StateDismissed {
		return Notification{}, &PreconditionError{Reason: "notification is already dismissed"}
	}
	n.State = StateDismissed
	n.StateChangedAt = time.Now().UTC()
	return cloneNotification(*n), nil
}

func (s *InMemoryNotificationStore) CountUnread(recipientUsrID string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	for _, n := range s.notifs {
		if n.RecipientUsrID == recipientUsrID && n.State == StateUnread {
			count++
		}
	}
	return count, nil
}

func (s *InMemoryNotificationStore) ListNotifications(opts ListNotificationsOptions) (NotificationPage, error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var matching []Notification
	for _, n := range s.notifs {
		if n.RecipientUsrID != opts.RecipientUsrID {
			continue
		}
		if opts.Scope != "" && n.Scope != opts.Scope {
			continue
		}
		if opts.State != nil && n.State != *opts.State {
			continue
		}
		if opts.Type != nil && n.Type != *opts.Type {
			continue
		}
		matching = append(matching, cloneNotification(*n))
	}
	sort.Slice(matching, func(i, j int) bool { return matching[i].ID < matching[j].ID })

	if opts.Cursor != nil {
		for i, n := range matching {
			if n.ID == *opts.Cursor {
				matching = matching[i+1:]
				break
			}
		}
	}

	var nextCursor *string
	if len(matching) > limit {
		c := matching[limit-1].ID
		nextCursor = &c
		matching = matching[:limit]
	}
	return NotificationPage{Data: matching, NextCursor: nextCursor}, nil
}
