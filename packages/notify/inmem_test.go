// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
package notify

import (
	"errors"
	"testing"
)

const testScope = "org_0190f2a81b3c7abc8123000000000004"
const testRecipient = "usr_0190f2a81b3c7abc8123000000000002"
const testIntruder = "usr_0190f2a81b3c7abc8123000000000099"

func defaultInput() CreateNotificationInput {
	return CreateNotificationInput{
		Scope:          testScope,
		RecipientUsrID: testRecipient,
		Type:           "comment.mention",
		Subject:        Subject{Kind: "doc", ID: "doc_abc"},
		Data:           map[string]any{"key": "val"},
	}
}

func newStore() *InMemoryNotificationStore { return NewInMemoryNotificationStore() }

func TestCreateGetRoundTrip(t *testing.T) {
	s := newStore()
	n, err := s.CreateNotification(defaultInput())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.GetNotification(testRecipient, n.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.State != StateUnread {
		t.Errorf("state = %q, want unread", got.State)
	}
	if got.RecipientUsrID != testRecipient {
		t.Errorf("recipient_usr_id = %q, want %q", got.RecipientUsrID, testRecipient)
	}
	if got.Data["key"] != "val" {
		t.Errorf("data.key = %v, want val", got.Data["key"])
	}
}

func TestMarkReadUnreadToggle(t *testing.T) {
	s := newStore()
	n, _ := s.CreateNotification(defaultInput())

	if _, err := s.MarkRead(testRecipient, n.ID); err != nil {
		t.Fatalf("MarkRead: %v", err)
	}
	got, _ := s.GetNotification(testRecipient, n.ID)
	if got.State != StateRead {
		t.Errorf("after MarkRead: state = %q, want read", got.State)
	}

	if _, err := s.MarkUnread(testRecipient, n.ID); err != nil {
		t.Fatalf("MarkUnread: %v", err)
	}
	got, _ = s.GetNotification(testRecipient, n.ID)
	if got.State != StateUnread {
		t.Errorf("after MarkUnread: state = %q, want unread", got.State)
	}
}

func TestDismissFromUnread(t *testing.T) {
	s := newStore()
	n, _ := s.CreateNotification(defaultInput())
	if _, err := s.Dismiss(testRecipient, n.ID); err != nil {
		t.Fatalf("Dismiss: %v", err)
	}
	got, _ := s.GetNotification(testRecipient, n.ID)
	if got.State != StateDismissed {
		t.Errorf("state = %q, want dismissed", got.State)
	}
}

func TestDismissFromRead(t *testing.T) {
	s := newStore()
	n, _ := s.CreateNotification(defaultInput())
	s.MarkRead(testRecipient, n.ID)
	if _, err := s.Dismiss(testRecipient, n.ID); err != nil {
		t.Fatalf("Dismiss from read: %v", err)
	}
	got, _ := s.GetNotification(testRecipient, n.ID)
	if got.State != StateDismissed {
		t.Errorf("state = %q, want dismissed", got.State)
	}
}

func TestDismissTerminal_OwnNotification(t *testing.T) {
	s := newStore()
	n, _ := s.CreateNotification(defaultInput())
	s.Dismiss(testRecipient, n.ID)
	_, err := s.Dismiss(testRecipient, n.ID)
	if !IsPrecondition(err) {
		t.Errorf("re-dismiss own: want PreconditionError, got %v", err)
	}
}

func TestMarkReadOnDismissed_OwnNotification(t *testing.T) {
	s := newStore()
	n, _ := s.CreateNotification(defaultInput())
	s.Dismiss(testRecipient, n.ID)
	_, err := s.MarkRead(testRecipient, n.ID)
	if !IsPrecondition(err) {
		t.Errorf("markRead on dismissed: want PreconditionError, got %v", err)
	}
}

// Cross-recipient access MUST return ErrNotFound, indistinguishable from non-existent.
func TestCrossRecipientGet_IsNotFound(t *testing.T) {
	s := newStore()
	n, _ := s.CreateNotification(defaultInput())
	_, err := s.GetNotification(testIntruder, n.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("cross-recipient get: want ErrNotFound, got %v", err)
	}
}

func TestCrossRecipientDismiss_IsNotFound(t *testing.T) {
	s := newStore()
	n, _ := s.CreateNotification(defaultInput())
	_, err := s.Dismiss(testIntruder, n.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("cross-recipient dismiss: want ErrNotFound, got %v", err)
	}
}

// ADR 0022 §Errors: ownership check before state-machine check.
// Intruder dismissing an already-dismissed notification MUST get NotFoundError,
// not PreconditionError (which would leak existence + state).
func TestCrossRecipientDismissOnDismissed_IsNotFound_NotPrecondition(t *testing.T) {
	s := newStore()
	n, _ := s.CreateNotification(defaultInput())
	s.Dismiss(testRecipient, n.ID)
	_, err := s.Dismiss(testIntruder, n.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("intruder dismiss-on-dismissed: want ErrNotFound, got %v", err)
	}
	if IsPrecondition(err) {
		t.Error("intruder dismiss-on-dismissed: must NOT be PreconditionError (leaks state)")
	}
}

func TestGetNotFound(t *testing.T) {
	s := newStore()
	_, err := s.GetNotification(testRecipient, "not_0190f2a81b3c7abc8123ffffffffffff")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("non-existent: want ErrNotFound, got %v", err)
	}
}

func TestCreateInvalidScope(t *testing.T) {
	s := newStore()
	in := defaultInput()
	in.Scope = "bad"
	_, err := s.CreateNotification(in)
	if !IsInvalidFormat(err) {
		t.Errorf("bad scope: want InvalidFormatError, got %v", err)
	}
}

func TestCreateInvalidRecipient(t *testing.T) {
	s := newStore()
	in := defaultInput()
	in.RecipientUsrID = "bad"
	_, err := s.CreateNotification(in)
	if !IsInvalidFormat(err) {
		t.Errorf("bad recipient: want InvalidFormatError, got %v", err)
	}
}

func TestCreateInvalidType(t *testing.T) {
	s := newStore()
	in := defaultInput()
	in.Type = "INVALID TYPE!"
	_, err := s.CreateNotification(in)
	if !IsInvalidFormat(err) {
		t.Errorf("bad type: want InvalidFormatError, got %v", err)
	}
}

func TestCreateInvalidSubject(t *testing.T) {
	s := newStore()
	in := defaultInput()
	in.Subject = Subject{Kind: "", ID: ""}
	_, err := s.CreateNotification(in)
	if !IsInvalidFormat(err) {
		t.Errorf("bad subject: want InvalidFormatError, got %v", err)
	}
}

func TestCountUnread(t *testing.T) {
	s := newStore()
	s.CreateNotification(defaultInput())
	s.CreateNotification(defaultInput())
	n3, _ := s.CreateNotification(defaultInput())
	s.MarkRead(testRecipient, n3.ID)

	count, err := s.CountUnread(testRecipient)
	if err != nil || count != 2 {
		t.Errorf("CountUnread = %d (err=%v), want 2", count, err)
	}
}
