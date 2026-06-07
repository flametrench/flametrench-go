// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package audit_test

import (
	"errors"
	"testing"
	"time"

	"github.com/flametrench/flametrench-go/packages/audit"
	"github.com/flametrench/flametrench-go/packages/ids"
)

func validInput() audit.WriteInput {
	usrID, _ := ids.Generate("usr")
	sesID := "ses_0190f2a81b3c7abc8123000000000007"
	return audit.WriteInput{
		OccurredAt: time.Now(),
		ActorUsrID: &usrID,
		Auth:       &audit.Auth{Kind: audit.AuthKindSession, SessionID: &sesID},
		Action:     "data.create.record",
		Target:     audit.Target{Kind: "doc", ID: "doc_abc123"},
		Outcome:    audit.OutcomeSuccess,
		Metadata:   map[string]any{},
	}
}

func TestWriteGetRoundTrip(t *testing.T) {
	store := audit.NewInMemoryAuditStore()
	in := validInput()
	ev, err := store.Write(in)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if ev.ID == "" {
		t.Fatal("Write: id is empty")
	}
	if ev.RecordedAt.IsZero() {
		t.Fatal("Write: recorded_at not set")
	}
	got, err := store.Get(ev.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != ev.ID {
		t.Errorf("Get: id = %q, want %q", got.ID, ev.ID)
	}
	if got.Action != in.Action {
		t.Errorf("Get: action = %q, want %q", got.Action, in.Action)
	}
}

func TestGetNotFound(t *testing.T) {
	store := audit.NewInMemoryAuditStore()
	_, err := store.Get("aud_0190f2a81b3c7abc8123000000000001")
	if !errors.Is(err, audit.ErrNotFound) {
		t.Fatalf("Get unknown: want ErrNotFound, got %v", err)
	}
}

func TestWriteValidation_InvalidOutcome(t *testing.T) {
	store := audit.NewInMemoryAuditStore()
	in := validInput()
	in.Outcome = "unknown"
	_, err := store.Write(in)
	if !audit.IsInvalidFormat(err) {
		t.Fatalf("invalid outcome: want InvalidFormatError, got %v", err)
	}
}

func TestWriteValidation_ActorUsrIDWrongType(t *testing.T) {
	store := audit.NewInMemoryAuditStore()
	in := validInput()
	orgID, _ := ids.Generate("org")
	in.ActorUsrID = &orgID
	_, err := store.Write(in)
	if !audit.IsInvalidFormat(err) {
		t.Fatalf("org_id as actor_usr_id: want InvalidFormatError, got %v", err)
	}
}

func TestWriteValidation_AuthKindMismatch(t *testing.T) {
	store := audit.NewInMemoryAuditStore()
	in := validInput()
	patID := "pat_0190f2a81b3c7abc8123000000000003"
	// kind=session but pat_id present (not session_id)
	in.Auth = &audit.Auth{Kind: audit.AuthKindSession, PatID: &patID}
	_, err := store.Write(in)
	if !audit.IsInvalidFormat(err) {
		t.Fatalf("auth kind mismatch: want InvalidFormatError, got %v", err)
	}
}

func TestWriteValidation_AuthMultipleIDs(t *testing.T) {
	store := audit.NewInMemoryAuditStore()
	in := validInput()
	sesID := "ses_0190f2a81b3c7abc8123000000000007"
	patID := "pat_0190f2a81b3c7abc8123000000000003"
	in.Auth = &audit.Auth{Kind: audit.AuthKindSession, SessionID: &sesID, PatID: &patID}
	_, err := store.Write(in)
	if !audit.IsInvalidFormat(err) {
		t.Fatalf("multiple auth ids: want InvalidFormatError, got %v", err)
	}
}

func TestWriteValidation_TargetKindInvalid(t *testing.T) {
	store := audit.NewInMemoryAuditStore()
	in := validInput()
	in.Target.Kind = "INVALID_TYPE_TOO_LONG_AND_UPPERCASE"
	_, err := store.Write(in)
	if !audit.IsInvalidFormat(err) {
		t.Fatalf("invalid target.kind: want InvalidFormatError, got %v", err)
	}
}

func TestWriteValidation_OpaqueFieldsNotValidated(t *testing.T) {
	// action, on_behalf.agent_id, auth.system_id, and adopter target.id
	// are opaque — Write must not reject them regardless of content.
	store := audit.NewInMemoryAuditStore()
	in := validInput()
	sysID := "totally-opaque-string-with-unicode-🔥"
	in.Auth = &audit.Auth{Kind: audit.AuthKindSystem, SystemID: &sysID}
	in.ActorUsrID = nil
	in.OnBehalf = &audit.OnBehalf{AgentID: "any-agent-id-format"}
	in.Action = "adopter.custom.verb::with-special-chars"
	in.Target = audit.Target{Kind: "doc", ID: "legacy-project-42-not-a-ft-id"}
	_, err := store.Write(in)
	if err != nil {
		t.Fatalf("opaque fields: Write should not reject them, got %v", err)
	}
}
