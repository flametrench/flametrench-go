// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

// Conformance runner for the notifications fixtures (ADR 0022):
//   - lifecycle-shape.json  — 4 positive vectors (create/state transitions)
//   - recipient-scope.json  — 3 negative IDOR vectors (cross-recipient access)
//
// Access is SDK-enforced Option-2: every per-notification op takes
// recipient_usr_id; cross-recipient and non-existent resolve to the same
// NotFoundError (existence non-disclosure).

package conformance

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/flametrench/flametrench-go/packages/ids"
	"github.com/flametrench/flametrench-go/packages/notify"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func notifyResultToMap(n notify.Notification) map[string]any {
	b, _ := json.Marshal(n)
	var m map[string]any
	json.Unmarshal(b, &m) //nolint:errcheck
	return m
}

func assertNotifySuperset(t *testing.T, caseID, label string, expected map[string]any, actual notify.Notification, captures map[string]string) {
	t.Helper()
	resolved := resolveInput(expected, captures)
	actual_m := notifyResultToMap(actual)
	assertNotifyMapSuperset(t, caseID+"/"+label, actual_m, resolved)
}

func assertNotifyMapSuperset(t *testing.T, label string, actual, expected map[string]any) {
	t.Helper()
	for k, ev := range expected {
		av, ok := actual[k]
		if !ok {
			t.Errorf("%s: missing field %q", label, k)
			continue
		}
		switch eMap := ev.(type) {
		case map[string]any:
			aMap, aOk := av.(map[string]interface{})
			if !aOk {
				t.Errorf("%s: field %q: expected map, got %T", label, k, av)
				continue
			}
			assertNotifyMapSuperset(t, label+"."+k, aMap, eMap)
		default:
			es := fmt.Sprintf("%v", ev)
			as := fmt.Sprintf("%v", av)
			if es != as {
				t.Errorf("%s: field %q: got %q, want %q", label, k, as, es)
			}
		}
	}
}

func matchNotifyError(err error, name string) bool {
	switch name {
	case "NotFoundError":
		return errors.Is(err, notify.ErrNotFound)
	case "PreconditionError":
		return notify.IsPrecondition(err)
	case "InvalidFormatError":
		return notify.IsInvalidFormat(err)
	}
	return false
}

// ── runner ───────────────────────────────────────────────────────────────────

func runNotifyCase(t *testing.T, c StepCase) {
	t.Helper()
	store := notify.NewInMemoryNotificationStore()
	captures := make(map[string]string)

	for _, name := range c.Users {
		id, err := ids.Generate("usr")
		if err != nil {
			t.Fatalf("%s: generate usr id for %q: %v", c.ID, name, err)
		}
		captures[name] = id
	}

	// default recipient = first named user
	defaultRecipient := ""
	if len(c.Users) > 0 {
		defaultRecipient = captures[c.Users[0]]
	}

	for i, step := range c.Steps {
		label := fmt.Sprintf("step[%d]/%s", i, step.Op)
		input := resolveInput(step.Input, captures)

		recipientUsrID := strField(input, "recipient_usr_id")
		if recipientUsrID == "" {
			recipientUsrID = defaultRecipient
		}
		notifID := strField(input, "id")

		var result notify.Notification
		var err error

		switch step.Op {
		case "create_notification":
			in := notify.CreateNotificationInput{
				Scope:          strField(input, "scope"),
				RecipientUsrID: strField(input, "recipient_usr_id"),
				Type:           strField(input, "type"),
			}
			if sub, ok := input["subject"].(map[string]any); ok {
				in.Subject = notify.Subject{
					Kind: strField(sub, "kind"),
					ID:   strField(sub, "id"),
				}
			}
			if d, ok := input["data"].(map[string]any); ok {
				in.Data = d
			} else {
				in.Data = map[string]any{}
			}
			result, err = store.CreateNotification(in)
			if err == nil {
				for varName, field := range step.Captures {
					if field == "id" {
						captures[varName] = result.ID
					}
				}
			}

		case "get_notification":
			result, err = store.GetNotification(recipientUsrID, notifID)

		case "mark_read":
			result, err = store.MarkRead(recipientUsrID, notifID)

		case "mark_unread":
			result, err = store.MarkUnread(recipientUsrID, notifID)

		case "dismiss":
			result, err = store.Dismiss(recipientUsrID, notifID)

		default:
			t.Fatalf("%s: %s: unknown op %q", c.ID, label, step.Op)
		}

		if step.Expected == nil {
			if err != nil {
				t.Errorf("%s: %s: unexpected error: %v", c.ID, label, err)
			}
			continue
		}

		if errName, ok := step.Expected["error"].(string); ok && errName != "" {
			if err == nil {
				t.Errorf("%s: %s: expected error %q but got result %+v", c.ID, label, errName, result)
				continue
			}
			if !matchNotifyError(err, errName) {
				t.Errorf("%s: %s: expected error %q, got %v", c.ID, label, errName, err)
			}
			continue
		}

		if err != nil {
			t.Errorf("%s: %s: unexpected error: %v", c.ID, label, err)
			continue
		}

		if res, ok := step.Expected["result"].(map[string]any); ok {
			assertNotifySuperset(t, c.ID, step.Op, res, result, captures)
		}
	}
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestNotificationLifecycleConformance(t *testing.T) {
	path := filepath.Join("fixtures", "notifications", "lifecycle-shape.json")
	f := loadStepFixtureFile(t, path)
	for _, c := range f.Tests {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			runNotifyCase(t, c)
		})
	}
}

func TestNotificationRecipientScopeConformance(t *testing.T) {
	path := filepath.Join("fixtures", "notifications", "recipient-scope.json")
	f := loadStepFixtureFile(t, path)
	for _, c := range f.Tests {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			runNotifyCase(t, c)
		})
	}
}
