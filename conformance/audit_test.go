// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

// Conformance runner for the audit write-event-shape fixture (ADR 0019).
// Tests write→get round-trips asserting structural invariants of the
// AuditEvent shape. Matching is superset: the expected object lists fields
// whose values ADR 0019 pins; server-set fields (recorded_at) are not asserted.

package conformance

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/flametrench/flametrench-go/packages/audit"
	"github.com/flametrench/flametrench-go/packages/ids"
)

// ── helpers ─────────────────────────────────────────────────────────────────

func resolveMapStrings(m map[string]any, captures map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		switch tv := v.(type) {
		case string:
			out[k] = resolveStr(tv, captures)
		case map[string]any:
			out[k] = resolveMapStrings(tv, captures)
		default:
			out[k] = v
		}
	}
	return out
}

// parseWriteInput converts a raw JSON input map to audit.WriteInput.
func parseWriteInput(input map[string]any, captures map[string]string) audit.WriteInput {
	input = resolveMapStrings(input, captures)

	var in audit.WriteInput

	if s, ok := input["occurred_at"].(string); ok {
		t, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			t, _ = time.Parse(time.RFC3339, s)
		}
		in.OccurredAt = t
	}

	if v, ok := input["actor_usr_id"]; ok {
		if v != nil {
			if s, ok := v.(string); ok {
				in.ActorUsrID = &s
			}
		}
	}

	if authRaw, ok := input["auth"].(map[string]any); ok {
		a := &audit.Auth{}
		if k, ok := authRaw["kind"].(string); ok {
			a.Kind = audit.AuthKind(k)
		}
		if s, ok := authRaw["session_id"].(string); ok {
			a.SessionID = &s
		}
		if s, ok := authRaw["pat_id"].(string); ok {
			a.PatID = &s
		}
		if s, ok := authRaw["share_id"].(string); ok {
			a.ShareID = &s
		}
		if s, ok := authRaw["system_id"].(string); ok {
			a.SystemID = &s
		}
		in.Auth = a
	}

	if obRaw, ok := input["on_behalf"].(map[string]any); ok {
		if id, ok := obRaw["agent_id"].(string); ok {
			in.OnBehalf = &audit.OnBehalf{AgentID: id}
		}
	}

	if s, ok := input["action"].(string); ok {
		in.Action = s
	}

	if tRaw, ok := input["target"].(map[string]any); ok {
		in.Target = audit.Target{
			Kind: strFieldAny(tRaw, "kind"),
			ID:   strFieldAny(tRaw, "id"),
		}
	}

	if sRaw, ok := input["scope"].(map[string]any); ok {
		in.Scope = &audit.Scope{
			Kind: strFieldAny(sRaw, "kind"),
			ID:   strFieldAny(sRaw, "id"),
		}
	}

	if o, ok := input["outcome"].(string); ok {
		in.Outcome = audit.Outcome(o)
	}

	if m, ok := input["metadata"].(map[string]any); ok {
		in.Metadata = m
	}

	if ctxRaw, ok := input["context"].(map[string]any); ok {
		ctx := &audit.EventContext{}
		if s, ok := ctxRaw["request_id"].(string); ok {
			ctx.RequestID = &s
		}
		if s, ok := ctxRaw["ip"].(string); ok {
			ctx.IP = &s
		}
		if s, ok := ctxRaw["user_agent"].(string); ok {
			ctx.UserAgent = &s
		}
		in.Context = ctx
	}

	return in
}

func strFieldAny(m map[string]any, key string) string {
	if s, ok := m[key].(string); ok {
		return s
	}
	return ""
}

// assertSuperset checks that every field in expected is present and equal in
// actual. Extra fields in actual are fine (server-set fields like recorded_at).
func assertAuditSuperset(t *testing.T, caseID, stepLabel string, expected map[string]any, ev audit.AuditEvent, captures map[string]string) {
	t.Helper()
	expected = resolveMapStrings(expected, captures)
	for key, wantVal := range expected {
		switch key {
		case "id":
			if s, ok := wantVal.(string); ok && ev.ID != s {
				t.Errorf("%s/%s: id = %q, want %q", caseID, stepLabel, ev.ID, s)
			}
		case "actor_usr_id":
			if wantVal == nil {
				if ev.ActorUsrID != nil {
					t.Errorf("%s/%s: actor_usr_id = %q, want null", caseID, stepLabel, *ev.ActorUsrID)
				}
			} else if s, ok := wantVal.(string); ok {
				if ev.ActorUsrID == nil {
					t.Errorf("%s/%s: actor_usr_id = null, want %q", caseID, stepLabel, s)
				} else if *ev.ActorUsrID != s {
					t.Errorf("%s/%s: actor_usr_id = %q, want %q", caseID, stepLabel, *ev.ActorUsrID, s)
				}
			}
		case "occurred_at":
			if s, ok := wantVal.(string); ok {
				want, _ := time.Parse(time.RFC3339, s)
				if !ev.OccurredAt.UTC().Equal(want.UTC()) {
					t.Errorf("%s/%s: occurred_at = %v, want %v", caseID, stepLabel, ev.OccurredAt, want)
				}
			}
		case "auth":
			wantAuth, ok := wantVal.(map[string]any)
			if !ok {
				break
			}
			if ev.Auth == nil {
				t.Errorf("%s/%s: auth = nil, want %v", caseID, stepLabel, wantAuth)
				break
			}
			if k, ok := wantAuth["kind"].(string); ok && string(ev.Auth.Kind) != k {
				t.Errorf("%s/%s: auth.kind = %q, want %q", caseID, stepLabel, ev.Auth.Kind, k)
			}
			if s, ok := wantAuth["session_id"].(string); ok {
				if ev.Auth.SessionID == nil || *ev.Auth.SessionID != s {
					got := "<nil>"
					if ev.Auth.SessionID != nil {
						got = *ev.Auth.SessionID
					}
					t.Errorf("%s/%s: auth.session_id = %q, want %q", caseID, stepLabel, got, s)
				}
			}
			if s, ok := wantAuth["pat_id"].(string); ok {
				if ev.Auth.PatID == nil || *ev.Auth.PatID != s {
					got := "<nil>"
					if ev.Auth.PatID != nil {
						got = *ev.Auth.PatID
					}
					t.Errorf("%s/%s: auth.pat_id = %q, want %q", caseID, stepLabel, got, s)
				}
			}
			if s, ok := wantAuth["share_id"].(string); ok {
				if ev.Auth.ShareID == nil || *ev.Auth.ShareID != s {
					got := "<nil>"
					if ev.Auth.ShareID != nil {
						got = *ev.Auth.ShareID
					}
					t.Errorf("%s/%s: auth.share_id = %q, want %q", caseID, stepLabel, got, s)
				}
			}
			if s, ok := wantAuth["system_id"].(string); ok {
				if ev.Auth.SystemID == nil || *ev.Auth.SystemID != s {
					got := "<nil>"
					if ev.Auth.SystemID != nil {
						got = *ev.Auth.SystemID
					}
					t.Errorf("%s/%s: auth.system_id = %q, want %q", caseID, stepLabel, got, s)
				}
			}
		case "on_behalf":
			wantOB, ok := wantVal.(map[string]any)
			if !ok {
				break
			}
			if ev.OnBehalf == nil {
				t.Errorf("%s/%s: on_behalf = nil, want %v", caseID, stepLabel, wantOB)
				break
			}
			if s, ok := wantOB["agent_id"].(string); ok && ev.OnBehalf.AgentID != s {
				t.Errorf("%s/%s: on_behalf.agent_id = %q, want %q", caseID, stepLabel, ev.OnBehalf.AgentID, s)
			}
		case "action":
			if s, ok := wantVal.(string); ok && ev.Action != s {
				t.Errorf("%s/%s: action = %q, want %q", caseID, stepLabel, ev.Action, s)
			}
		case "target":
			if wantT, ok := wantVal.(map[string]any); ok {
				if k, ok := wantT["kind"].(string); ok && ev.Target.Kind != k {
					t.Errorf("%s/%s: target.kind = %q, want %q", caseID, stepLabel, ev.Target.Kind, k)
				}
				if id, ok := wantT["id"].(string); ok && ev.Target.ID != id {
					t.Errorf("%s/%s: target.id = %q, want %q", caseID, stepLabel, ev.Target.ID, id)
				}
			}
		case "scope":
			if wantS, ok := wantVal.(map[string]any); ok {
				if ev.Scope == nil {
					t.Errorf("%s/%s: scope = nil, want %v", caseID, stepLabel, wantS)
					break
				}
				if k, ok := wantS["kind"].(string); ok && ev.Scope.Kind != k {
					t.Errorf("%s/%s: scope.kind = %q, want %q", caseID, stepLabel, ev.Scope.Kind, k)
				}
				if id, ok := wantS["id"].(string); ok && ev.Scope.ID != id {
					t.Errorf("%s/%s: scope.id = %q, want %q", caseID, stepLabel, ev.Scope.ID, id)
				}
			}
		case "outcome":
			if s, ok := wantVal.(string); ok && string(ev.Outcome) != s {
				t.Errorf("%s/%s: outcome = %q, want %q", caseID, stepLabel, ev.Outcome, s)
			}
		case "metadata":
			if wantM, ok := wantVal.(map[string]any); ok {
				for mk, mv := range wantM {
					gotV, exists := ev.Metadata[mk]
					if !exists {
						t.Errorf("%s/%s: metadata[%q] missing, want %v", caseID, stepLabel, mk, mv)
					} else if !reflect.DeepEqual(gotV, mv) {
						t.Errorf("%s/%s: metadata[%q] = %v, want %v", caseID, stepLabel, mk, gotV, mv)
					}
				}
			}
		}
	}
}

// ── runner ───────────────────────────────────────────────────────────────────

func runAuditCase(t *testing.T, c StepCase) {
	t.Helper()
	store := audit.NewInMemoryAuditStore()
	captures := make(map[string]string)

	// Pre-create usr_ IDs for each named user.
	for _, name := range c.Users {
		id, err := ids.Generate("usr")
		if err != nil {
			t.Fatalf("%s: generate usr id for %q: %v", c.ID, name, err)
		}
		captures[name] = id
	}

	for _, step := range c.Steps {
		label := step.Op
		input := resolveInput(step.Input, captures)

		switch step.Op {
		case "write":
			in := parseWriteInput(input, captures)
			ev, err := store.Write(in)
			if err != nil {
				t.Fatalf("%s/%s: write: %v", c.ID, label, err)
			}
			for varName, path := range step.Captures {
				if path == "id" {
					captures[varName] = ev.ID
				}
			}

		case "get":
			audID, _ := input["id"].(string)
			ev, err := store.Get(audID)
			if err != nil {
				t.Fatalf("%s/%s: get(%q): %v", c.ID, label, audID, err)
			}
			if res, ok := step.Expected["result"].(map[string]any); ok {
				assertAuditSuperset(t, c.ID, label, res, ev, captures)
			}

		default:
			t.Fatalf("%s: unknown op %q", c.ID, step.Op)
		}
	}
}

func runAuditFixture(t *testing.T, path string) {
	t.Helper()
	f := loadStepFixtureFile(t, path)
	for _, c := range f.Tests {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			runAuditCase(t, c)
		})
	}
}

func TestWriteEventShapeConformance(t *testing.T) {
	runAuditFixture(t, filepath.Join("fixtures", "audit", "write-event-shape.json"))
}
