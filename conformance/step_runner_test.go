// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

// Shared infrastructure for the stateful step-based conformance runners
// used by identity_stateful_test.go and tenancy_test.go.

package conformance

import (
	"encoding/json"
	"os"
	"regexp"
	"testing"
)

// StepCase is the stateful step-based test case shape.
type StepCase struct {
	ID          string        `json:"id"`
	Description string        `json:"description"`
	Users       []string      `json:"users"`
	Steps       []FixtureStep `json:"steps"`
}

// FixtureStep is one step in a stateful conformance scenario.
type FixtureStep struct {
	Op       string            `json:"op"`
	Input    map[string]any    `json:"input"`
	Expected map[string]any    `json:"expected"`
	Captures map[string]string `json:"captures"`
}

// StepFixtureFile is the top-level shape of a step-based fixture JSON file.
type StepFixtureFile struct {
	Capability string     `json:"capability"`
	Operation  string     `json:"operation"`
	Tests      []StepCase `json:"tests"`
}

func loadStepFixtureFile(t *testing.T, path string) StepFixtureFile {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var f StepFixtureFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return f
}

var varRe = regexp.MustCompile(`\{([^}]+)\}`)

// resolveStr replaces every {var} in s with its captured value.
func resolveStr(s string, captures map[string]string) string {
	return varRe.ReplaceAllStringFunc(s, func(m string) string {
		key := m[1 : len(m)-1]
		if v, ok := captures[key]; ok {
			return v
		}
		return m
	})
}

// resolveAny recursively resolves {var} in strings, maps, and slices.
func resolveAny(v any, captures map[string]string) any {
	switch val := v.(type) {
	case string:
		return resolveStr(val, captures)
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, mv := range val {
			// Also resolve {var} in map keys (needed for user_display_names assertions).
			resolvedKey := resolveStr(k, captures)
			out[resolvedKey] = resolveAny(mv, captures)
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, elem := range val {
			out[i] = resolveAny(elem, captures)
		}
		return out
	default:
		return v
	}
}

// resolveInput resolves all {var} references in a step input map.
func resolveInput(m map[string]any, captures map[string]string) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = resolveAny(v, captures)
	}
	return out
}

// strField returns m[key] as a string, "" if absent or non-string.
func strField(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

// strPtr returns a *string from m[key], nil if absent or JSON null.
func strPtr(m map[string]any, key string) *string {
	raw, ok := m[key]
	if !ok || raw == nil {
		return nil
	}
	s, ok := raw.(string)
	if !ok {
		return nil
	}
	return &s
}

// hasKey reports whether key is present in the map (even if the value is nil).
func hasKey(m map[string]any, key string) bool {
	_, ok := m[key]
	return ok
}

// toStringSlice converts []any to []string; panics if any element is not a string.
func toStringSlice(v any) []string {
	if v == nil {
		return nil
	}
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, len(raw))
	for i, elem := range raw {
		out[i], _ = elem.(string)
	}
	return out
}
