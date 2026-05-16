// Conformance runner — drives the Flametrench JSON fixture corpus
// against packages/ids and asserts byte-identical outputs with the
// Python / Node / PHP / Java SDKs.
//
// The fixtures here are vendored from `flametrench/spec/conformance/fixtures/`
// (see VENDORED-FROM for the pinned source). Refresh by re-copying from the
// spec repo and re-running this test.
//
// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
package conformance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/flametrench/flametrench-go/packages/ids"
)

// Fixture is the shape of the spec's conformance JSON files.
type Fixture struct {
	SpecVersion      string         `json:"spec_version"`
	Capability       string         `json:"capability"`
	Operation        string         `json:"operation"`
	ConformanceLevel string         `json:"conformance_level"`
	SpecSection      string         `json:"spec_section"`
	Description      string         `json:"description"`
	Tests            []FixtureCase  `json:"tests"`
}

type FixtureCase struct {
	ID          string         `json:"id"`
	Description string         `json:"description"`
	Input       map[string]any `json:"input"`
	Expected    map[string]any `json:"expected"`
}

func loadFixture(t *testing.T, path string) Fixture {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var f Fixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return f
}

// classifyError maps a Go error into one of the conformance error class
// names the spec fixtures use ("InvalidIdError" / "InvalidTypeError").
func classifyError(err error) string {
	if err == nil {
		return ""
	}
	if ids.IsInvalidType(err) {
		return "InvalidTypeError"
	}
	if ids.IsInvalidID(err) {
		return "InvalidIdError"
	}
	return "UnknownError:" + err.Error()
}

func assertExpectedError(t *testing.T, caseID string, expected map[string]any, got error) {
	t.Helper()
	rawWant, ok := expected["error"]
	if !ok {
		t.Fatalf("%s: case has no expected.error but got error: %v", caseID, got)
	}
	want, ok := rawWant.(string)
	if !ok {
		t.Fatalf("%s: expected.error is not a string: %v", caseID, rawWant)
	}
	gotClass := classifyError(got)
	if gotClass != want {
		t.Errorf("%s: error class = %q, want %q (raw err: %v)", caseID, gotClass, want, got)
	}
	if matches, ok := expected["error_matches"].(string); ok && matches != "" {
		if !strings.Contains(strings.ToLower(got.Error()), strings.ToLower(matches)) {
			t.Errorf("%s: error message %q does not contain %q", caseID, got.Error(), matches)
		}
	}
}

// assertExpectedResult compares actual against expected.result for a
// simple value (string, bool, or {type,uuid} map).
func assertExpectedResult(t *testing.T, caseID string, expected map[string]any, actual any) {
	t.Helper()
	want, ok := expected["result"]
	if !ok {
		t.Fatalf("%s: no expected.result on success path", caseID)
	}
	switch wantTyped := want.(type) {
	case string:
		gotStr, ok := actual.(string)
		if !ok {
			t.Errorf("%s: actual = %v (%T); want string %q", caseID, actual, actual, wantTyped)
			return
		}
		if gotStr != wantTyped {
			t.Errorf("%s: result = %q; want %q", caseID, gotStr, wantTyped)
		}
	case bool:
		gotBool, ok := actual.(bool)
		if !ok {
			t.Errorf("%s: actual = %v (%T); want bool %v", caseID, actual, actual, wantTyped)
			return
		}
		if gotBool != wantTyped {
			t.Errorf("%s: result = %v; want %v", caseID, gotBool, wantTyped)
		}
	case map[string]any:
		gotMap, ok := actual.(map[string]any)
		if !ok {
			t.Errorf("%s: actual = %v (%T); want map %v", caseID, actual, actual, wantTyped)
			return
		}
		// Compare each expected key — actual may have more, that's fine.
		for k, v := range wantTyped {
			if gotMap[k] != v {
				t.Errorf("%s: result.%s = %v; want %v", caseID, k, gotMap[k], v)
			}
		}
	default:
		t.Fatalf("%s: unsupported expected.result type %T: %v", caseID, want, want)
	}
}

// runEncode executes the ids.Encode case.
func runEncode(t *testing.T, c FixtureCase) {
	typ, _ := c.Input["type"].(string)
	uuidStr, _ := c.Input["uuid"].(string)
	result, err := ids.Encode(typ, uuidStr)
	if _, expectsError := c.Expected["error"]; expectsError {
		if err == nil {
			t.Errorf("%s: Encode(%q,%q) succeeded with %q; want error", c.ID, typ, uuidStr, result)
			return
		}
		assertExpectedError(t, c.ID, c.Expected, err)
		return
	}
	if err != nil {
		t.Errorf("%s: Encode(%q,%q) errored: %v", c.ID, typ, uuidStr, err)
		return
	}
	assertExpectedResult(t, c.ID, c.Expected, result)
}

func runDecode(t *testing.T, c FixtureCase) {
	id, _ := c.Input["id"].(string)
	result, err := ids.Decode(id)
	if _, expectsError := c.Expected["error"]; expectsError {
		if err == nil {
			t.Errorf("%s: Decode(%q) succeeded with %+v; want error", c.ID, id, result)
			return
		}
		assertExpectedError(t, c.ID, c.Expected, err)
		return
	}
	if err != nil {
		t.Errorf("%s: Decode(%q) errored: %v", c.ID, id, err)
		return
	}
	asMap := map[string]any{"type": result.Type, "uuid": result.UUID}
	assertExpectedResult(t, c.ID, c.Expected, asMap)
}

func runIsValid(t *testing.T, c FixtureCase) {
	id, _ := c.Input["id"].(string)
	expectedType, _ := c.Input["expected_type"].(string)
	var ok bool
	if expectedType != "" {
		ok = ids.IsValid(id, expectedType)
	} else {
		ok = ids.IsValid(id)
	}
	assertExpectedResult(t, c.ID, c.Expected, ok)
}

func runTypeOf(t *testing.T, c FixtureCase) {
	id, _ := c.Input["id"].(string)
	typ, err := ids.TypeOf(id)
	if _, expectsError := c.Expected["error"]; expectsError {
		if err == nil {
			t.Errorf("%s: TypeOf(%q) succeeded with %q; want error", c.ID, id, typ)
			return
		}
		assertExpectedError(t, c.ID, c.Expected, err)
		return
	}
	if err != nil {
		t.Errorf("%s: TypeOf(%q) errored: %v", c.ID, id, err)
		return
	}
	assertExpectedResult(t, c.ID, c.Expected, typ)
}

func dispatch(t *testing.T, op string, c FixtureCase) {
	switch op {
	case "encode":
		runEncode(t, c)
	case "decode":
		runDecode(t, c)
	case "is_valid":
		runIsValid(t, c)
	case "type_of":
		runTypeOf(t, c)
	default:
		t.Fatalf("unknown operation %q in fixture", op)
	}
}

func TestIDsConformance(t *testing.T) {
	root := filepath.Join("fixtures", "ids")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}
	totalTests := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(root, entry.Name())
		fixture := loadFixture(t, path)
		if fixture.Capability != "ids" {
			continue
		}
		t.Run(fmt.Sprintf("%s_%s", fixture.Operation, entry.Name()), func(t *testing.T) {
			for _, c := range fixture.Tests {
				c := c
				t.Run(c.ID, func(t *testing.T) {
					dispatch(t, fixture.Operation, c)
				})
				totalTests++
			}
		})
	}
	t.Logf("ids conformance: %d cases across %d fixture files", totalTests, len(entries))
}
