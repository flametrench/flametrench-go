// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

// Conformance runners for all authorization fixtures: check, check-any,
// format, uniqueness, and the three rewrite-rule fixtures.

package conformance

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/flametrench/flametrench-go/packages/authz"
)

// AuthzFixtureCase is the per-test-case shape for authz fixtures.
// It extends FixtureCase with an optional top-level `rules` field
// (used by the rewrite-rule fixtures).
type AuthzFixtureCase struct {
	ID          string                              `json:"id"`
	Description string                              `json:"description"`
	Rules       map[string]map[string][]map[string]any `json:"rules"`
	Input       map[string]any                      `json:"input"`
	Expected    map[string]any                      `json:"expected"`
}

// AuthzFixtureFile is the top-level shape of an authz fixture JSON file.
type AuthzFixtureFile struct {
	Capability string             `json:"capability"`
	Operation  string             `json:"operation"`
	Tests      []AuthzFixtureCase `json:"tests"`
}

func loadAuthzFixture(t *testing.T, path string) AuthzFixtureFile {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var f AuthzFixtureFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return f
}

// classifyAuthzError maps a Go error to the fixture error class name.
func classifyAuthzError(err error) string {
	if errors.Is(err, authz.ErrDuplicateTuple) {
		return "DuplicateTupleError"
	}
	if errors.Is(err, authz.ErrEmptyRelationSet) {
		return "EmptyRelationSetError"
	}
	if errors.Is(err, authz.ErrInvalidFormat) {
		return "InvalidFormatError"
	}
	return "UnknownError:" + err.Error()
}

// parseAuthzRules converts the raw JSON rules map to authz.Rules.
func parseAuthzRules(raw map[string]map[string][]map[string]any) authz.Rules {
	if raw == nil {
		return nil
	}
	rules := make(authz.Rules, len(raw))
	for objectType, relMap := range raw {
		rules[objectType] = make(map[string]authz.Rule, len(relMap))
		for relation, nodes := range relMap {
			rule := make(authz.Rule, 0, len(nodes))
			for _, node := range nodes {
				switch node["type"] {
				case "this":
					rule = append(rule, authz.This{})
				case "computed_userset":
					rel, _ := node["relation"].(string)
					rule = append(rule, authz.ComputedUserset{Relation: rel})
				case "tuple_to_userset":
					tsr, _ := node["tupleset_relation"].(string)
					cur, _ := node["computed_userset_relation"].(string)
					rule = append(rule, authz.TupleToUserset{
						TuplesetRelation:        tsr,
						ComputedUsersetRelation: cur,
					})
				}
			}
			rules[objectType][relation] = rule
		}
	}
	return rules
}

// seedTuples creates the given_tuples in the store. Returns false if any creation fails.
func seedTuples(t *testing.T, caseID string, store authz.TupleStore, givenRaw any) bool {
	t.Helper()
	given, _ := givenRaw.([]any)
	for _, raw := range given {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		_, err := store.CreateTuple(authz.CreateTupleInput{
			SubjectType: strField(m, "subject_type"),
			SubjectID:   strField(m, "subject_id"),
			Relation:    strField(m, "relation"),
			ObjectType:  strField(m, "object_type"),
			ObjectID:    strField(m, "object_id"),
		})
		if err != nil {
			t.Errorf("%s: seed tuple: %v", caseID, err)
			return false
		}
	}
	return true
}

// runAuthzCheckCase runs a single check or check_any fixture case.
func runAuthzCheckCase(t *testing.T, c AuthzFixtureCase, store authz.TupleStore) {
	t.Helper()
	checkRaw, _ := c.Input["check"].(map[string]any)
	if checkRaw == nil {
		t.Fatalf("%s: missing input.check", c.ID)
	}

	wantResult, _ := c.Expected["result"].(map[string]any)
	wantError, _ := c.Expected["error"].(string)

	// check_any if "relations" key present, else check.
	if relRaw, ok := checkRaw["relations"]; ok {
		var relations []string
		for _, r := range relRaw.([]any) {
			relations = append(relations, r.(string))
		}
		result, err := store.CheckAny(authz.CheckAnyInput{
			SubjectType: strField(checkRaw, "subject_type"),
			SubjectID:   strField(checkRaw, "subject_id"),
			Relations:   relations,
			ObjectType:  strField(checkRaw, "object_type"),
			ObjectID:    strField(checkRaw, "object_id"),
		})
		if wantError != "" {
			if err == nil {
				t.Errorf("%s: expected %s but got no error", c.ID, wantError)
				return
			}
			got := classifyAuthzError(err)
			if got != wantError {
				t.Errorf("%s: error = %q, want %q", c.ID, got, wantError)
			}
			return
		}
		if err != nil {
			t.Errorf("%s: CheckAny: %v", c.ID, err)
			return
		}
		wantAllowed, _ := wantResult["allowed"].(bool)
		if result.Allowed != wantAllowed {
			t.Errorf("%s: allowed = %v, want %v", c.ID, result.Allowed, wantAllowed)
		}
		return
	}

	result, err := store.Check(authz.CheckInput{
		SubjectType: strField(checkRaw, "subject_type"),
		SubjectID:   strField(checkRaw, "subject_id"),
		Relation:    strField(checkRaw, "relation"),
		ObjectType:  strField(checkRaw, "object_type"),
		ObjectID:    strField(checkRaw, "object_id"),
	})
	if wantError != "" {
		if err == nil {
			t.Errorf("%s: expected %s but got no error", c.ID, wantError)
			return
		}
		got := classifyAuthzError(err)
		if got != wantError {
			t.Errorf("%s: error = %q, want %q", c.ID, got, wantError)
		}
		return
	}
	if err != nil {
		t.Errorf("%s: Check: %v", c.ID, err)
		return
	}
	wantAllowed, _ := wantResult["allowed"].(bool)
	if result.Allowed != wantAllowed {
		t.Errorf("%s: allowed = %v, want %v", c.ID, result.Allowed, wantAllowed)
	}
}

// runAuthzCreateCase runs a single create_tuple fixture case (format/uniqueness).
func runAuthzCreateCase(t *testing.T, c AuthzFixtureCase, store authz.TupleStore) {
	t.Helper()
	createRaw, _ := c.Input["create"].(map[string]any)
	if createRaw == nil {
		t.Fatalf("%s: missing input.create", c.ID)
	}

	wantError, _ := c.Expected["error"].(string)
	wantResult, _ := c.Expected["result"].(string)

	_, err := store.CreateTuple(authz.CreateTupleInput{
		SubjectType: strField(createRaw, "subject_type"),
		SubjectID:   strField(createRaw, "subject_id"),
		Relation:    strField(createRaw, "relation"),
		ObjectType:  strField(createRaw, "object_type"),
		ObjectID:    strField(createRaw, "object_id"),
	})
	if wantError != "" {
		if err == nil {
			t.Errorf("%s: expected %s but got no error", c.ID, wantError)
			return
		}
		got := classifyAuthzError(err)
		if got != wantError {
			t.Errorf("%s: error = %q, want %q (raw: %v)", c.ID, got, wantError, err)
		}
		return
	}
	if err != nil {
		t.Errorf("%s: CreateTuple: %v", c.ID, err)
		return
	}
	if wantResult != "" && wantResult != "ok" {
		t.Errorf("%s: unexpected expected.result %q", c.ID, wantResult)
	}
}

func runAuthzCheckFixture(t *testing.T, path string) {
	t.Helper()
	f := loadAuthzFixture(t, path)
	for _, c := range f.Tests {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			rules := parseAuthzRules(c.Rules)
			var store authz.TupleStore
			if len(rules) > 0 {
				store = authz.NewInMemoryTupleStoreWithRules(rules, authz.EvaluateOptions{})
			} else {
				store = authz.NewInMemoryTupleStore()
			}
			if !seedTuples(t, c.ID, store, c.Input["given_tuples"]) {
				return
			}
			runAuthzCheckCase(t, c, store)
		})
	}
}

func runAuthzCreateFixture(t *testing.T, path string) {
	t.Helper()
	f := loadAuthzFixture(t, path)
	for _, c := range f.Tests {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			store := authz.NewInMemoryTupleStore()
			if !seedTuples(t, c.ID, store, c.Input["given_tuples"]) {
				return
			}
			runAuthzCreateCase(t, c, store)
		})
	}
}

func TestAuthzCheckConformance(t *testing.T) {
	runAuthzCheckFixture(t, filepath.Join("fixtures", "authorization", "check.json"))
}

func TestAuthzCheckAnyConformance(t *testing.T) {
	runAuthzCheckFixture(t, filepath.Join("fixtures", "authorization", "check-any.json"))
}

func TestAuthzFormatConformance(t *testing.T) {
	runAuthzCreateFixture(t, filepath.Join("fixtures", "authorization", "format.json"))
}

func TestAuthzUniquenessConformance(t *testing.T) {
	runAuthzCreateFixture(t, filepath.Join("fixtures", "authorization", "uniqueness.json"))
}

func TestAuthzComputedUsersetConformance(t *testing.T) {
	runAuthzCheckFixture(t, filepath.Join("fixtures", "authorization", "rewrite-rules", "computed-userset.json"))
}

func TestAuthzTupleToUsersetConformance(t *testing.T) {
	runAuthzCheckFixture(t, filepath.Join("fixtures", "authorization", "rewrite-rules", "tuple-to-userset.json"))
}

func TestAuthzEmptyRulesEqualsV01Conformance(t *testing.T) {
	runAuthzCheckFixture(t, filepath.Join("fixtures", "authorization", "rewrite-rules", "empty-rules-equals-v01.json"))
}
