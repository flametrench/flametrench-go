// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
package flags

import (
	"errors"
	"testing"
)

func newTestStore(t *testing.T) *InMemoryFlagsStore {
	t.Helper()
	return NewInMemoryFlagsStore()
}

const testScope = "org_0190f2a81b3c7abc8123000000000004"

func TestAssignBucket_Deterministic(t *testing.T) {
	a := AssignBucket("new-checkout", "usr_0190f2a81b3c7abc8123000000000002")
	b := AssignBucket("new-checkout", "usr_0190f2a81b3c7abc8123000000000002")
	if a != b {
		t.Errorf("AssignBucket is not deterministic: %d != %d", a, b)
	}
}

func TestAssignBucket_Range(t *testing.T) {
	v := AssignBucket("key", "usr_0190f2a81b3c7abc8123000000000002")
	if v >= 10000 {
		t.Errorf("AssignBucket result %d out of [0,9999]", v)
	}
}

func TestCreateGetRoundTrip(t *testing.T) {
	s := newTestStore(t)
	f, err := s.CreateFlag(CreateFlagInput{
		Scope:          testScope,
		Key:            "my-flag",
		Enabled:        true,
		DefaultVariant: false,
	})
	if err != nil {
		t.Fatalf("CreateFlag: %v", err)
	}
	got, err := s.GetFlag(f.ID)
	if err != nil {
		t.Fatalf("GetFlag: %v", err)
	}
	if got.Key != "my-flag" || got.Scope != testScope {
		t.Errorf("got %+v; want key=my-flag scope=%s", got, testScope)
	}
}

func TestGetFlagByKey(t *testing.T) {
	s := newTestStore(t)
	s.CreateFlag(CreateFlagInput{Scope: testScope, Key: "lookup-me"})
	f, err := s.GetFlagByKey(testScope, "lookup-me")
	if err != nil {
		t.Fatalf("GetFlagByKey: %v", err)
	}
	if f.Key != "lookup-me" {
		t.Errorf("got key %q; want lookup-me", f.Key)
	}
	_, err = s.GetFlagByKey(testScope, "absent")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("missing key: want ErrNotFound, got %v", err)
	}
}

func TestGetNotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.GetFlag("flag_0190f2a81b3c7abc8123000000000099")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
}

func TestKeyConflict(t *testing.T) {
	s := newTestStore(t)
	s.CreateFlag(CreateFlagInput{Scope: testScope, Key: "unique"})
	_, err := s.CreateFlag(CreateFlagInput{Scope: testScope, Key: "unique"})
	if !errors.Is(err, ErrKeyConflict) {
		t.Errorf("duplicate key: want ErrKeyConflict, got %v", err)
	}
}

func TestCreateInvalidScope(t *testing.T) {
	s := newTestStore(t)
	_, err := s.CreateFlag(CreateFlagInput{Scope: "bad-scope", Key: "f"})
	if !IsInvalidFormat(err) {
		t.Errorf("bad scope: want InvalidFormatError, got %v", err)
	}
}

func TestCreateInvalidKey(t *testing.T) {
	s := newTestStore(t)
	_, err := s.CreateFlag(CreateFlagInput{Scope: testScope, Key: "BAD KEY!"})
	if !IsInvalidFormat(err) {
		t.Errorf("bad key: want InvalidFormatError, got %v", err)
	}
}

func TestCreateInvalidRule_BadRelation(t *testing.T) {
	s := newTestStore(t)
	_, err := s.CreateFlag(CreateFlagInput{
		Scope: testScope,
		Key:   "r",
		Rules: []Rule{{Kind: RuleKindAuthz, Relation: "BAD!", Object: &RuleObject{Type: "org", ID: testScope}, Variant: true}},
	})
	if !IsInvalidFormat(err) {
		t.Errorf("bad relation: want InvalidFormatError, got %v", err)
	}
}

func TestCreateInvalidRule_BadBasisPoints(t *testing.T) {
	s := newTestStore(t)
	_, err := s.CreateFlag(CreateFlagInput{
		Scope: testScope,
		Key:   "p",
		Rules: []Rule{{Kind: RuleKindPercentage, BasisPoints: 99999, Variant: true}},
	})
	if !IsInvalidFormat(err) {
		t.Errorf("bad basis_points: want InvalidFormatError, got %v", err)
	}
}

func TestUpdateFlag(t *testing.T) {
	s := newTestStore(t)
	f, _ := s.CreateFlag(CreateFlagInput{Scope: testScope, Key: "upd", Enabled: false})
	enabled := true
	updated, err := s.UpdateFlag(UpdateFlagInput{ID: f.ID, Enabled: &enabled})
	if err != nil {
		t.Fatalf("UpdateFlag: %v", err)
	}
	if !updated.Enabled {
		t.Error("Enabled not updated")
	}
	if !updated.UpdatedAt.After(f.UpdatedAt) {
		t.Error("UpdatedAt not advanced")
	}
}

func TestDeleteFlag(t *testing.T) {
	s := newTestStore(t)
	f, _ := s.CreateFlag(CreateFlagInput{Scope: testScope, Key: "del"})
	if err := s.DeleteFlag(f.ID); err != nil {
		t.Fatalf("DeleteFlag: %v", err)
	}
	if _, err := s.GetFlag(f.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete: want ErrNotFound, got %v", err)
	}
	// Key slot freed — same key can be created again.
	_, err := s.CreateFlag(CreateFlagInput{Scope: testScope, Key: "del"})
	if err != nil {
		t.Errorf("after delete, re-create same key: %v", err)
	}
}

func TestEvaluate_DisabledReturnsDefault(t *testing.T) {
	s := newTestStore(t)
	s.CreateFlag(CreateFlagInput{
		Scope:          testScope,
		Key:            "off",
		Enabled:        false,
		DefaultVariant: true,
		Rules:          []Rule{{Kind: RuleKindPercentage, BasisPoints: 10000, Variant: false}},
	})
	v, err := s.Evaluate(testScope, "off", "usr_0190f2a81b3c7abc8123000000000002", nil)
	if err != nil || v != true {
		t.Errorf("disabled flag: want true (default), got %v err=%v", v, err)
	}
}

func TestEvaluate_PercentageFull(t *testing.T) {
	s := newTestStore(t)
	s.CreateFlag(CreateFlagInput{
		Scope:   testScope,
		Key:     "full",
		Enabled: true,
		Rules:   []Rule{{Kind: RuleKindPercentage, BasisPoints: 10000, Variant: true}},
	})
	v, err := s.Evaluate(testScope, "full", "usr_0190f2a81b3c7abc8123000000000002", nil)
	if err != nil || !v {
		t.Errorf("100%% rollout: want true, got %v err=%v", v, err)
	}
}

func TestEvaluate_UnknownFlagReturnsFalse(t *testing.T) {
	s := newTestStore(t)
	v, err := s.Evaluate(testScope, "ghost", "usr_0190f2a81b3c7abc8123000000000002", nil)
	if err != nil || v != false {
		t.Errorf("unknown flag: want false, got %v err=%v", v, err)
	}
}

func TestEvaluate_AuthzRuleMatch(t *testing.T) {
	s := newTestStore(t)
	s.CreateFlag(CreateFlagInput{
		Scope:   testScope,
		Key:     "authz-flag",
		Enabled: true,
		Rules: []Rule{{
			Kind:     RuleKindAuthz,
			Relation: "editor",
			Object:   &RuleObject{Type: "org", ID: testScope},
			Variant:  true,
		}},
	})
	check := func(subjectID, relation, objType, objID string) bool { return true }
	v, err := s.Evaluate(testScope, "authz-flag", "usr_0190f2a81b3c7abc8123000000000002", check)
	if err != nil || !v {
		t.Errorf("authz match: want true, got %v err=%v", v, err)
	}
}
