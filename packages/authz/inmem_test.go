// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
package authz

import (
	"testing"
	"time"
)

func TestInMemCheckExact(t *testing.T) {
	s := NewInMemoryTupleStore()
	_, err := s.CreateTuple(CreateTupleInput{
		SubjectType: "usr", SubjectID: "alice", Relation: "viewer",
		ObjectType: "proj", ObjectID: "p1",
	})
	if err != nil {
		t.Fatalf("CreateTuple: %v", err)
	}
	r, err := s.Check(CheckInput{SubjectType: "usr", SubjectID: "alice", Relation: "viewer", ObjectType: "proj", ObjectID: "p1"})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !r.Allowed {
		t.Error("expected allowed=true")
	}

	// Wrong relation rejects.
	r2, _ := s.Check(CheckInput{SubjectType: "usr", SubjectID: "alice", Relation: "editor", ObjectType: "proj", ObjectID: "p1"})
	if r2.Allowed {
		t.Error("editor should not be allowed")
	}

	// Duplicate tuple rejects.
	if _, err := s.CreateTuple(CreateTupleInput{
		SubjectType: "usr", SubjectID: "alice", Relation: "viewer",
		ObjectType: "proj", ObjectID: "p1",
	}); err == nil {
		t.Error("duplicate tuple should reject")
	}
}

func TestInMemCheckWithRewriteRules(t *testing.T) {
	rules := Rules{
		"proj": map[string]Rule{
			"viewer": {
				This{},
				ComputedUserset{Relation: "editor"},
				TupleToUserset{TuplesetRelation: "parent_org", ComputedUsersetRelation: "member"},
			},
		},
	}
	s := NewInMemoryTupleStoreWithRules(rules, EvaluateOptions{})
	_, _ = s.CreateTuple(CreateTupleInput{
		SubjectType: "usr", SubjectID: "alice", Relation: "editor",
		ObjectType: "proj", ObjectID: "p1",
	})
	// alice is editor → should also be viewer via ComputedUserset.
	r, err := s.Check(CheckInput{SubjectType: "usr", SubjectID: "alice", Relation: "viewer", ObjectType: "proj", ObjectID: "p1"})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !r.Allowed {
		t.Error("editor-implies-viewer rule should allow")
	}

	// Org-parent hop: bob is org member; project is parent_org-attached to org. Expect viewer via TupleToUserset.
	_, _ = s.CreateTuple(CreateTupleInput{SubjectType: "usr", SubjectID: "bob", Relation: "member", ObjectType: "org", ObjectID: "o1"})
	_, _ = s.CreateTuple(CreateTupleInput{SubjectType: "org", SubjectID: "o1", Relation: "parent_org", ObjectType: "proj", ObjectID: "p1"})
	r2, err := s.Check(CheckInput{SubjectType: "usr", SubjectID: "bob", Relation: "viewer", ObjectType: "proj", ObjectID: "p1"})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !r2.Allowed {
		t.Error("tuple_to_userset parent_org hop should allow")
	}
}

func TestInMemCheckAny(t *testing.T) {
	s := NewInMemoryTupleStore()
	_, _ = s.CreateTuple(CreateTupleInput{
		SubjectType: "usr", SubjectID: "alice", Relation: "editor",
		ObjectType: "proj", ObjectID: "p1",
	})
	r, err := s.CheckAny(CheckAnyInput{
		SubjectType: "usr", SubjectID: "alice",
		Relations:   []string{"viewer", "editor", "admin"},
		ObjectType: "proj", ObjectID: "p1",
	})
	if err != nil {
		t.Fatalf("CheckAny: %v", err)
	}
	if !r.Allowed {
		t.Error("CheckAny should hit on editor")
	}
	// Empty relation set rejects.
	if _, err := s.CheckAny(CheckAnyInput{SubjectType: "usr", SubjectID: "alice", Relations: []string{}, ObjectType: "proj", ObjectID: "p1"}); err == nil {
		t.Error("empty relations should reject")
	}
}

func TestInMemShareLifecycle(t *testing.T) {
	s := NewInMemoryShareStore()
	res, err := s.CreateShare(CreateShareInput{
		ObjectType: "ticket", ObjectID: "t1",
		Relation: "commenter", CreatedBy: "usr_alice",
		ExpiresInSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("CreateShare: %v", err)
	}
	if !res.Share.ExpiresAt.After(time.Now().UTC()) {
		t.Errorf("expires_at not in the future")
	}

	v, err := s.VerifyShareToken(res.Token)
	if err != nil {
		t.Fatalf("VerifyShareToken: %v", err)
	}
	if v.Relation != "commenter" {
		t.Errorf("wrong relation")
	}

	// Tampered token rejects.
	if _, err := s.VerifyShareToken(res.Token[:len(res.Token)-3] + "AAA"); err == nil {
		t.Error("tampered share token should reject")
	}

	// Revoke.
	if _, err := s.RevokeShare(res.Share.ID); err != nil {
		t.Fatalf("RevokeShare: %v", err)
	}
	if _, err := s.VerifyShareToken(res.Token); err == nil {
		t.Error("revoked share should reject verify")
	}
}

func TestInMemShareSingleUse(t *testing.T) {
	s := NewInMemoryShareStore()
	res, _ := s.CreateShare(CreateShareInput{
		ObjectType: "doc", ObjectID: "d1", Relation: "viewer",
		CreatedBy: "usr_a", ExpiresInSeconds: 600, SingleUse: true,
	})
	if _, err := s.VerifyShareToken(res.Token); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if _, err := s.VerifyShareToken(res.Token); err == nil {
		t.Error("second verify of single-use share should reject")
	}
}
