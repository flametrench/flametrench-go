// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Shared test suites for any TupleStore + ShareStore implementations.
// Mirrors the identity/tenancy harness pattern: identical bodies run
// against both InMemory and Postgres backends through factory funcs.
// All subject/object IDs use the wire-format `prefix_<32hex>` so that
// Postgres uuid columns accept them.

package authz

import (
	"errors"
	"testing"
	"time"
)

// ─── factory types ───

// tupleFactory returns a fresh TupleStore + cleanup + seed-user hook.
// The Postgres backend FKs nothing in tup, so the seed hook can be a
// no-op for tuples; ShareStore's created_by FK to usr requires a real
// row though, so we share the same hook signature across both suites.
type tupleFactory func(t *testing.T, rules Rules, opts EvaluateOptions) (TupleStore, func(t *testing.T, usrID string), func())

// shareFactory returns a fresh ShareStore + cleanup + seed-user hook.
type shareFactory func(t *testing.T) (ShareStore, func(t *testing.T, usrID string), func())

// ─── wire-format helpers ───

// usrID and objID build deterministic wire-format ids: 32-hex payload
// derived from idx so distinct rows don't collide across sub-tests.
func usrID(idx int) string { return wireFromBase("usr", idx) }
func objID(prefix string, idx int) string {
	return wireFromBase(prefix, idx)
}

func wireFromBase(prefix string, idx int) string {
	const hex = "0123456789abcdef"
	base := "0190f2a81b3c7abc8123456789ab"
	out := []byte(prefix)
	out = append(out, '_')
	out = append(out, []byte(base)...)
	out = append(out,
		hex[(idx>>12)&0xF],
		hex[(idx>>8)&0xF],
		hex[(idx>>4)&0xF],
		hex[idx&0xF],
	)
	return string(out)
}

// ─── Tuple suite ───

func runTupleSuite(t *testing.T, newStore tupleFactory) {
	t.Run("CreateAndCheck", func(t *testing.T) { testCreateAndCheck(t, newStore) })
	t.Run("DuplicateRejects", func(t *testing.T) { testDuplicateRejects(t, newStore) })
	t.Run("Delete", func(t *testing.T) { testDeleteTuple(t, newStore) })
	t.Run("GetTuple", func(t *testing.T) { testGetTuple(t, newStore) })
	t.Run("CascadeRevoke", func(t *testing.T) { testCascadeRevoke(t, newStore) })
	t.Run("CheckAny", func(t *testing.T) { testCheckAny(t, newStore) })
	t.Run("ListBySubject", func(t *testing.T) { testListBySubject(t, newStore) })
	t.Run("ListByObject", func(t *testing.T) { testListByObject(t, newStore) })
	t.Run("RewriteRules", func(t *testing.T) { testRewriteRules(t, newStore) })
	t.Run("InvalidFormats", func(t *testing.T) { testInvalidFormats(t, newStore) })
	t.Run("Errors", func(t *testing.T) { testTupleErrors(t, newStore) })
}

func testCreateAndCheck(t *testing.T, newStore tupleFactory) {
	s, _, done := newStore(t, nil, EvaluateOptions{})
	defer done()
	alice := usrID(1)
	proj := objID("proj", 1)
	tup, err := s.CreateTuple(CreateTupleInput{
		SubjectType: "usr", SubjectID: alice, Relation: "viewer",
		ObjectType: "proj", ObjectID: proj,
	})
	if err != nil {
		t.Fatalf("CreateTuple: %v", err)
	}
	if tup.ID == "" {
		t.Error("tuple ID empty")
	}
	r, err := s.Check(CheckInput{SubjectType: "usr", SubjectID: alice, Relation: "viewer", ObjectType: "proj", ObjectID: proj})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !r.Allowed {
		t.Error("expected allowed")
	}
	if r.MatchedTupleID == nil || *r.MatchedTupleID != tup.ID {
		t.Errorf("MatchedTupleID = %v", r.MatchedTupleID)
	}
}

func testDuplicateRejects(t *testing.T, newStore tupleFactory) {
	s, _, done := newStore(t, nil, EvaluateOptions{})
	defer done()
	alice := usrID(1)
	proj := objID("proj", 1)
	in := CreateTupleInput{
		SubjectType: "usr", SubjectID: alice, Relation: "viewer",
		ObjectType: "proj", ObjectID: proj,
	}
	if _, err := s.CreateTuple(in); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := s.CreateTuple(in)
	if !IsDuplicateTuple(err) {
		t.Errorf("IsDuplicateTuple(%v) = false", err)
	}
}

func testDeleteTuple(t *testing.T, newStore tupleFactory) {
	s, _, done := newStore(t, nil, EvaluateOptions{})
	defer done()
	alice := usrID(1)
	proj := objID("proj", 1)
	tup, _ := s.CreateTuple(CreateTupleInput{
		SubjectType: "usr", SubjectID: alice, Relation: "viewer",
		ObjectType: "proj", ObjectID: proj,
	})
	if err := s.DeleteTuple(tup.ID); err != nil {
		t.Fatalf("DeleteTuple: %v", err)
	}
	r, _ := s.Check(CheckInput{SubjectType: "usr", SubjectID: alice, Relation: "viewer", ObjectType: "proj", ObjectID: proj})
	if r.Allowed {
		t.Error("deleted tuple should not match")
	}
	// Deleting again errors (not-found).
	if err := s.DeleteTuple(tup.ID); err == nil {
		t.Error("re-delete should error")
	}
}

func testGetTuple(t *testing.T, newStore tupleFactory) {
	s, _, done := newStore(t, nil, EvaluateOptions{})
	defer done()
	alice := usrID(1)
	proj := objID("proj", 1)
	tup, _ := s.CreateTuple(CreateTupleInput{
		SubjectType: "usr", SubjectID: alice, Relation: "viewer",
		ObjectType: "proj", ObjectID: proj,
	})
	got, err := s.GetTuple(tup.ID)
	if err != nil {
		t.Fatalf("GetTuple: %v", err)
	}
	if got.SubjectID != alice || got.Relation != "viewer" {
		t.Errorf("got %+v", got)
	}
	// Unknown.
	if _, err := s.GetTuple("tup_00000000000000000000000000000001"); err == nil {
		t.Error("unknown tup id should error")
	}
}

func testCascadeRevoke(t *testing.T, newStore tupleFactory) {
	s, _, done := newStore(t, nil, EvaluateOptions{})
	defer done()
	alice := usrID(1)
	proj1 := objID("proj", 1)
	proj2 := objID("proj", 2)
	_, _ = s.CreateTuple(CreateTupleInput{SubjectType: "usr", SubjectID: alice, Relation: "viewer", ObjectType: "proj", ObjectID: proj1})
	_, _ = s.CreateTuple(CreateTupleInput{SubjectType: "usr", SubjectID: alice, Relation: "editor", ObjectType: "proj", ObjectID: proj2})
	n, err := s.CascadeRevokeSubject("usr", alice)
	if err != nil {
		t.Fatalf("CascadeRevokeSubject: %v", err)
	}
	if n != 2 {
		t.Errorf("revoked %d; want 2", n)
	}
	r, _ := s.Check(CheckInput{SubjectType: "usr", SubjectID: alice, Relation: "viewer", ObjectType: "proj", ObjectID: proj1})
	if r.Allowed {
		t.Error("cascade-revoked tuple should not match")
	}
}

func testCheckAny(t *testing.T, newStore tupleFactory) {
	s, _, done := newStore(t, nil, EvaluateOptions{})
	defer done()
	alice := usrID(1)
	proj := objID("proj", 1)
	_, _ = s.CreateTuple(CreateTupleInput{SubjectType: "usr", SubjectID: alice, Relation: "editor", ObjectType: "proj", ObjectID: proj})
	r, err := s.CheckAny(CheckAnyInput{
		SubjectType: "usr", SubjectID: alice,
		Relations:  []string{"viewer", "editor", "admin"},
		ObjectType: "proj", ObjectID: proj,
	})
	if err != nil {
		t.Fatalf("CheckAny: %v", err)
	}
	if !r.Allowed {
		t.Error("CheckAny should hit on editor")
	}
	// Empty relations.
	_, err = s.CheckAny(CheckAnyInput{SubjectType: "usr", SubjectID: alice, Relations: []string{}, ObjectType: "proj", ObjectID: proj})
	if !errors.Is(err, ErrEmptyRelationSet) {
		t.Errorf("err = %v; want ErrEmptyRelationSet", err)
	}
	// All-miss.
	r2, _ := s.CheckAny(CheckAnyInput{
		SubjectType: "usr", SubjectID: alice,
		Relations:  []string{"admin", "owner"},
		ObjectType: "proj", ObjectID: proj,
	})
	if r2.Allowed {
		t.Error("all-miss CheckAny should not allow")
	}
}

func testListBySubject(t *testing.T, newStore tupleFactory) {
	s, _, done := newStore(t, nil, EvaluateOptions{})
	defer done()
	alice := usrID(1)
	for i := 1; i <= 4; i++ {
		_, _ = s.CreateTuple(CreateTupleInput{
			SubjectType: "usr", SubjectID: alice, Relation: "viewer",
			ObjectType: "proj", ObjectID: objID("proj", i),
		})
	}
	page1, err := s.ListTuplesBySubject("usr", alice, ListTuplesOptions{Limit: 2})
	if err != nil {
		t.Fatalf("ListTuplesBySubject: %v", err)
	}
	if len(page1.Data) != 2 {
		t.Errorf("page1 len = %d; want 2", len(page1.Data))
	}
	if page1.NextCursor == nil {
		t.Error("expected next cursor")
	}
	page2, err := s.ListTuplesBySubject("usr", alice, ListTuplesOptions{Limit: 10, Cursor: page1.NextCursor})
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2.Data) == 0 {
		t.Error("page2 empty")
	}
}

func testListByObject(t *testing.T, newStore tupleFactory) {
	s, _, done := newStore(t, nil, EvaluateOptions{})
	defer done()
	proj := objID("proj", 1)
	_, _ = s.CreateTuple(CreateTupleInput{SubjectType: "usr", SubjectID: usrID(1), Relation: "viewer", ObjectType: "proj", ObjectID: proj})
	_, _ = s.CreateTuple(CreateTupleInput{SubjectType: "usr", SubjectID: usrID(2), Relation: "viewer", ObjectType: "proj", ObjectID: proj})
	_, _ = s.CreateTuple(CreateTupleInput{SubjectType: "usr", SubjectID: usrID(3), Relation: "editor", ObjectType: "proj", ObjectID: proj})

	all, err := s.ListTuplesByObject("proj", proj, ListByObjectOptions{Limit: 10})
	if err != nil {
		t.Fatalf("ListTuplesByObject: %v", err)
	}
	if len(all.Data) != 3 {
		t.Errorf("all len = %d; want 3", len(all.Data))
	}
	viewer := "viewer"
	filtered, _ := s.ListTuplesByObject("proj", proj, ListByObjectOptions{Limit: 10, Relation: &viewer})
	if len(filtered.Data) != 2 {
		t.Errorf("viewer-filter len = %d; want 2", len(filtered.Data))
	}
}

func testRewriteRules(t *testing.T, newStore tupleFactory) {
	rules := Rules{
		"proj": map[string]Rule{
			"viewer": {
				This{},
				ComputedUserset{Relation: "editor"},
				TupleToUserset{TuplesetRelation: "parent_org", ComputedUsersetRelation: "member"},
			},
		},
	}
	s, _, done := newStore(t, rules, EvaluateOptions{})
	defer done()

	alice := usrID(1)
	bob := usrID(2)
	proj := objID("proj", 1)
	org := objID("org", 1)

	// alice = editor on proj → should also be viewer via ComputedUserset.
	_, _ = s.CreateTuple(CreateTupleInput{
		SubjectType: "usr", SubjectID: alice, Relation: "editor",
		ObjectType: "proj", ObjectID: proj,
	})
	r, err := s.Check(CheckInput{
		SubjectType: "usr", SubjectID: alice, Relation: "viewer",
		ObjectType: "proj", ObjectID: proj,
	})
	if err != nil {
		t.Fatalf("Check (computed): %v", err)
	}
	if !r.Allowed {
		t.Error("editor-implies-viewer should allow")
	}

	// bob = member of org; org = parent_org of proj. Should be viewer via TupleToUserset.
	_, _ = s.CreateTuple(CreateTupleInput{SubjectType: "usr", SubjectID: bob, Relation: "member", ObjectType: "org", ObjectID: org})
	_, _ = s.CreateTuple(CreateTupleInput{SubjectType: "org", SubjectID: org, Relation: "parent_org", ObjectType: "proj", ObjectID: proj})
	r2, err := s.Check(CheckInput{SubjectType: "usr", SubjectID: bob, Relation: "viewer", ObjectType: "proj", ObjectID: proj})
	if err != nil {
		t.Fatalf("Check (TupleToUserset): %v", err)
	}
	if !r2.Allowed {
		t.Error("parent_org hop should allow")
	}

	// Unrelated user gets denied.
	r3, _ := s.Check(CheckInput{SubjectType: "usr", SubjectID: usrID(99), Relation: "viewer", ObjectType: "proj", ObjectID: proj})
	if r3.Allowed {
		t.Error("unrelated user should not match")
	}
}

func testInvalidFormats(t *testing.T, newStore tupleFactory) {
	s, _, done := newStore(t, nil, EvaluateOptions{})
	defer done()
	// Invalid subject_type (not 2-6 lowercase).
	_, err := s.CreateTuple(CreateTupleInput{
		SubjectType: "USR", SubjectID: usrID(1), Relation: "viewer",
		ObjectType: "proj", ObjectID: objID("proj", 1),
	})
	if err == nil {
		t.Error("invalid subject_type should reject")
	}
	// Invalid relation.
	_, err = s.CreateTuple(CreateTupleInput{
		SubjectType: "usr", SubjectID: usrID(1), Relation: "BAD-RELATION",
		ObjectType: "proj", ObjectID: objID("proj", 1),
	})
	if err == nil {
		t.Error("invalid relation should reject")
	}
}

func testTupleErrors(t *testing.T, newStore tupleFactory) {
	s, _, done := newStore(t, nil, EvaluateOptions{})
	defer done()
	// Delete unknown → ErrTupleNotFound.
	err := s.DeleteTuple("tup_00000000000000000000000000000001")
	if !IsTupleNotFound(err) {
		t.Errorf("IsTupleNotFound(%v) = false", err)
	}
	// ErrorCode helper.
	if ErrorCode(err) == "" {
		t.Error("ErrorCode empty")
	}
}

// ─── Share suite ───

func runShareSuite(t *testing.T, newStore shareFactory) {
	t.Run("Lifecycle", func(t *testing.T) { testShareLifecycle(t, newStore) })
	t.Run("SingleUse", func(t *testing.T) { testShareSingleUse(t, newStore) })
	t.Run("Revoked", func(t *testing.T) { testShareRevoked(t, newStore) })
	t.Run("TamperedToken", func(t *testing.T) { testShareTampered(t, newStore) })
	t.Run("Expired", func(t *testing.T) { testShareExpired(t, newStore) })
	t.Run("Get", func(t *testing.T) { testShareGet(t, newStore) })
	t.Run("ListForObject", func(t *testing.T) { testShareList(t, newStore) })
	t.Run("InvalidRelation", func(t *testing.T) { testShareInvalidRelation(t, newStore) })
	t.Run("MaxTTL", func(t *testing.T) { testShareMaxTTL(t, newStore) })
	t.Run("IsInvalidShareToken", func(t *testing.T) { testShareIsInvalid(t, newStore) })
}

func testShareLifecycle(t *testing.T, newStore shareFactory) {
	s, seed, done := newStore(t)
	defer done()
	alice := usrID(1)
	seed(t, alice)
	res, err := s.CreateShare(CreateShareInput{
		ObjectType: "doc", ObjectID: objID("doc", 1),
		Relation: "viewer", CreatedBy: alice, ExpiresInSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("CreateShare: %v", err)
	}
	if res.Token == "" {
		t.Error("token empty")
	}
	v, err := s.VerifyShareToken(res.Token)
	if err != nil {
		t.Fatalf("VerifyShareToken: %v", err)
	}
	if v.Relation != "viewer" {
		t.Errorf("relation = %q", v.Relation)
	}
}

func testShareSingleUse(t *testing.T, newStore shareFactory) {
	s, seed, done := newStore(t)
	defer done()
	alice := usrID(1)
	seed(t, alice)
	res, _ := s.CreateShare(CreateShareInput{
		ObjectType: "doc", ObjectID: objID("doc", 2),
		Relation: "viewer", CreatedBy: alice,
		ExpiresInSeconds: 3600, SingleUse: true,
	})
	if _, err := s.VerifyShareToken(res.Token); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	_, err := s.VerifyShareToken(res.Token)
	if !errors.Is(err, ErrShareConsumed) && !IsInvalidShareToken(err) {
		t.Errorf("second verify of single-use should error, got %v", err)
	}
}

func testShareRevoked(t *testing.T, newStore shareFactory) {
	s, seed, done := newStore(t)
	defer done()
	alice := usrID(1)
	seed(t, alice)
	res, _ := s.CreateShare(CreateShareInput{
		ObjectType: "doc", ObjectID: objID("doc", 3),
		Relation: "viewer", CreatedBy: alice, ExpiresInSeconds: 3600,
	})
	if _, err := s.RevokeShare(res.Share.ID); err != nil {
		t.Fatalf("RevokeShare: %v", err)
	}
	_, err := s.VerifyShareToken(res.Token)
	if !errors.Is(err, ErrShareRevoked) && !IsInvalidShareToken(err) {
		t.Errorf("revoked verify err = %v", err)
	}
}

func testShareTampered(t *testing.T, newStore shareFactory) {
	s, seed, done := newStore(t)
	defer done()
	alice := usrID(1)
	seed(t, alice)
	res, _ := s.CreateShare(CreateShareInput{
		ObjectType: "doc", ObjectID: objID("doc", 4),
		Relation: "viewer", CreatedBy: alice, ExpiresInSeconds: 3600,
	})
	tampered := res.Token[:len(res.Token)-3] + "AAA"
	_, err := s.VerifyShareToken(tampered)
	if !IsInvalidShareToken(err) {
		t.Errorf("tampered token err = %v", err)
	}
}

func testShareExpired(t *testing.T, newStore shareFactory) {
	s, seed, done := newStore(t)
	defer done()
	alice := usrID(1)
	seed(t, alice)
	res, _ := s.CreateShare(CreateShareInput{
		ObjectType: "doc", ObjectID: objID("doc", 5),
		Relation: "viewer", CreatedBy: alice, ExpiresInSeconds: 1,
	})
	time.Sleep(1100 * time.Millisecond)
	_, err := s.VerifyShareToken(res.Token)
	if !errors.Is(err, ErrShareExpired) && !IsInvalidShareToken(err) {
		t.Errorf("expired verify err = %v", err)
	}
}

func testShareGet(t *testing.T, newStore shareFactory) {
	s, seed, done := newStore(t)
	defer done()
	alice := usrID(1)
	seed(t, alice)
	res, _ := s.CreateShare(CreateShareInput{
		ObjectType: "doc", ObjectID: objID("doc", 6),
		Relation: "viewer", CreatedBy: alice, ExpiresInSeconds: 3600,
	})
	got, err := s.GetShare(res.Share.ID)
	if err != nil {
		t.Fatalf("GetShare: %v", err)
	}
	if got.ID != res.Share.ID {
		t.Errorf("ids differ")
	}
	// Unknown.
	if _, err := s.GetShare("shr_00000000000000000000000000000001"); err == nil {
		t.Error("unknown share id should error")
	}
}

func testShareList(t *testing.T, newStore shareFactory) {
	s, seed, done := newStore(t)
	defer done()
	alice := usrID(1)
	seed(t, alice)
	doc := objID("doc", 7)
	for i := 0; i < 3; i++ {
		_, _ = s.CreateShare(CreateShareInput{
			ObjectType: "doc", ObjectID: doc,
			Relation: "viewer", CreatedBy: alice, ExpiresInSeconds: 3600,
		})
	}
	page, err := s.ListSharesForObject("doc", doc, ListSharesOptions{Limit: 10})
	if err != nil {
		t.Fatalf("ListSharesForObject: %v", err)
	}
	if len(page.Data) < 3 {
		t.Errorf("len = %d; want ≥3", len(page.Data))
	}
}

func testShareInvalidRelation(t *testing.T, newStore shareFactory) {
	s, seed, done := newStore(t)
	defer done()
	alice := usrID(1)
	seed(t, alice)
	_, err := s.CreateShare(CreateShareInput{
		ObjectType: "doc", ObjectID: objID("doc", 8),
		Relation: "BAD", CreatedBy: alice, ExpiresInSeconds: 3600,
	})
	if err == nil {
		t.Error("invalid relation should reject")
	}
}

func testShareMaxTTL(t *testing.T, newStore shareFactory) {
	s, seed, done := newStore(t)
	defer done()
	alice := usrID(1)
	seed(t, alice)
	// 366 days exceeds the cap.
	_, err := s.CreateShare(CreateShareInput{
		ObjectType: "doc", ObjectID: objID("doc", 9),
		Relation: "viewer", CreatedBy: alice,
		ExpiresInSeconds: ShareMaxTTLSeconds + 1000,
	})
	if err == nil {
		t.Error("over-cap TTL should reject")
	}
}

func testShareIsInvalid(t *testing.T, newStore shareFactory) {
	s, _, done := newStore(t)
	defer done()
	_, err := s.VerifyShareToken("not-a-token")
	if !IsInvalidShareToken(err) {
		t.Errorf("IsInvalidShareToken(%v) = false", err)
	}
}

// ─── In-memory bindings ───

func TestInMemoryTupleSuite(t *testing.T) {
	runTupleSuite(t, func(t *testing.T, rules Rules, opts EvaluateOptions) (TupleStore, func(*testing.T, string), func()) {
		var s TupleStore
		if rules == nil {
			s = NewInMemoryTupleStore()
		} else {
			s = NewInMemoryTupleStoreWithRules(rules, opts)
		}
		return s, func(t *testing.T, _ string) {}, func() {}
	})
}

func TestInMemoryShareSuite(t *testing.T) {
	runShareSuite(t, func(t *testing.T) (ShareStore, func(*testing.T, string), func()) {
		return NewInMemoryShareStore(), func(t *testing.T, _ string) {}, func() {}
	})
}
