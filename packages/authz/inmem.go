// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

// InMemoryTupleStore + InMemoryShareStore — reference implementations.

package authz

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	flametrenchids "github.com/flametrench/flametrench-go/packages/ids"
)

// Compile-time guarantees.
var _ TupleStore = (*InMemoryTupleStore)(nil)
var _ ShareStore = (*InMemoryShareStore)(nil)

// InMemoryTupleStore is the reference in-memory tuple store. Optional
// rewrite-rule support is enabled by constructing with a non-nil rules
// map; absent rules, Check is byte-identical to v0.1 semantics.
type InMemoryTupleStore struct {
	mu sync.Mutex

	clock func() time.Time

	tuples         map[string]Tuple // id → tuple
	naturalKeyToID map[string]string // natural-key → id

	rules     Rules
	maxDepth  int
	maxFanOut int
}

// NewInMemoryTupleStore returns a v0.1-semantics store (exact-match only).
func NewInMemoryTupleStore() *InMemoryTupleStore {
	return &InMemoryTupleStore{
		clock:          func() time.Time { return time.Now().UTC() },
		tuples:         map[string]Tuple{},
		naturalKeyToID: map[string]string{},
	}
}

// WithRules returns a store enabled with v0.2+ rewrite-rule evaluation.
func NewInMemoryTupleStoreWithRules(rules Rules, opts EvaluateOptions) *InMemoryTupleStore {
	s := NewInMemoryTupleStore()
	s.rules = rules
	s.maxDepth = opts.MaxDepth
	s.maxFanOut = opts.MaxFanOut
	return s
}

func (s *InMemoryTupleStore) WithClock(clock func() time.Time) *InMemoryTupleStore {
	s.clock = clock
	return s
}

func tupleNaturalKey(subjectType, subjectID, relation, objectType, objectID string) string {
	return subjectType + "|" + subjectID + "|" + relation + "|" + objectType + "|" + objectID
}

func (s *InMemoryTupleStore) CreateTuple(in CreateTupleInput) (Tuple, error) {
	if !RelationNamePattern.MatchString(in.Relation) {
		return Tuple{}, fmt.Errorf("relation %q: %w", in.Relation, ErrInvalidFormat)
	}
	if !TypePrefixPattern.MatchString(in.SubjectType) {
		return Tuple{}, fmt.Errorf("subject_type %q: %w", in.SubjectType, ErrInvalidFormat)
	}
	if !TypePrefixPattern.MatchString(in.ObjectType) {
		return Tuple{}, fmt.Errorf("object_type %q: %w", in.ObjectType, ErrInvalidFormat)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := tupleNaturalKey(in.SubjectType, in.SubjectID, in.Relation, in.ObjectType, in.ObjectID)
	if existingID, taken := s.naturalKeyToID[key]; taken {
		return Tuple{}, fmt.Errorf("tuple %s: %w", existingID, ErrDuplicateTuple)
	}
	id, err := flametrenchids.Generate("tup")
	if err != nil {
		return Tuple{}, err
	}
	t := Tuple{
		ID: id, SubjectType: in.SubjectType, SubjectID: in.SubjectID,
		Relation: in.Relation, ObjectType: in.ObjectType, ObjectID: in.ObjectID,
		CreatedAt: s.clock(), CreatedBy: in.CreatedBy,
	}
	s.tuples[id] = t
	s.naturalKeyToID[key] = id
	return t, nil
}

func (s *InMemoryTupleStore) DeleteTuple(tupleID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tuples[tupleID]
	if !ok {
		return fmt.Errorf("tuple %s: %w", tupleID, ErrTupleNotFound)
	}
	delete(s.tuples, tupleID)
	delete(s.naturalKeyToID, tupleNaturalKey(t.SubjectType, t.SubjectID, t.Relation, t.ObjectType, t.ObjectID))
	return nil
}

func (s *InMemoryTupleStore) CascadeRevokeSubject(subjectType, subjectID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, t := range s.tuples {
		if t.SubjectType == subjectType && t.SubjectID == subjectID {
			delete(s.tuples, id)
			delete(s.naturalKeyToID, tupleNaturalKey(t.SubjectType, t.SubjectID, t.Relation, t.ObjectType, t.ObjectID))
			n++
		}
	}
	return n, nil
}

func (s *InMemoryTupleStore) Check(in CheckInput) (CheckResult, error) {
	if s.rules == nil {
		// v0.1 fast path: direct lookup only.
		s.mu.Lock()
		key := tupleNaturalKey(in.SubjectType, in.SubjectID, in.Relation, in.ObjectType, in.ObjectID)
		id, ok := s.naturalKeyToID[key]
		s.mu.Unlock()
		if ok {
			return CheckResult{Allowed: true, MatchedTupleID: &id}, nil
		}
		return CheckResult{Allowed: false}, nil
	}
	// v0.2 rule-aware path.
	res, err := Evaluate(
		s.rules,
		in.SubjectType, in.SubjectID, in.Relation, in.ObjectType, in.ObjectID,
		func(st, sid, rel, ot, oid string) (string, bool) {
			s.mu.Lock()
			defer s.mu.Unlock()
			id, ok := s.naturalKeyToID[tupleNaturalKey(st, sid, rel, ot, oid)]
			return id, ok
		},
		func(ot, oid, rel string) []SubjectRef {
			s.mu.Lock()
			defer s.mu.Unlock()
			out := make([]SubjectRef, 0)
			for _, t := range s.tuples {
				if t.ObjectType == ot && t.ObjectID == oid && t.Relation == rel {
					out = append(out, SubjectRef{SubjectType: t.SubjectType, SubjectID: t.SubjectID, TupleID: t.ID})
				}
			}
			return out
		},
		EvaluateOptions{MaxDepth: s.maxDepth, MaxFanOut: s.maxFanOut},
	)
	if err != nil {
		return CheckResult{}, err
	}
	if res.Allowed {
		mid := res.MatchedTupleID
		return CheckResult{Allowed: true, MatchedTupleID: &mid}, nil
	}
	return CheckResult{Allowed: false}, nil
}

func (s *InMemoryTupleStore) CheckAny(in CheckAnyInput) (CheckResult, error) {
	if len(in.Relations) == 0 {
		return CheckResult{}, ErrEmptyRelationSet
	}
	for _, rel := range in.Relations {
		r, err := s.Check(CheckInput{
			SubjectType: in.SubjectType, SubjectID: in.SubjectID,
			Relation: rel, ObjectType: in.ObjectType, ObjectID: in.ObjectID,
		})
		if err != nil {
			return CheckResult{}, err
		}
		if r.Allowed {
			return r, nil
		}
	}
	return CheckResult{Allowed: false}, nil
}

func (s *InMemoryTupleStore) GetTuple(tupleID string) (Tuple, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tuples[tupleID]
	if !ok {
		return Tuple{}, fmt.Errorf("tuple %s: %w", tupleID, ErrTupleNotFound)
	}
	return t, nil
}

func (s *InMemoryTupleStore) ListTuplesBySubject(subjectType, subjectID string, opts ListTuplesOptions) (Page[Tuple], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	matched := make([]Tuple, 0)
	for _, t := range s.tuples {
		if t.SubjectType == subjectType && t.SubjectID == subjectID {
			matched = append(matched, t)
		}
	}
	return paginateTuples(matched, opts.Cursor, limit), nil
}

func (s *InMemoryTupleStore) ListTuplesByObject(objectType, objectID string, opts ListByObjectOptions) (Page[Tuple], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	matched := make([]Tuple, 0)
	for _, t := range s.tuples {
		if t.ObjectType != objectType || t.ObjectID != objectID {
			continue
		}
		if opts.Relation != nil && t.Relation != *opts.Relation {
			continue
		}
		matched = append(matched, t)
	}
	return paginateTuples(matched, opts.Cursor, limit), nil
}

func paginateTuples(matched []Tuple, cursor *string, limit int) Page[Tuple] {
	for i := 1; i < len(matched); i++ {
		for j := i; j > 0; j-- {
			if matched[j].CreatedAt.Before(matched[j-1].CreatedAt) ||
				(matched[j].CreatedAt.Equal(matched[j-1].CreatedAt) && matched[j].ID < matched[j-1].ID) {
				matched[j-1], matched[j] = matched[j], matched[j-1]
			} else {
				break
			}
		}
	}
	startIdx := 0
	if cursor != nil && *cursor != "" {
		for i, t := range matched {
			if t.ID == *cursor {
				startIdx = i + 1
				break
			}
		}
	}
	end := startIdx + limit
	if end > len(matched) {
		end = len(matched)
	}
	data := matched[startIdx:end]
	var next *string
	if end < len(matched) && len(data) > 0 {
		c := data[len(data)-1].ID
		next = &c
	}
	return Page[Tuple]{Data: data, NextCursor: next}
}

// ─── InMemoryShareStore ───

type InMemoryShareStore struct {
	mu    sync.Mutex
	clock func() time.Time

	shares             map[string]Share  // share_id → record
	shareTokenHashes   map[string][]byte // share_id → 32-byte sha256
	shareIDByTokenHash map[string]string // hex(sha256) → share_id
}

func NewInMemoryShareStore() *InMemoryShareStore {
	return &InMemoryShareStore{
		clock:              func() time.Time { return time.Now().UTC() },
		shares:             map[string]Share{},
		shareTokenHashes:   map[string][]byte{},
		shareIDByTokenHash: map[string]string{},
	}
}

func (s *InMemoryShareStore) WithClock(c func() time.Time) *InMemoryShareStore { s.clock = c; return s }

func (s *InMemoryShareStore) CreateShare(in CreateShareInput) (CreateShareResult, error) {
	if !RelationNamePattern.MatchString(in.Relation) {
		return CreateShareResult{}, fmt.Errorf("relation: %w", ErrInvalidFormat)
	}
	if in.ExpiresInSeconds <= 0 || in.ExpiresInSeconds > ShareMaxTTLSeconds {
		return CreateShareResult{}, fmt.Errorf("ttl out of range (1..%d): %w", ShareMaxTTLSeconds, ErrInvalidFormat)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id, err := flametrenchids.Generate("shr")
	if err != nil {
		return CreateShareResult{}, err
	}
	// Mint 32-byte token.
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return CreateShareResult{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	h := sha256.Sum256([]byte(token))
	now := s.clock()
	share := Share{
		ID: id, ObjectType: in.ObjectType, ObjectID: in.ObjectID,
		Relation: in.Relation, CreatedBy: in.CreatedBy,
		ExpiresAt: now.Add(time.Duration(in.ExpiresInSeconds) * time.Second),
		SingleUse: in.SingleUse, CreatedAt: now,
	}
	s.shares[id] = share
	s.shareTokenHashes[id] = h[:]
	s.shareIDByTokenHash[hex.EncodeToString(h[:])] = id
	return CreateShareResult{Share: share, Token: token}, nil
}

func (s *InMemoryShareStore) GetShare(shareID string) (Share, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sh, ok := s.shares[shareID]
	if !ok {
		return Share{}, fmt.Errorf("share %s: %w", shareID, ErrShareNotFound)
	}
	return sh, nil
}

func (s *InMemoryShareStore) VerifyShareToken(token string) (VerifiedShare, error) {
	h := sha256.Sum256([]byte(token))
	s.mu.Lock()
	defer s.mu.Unlock()
	shareID, ok := s.shareIDByTokenHash[hex.EncodeToString(h[:])]
	if !ok {
		return VerifiedShare{}, ErrInvalidShareToken
	}
	storedHash := s.shareTokenHashes[shareID]
	if subtle.ConstantTimeCompare(h[:], storedHash) != 1 {
		return VerifiedShare{}, ErrInvalidShareToken
	}
	sh := s.shares[shareID]
	if sh.RevokedAt != nil {
		return VerifiedShare{}, ErrShareRevoked
	}
	if sh.SingleUse && sh.ConsumedAt != nil {
		return VerifiedShare{}, ErrShareConsumed
	}
	if !s.clock().Before(sh.ExpiresAt) {
		return VerifiedShare{}, ErrShareExpired
	}
	if sh.SingleUse {
		now := s.clock()
		sh.ConsumedAt = &now
		s.shares[shareID] = sh
	}
	return VerifiedShare{
		ShareID: sh.ID, ObjectType: sh.ObjectType, ObjectID: sh.ObjectID,
		Relation: sh.Relation,
	}, nil
}

func (s *InMemoryShareStore) RevokeShare(shareID string) (Share, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sh, ok := s.shares[shareID]
	if !ok {
		return Share{}, fmt.Errorf("share %s: %w", shareID, ErrShareNotFound)
	}
	if sh.RevokedAt != nil {
		return sh, nil // idempotent
	}
	now := s.clock()
	sh.RevokedAt = &now
	s.shares[shareID] = sh
	return sh, nil
}

func (s *InMemoryShareStore) ListSharesForObject(objectType, objectID string, opts ListSharesOptions) (Page[Share], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	matched := make([]Share, 0)
	for _, sh := range s.shares {
		if sh.ObjectType == objectType && sh.ObjectID == objectID {
			matched = append(matched, sh)
		}
	}
	for i := 1; i < len(matched); i++ {
		for j := i; j > 0; j-- {
			if matched[j].CreatedAt.Before(matched[j-1].CreatedAt) ||
				(matched[j].CreatedAt.Equal(matched[j-1].CreatedAt) && matched[j].ID < matched[j-1].ID) {
				matched[j-1], matched[j] = matched[j], matched[j-1]
			} else {
				break
			}
		}
	}
	startIdx := 0
	if opts.Cursor != nil && *opts.Cursor != "" {
		for i, sh := range matched {
			if sh.ID == *opts.Cursor {
				startIdx = i + 1
				break
			}
		}
	}
	end := startIdx + limit
	if end > len(matched) {
		end = len(matched)
	}
	data := matched[startIdx:end]
	var next *string
	if end < len(matched) && len(data) > 0 {
		c := data[len(data)-1].ID
		next = &c
	}
	return Page[Share]{Data: data, NextCursor: next}, nil
}
