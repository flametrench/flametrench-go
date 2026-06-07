// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
package flags

import (
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/flametrench/flametrench-go/packages/ids"
)

var (
	keyRe      = regexp.MustCompile(`^[a-z0-9._\-]{1,128}$`)
	relationRe = regexp.MustCompile(`^[a-z_]{2,32}$`)
)

func validateRules(rules []Rule) error {
	for i, r := range rules {
		switch r.Kind {
		case RuleKindAuthz:
			if !relationRe.MatchString(r.Relation) {
				return &InvalidFormatError{
					Field:  "rules[*].relation",
					Reason: "must match ^[a-z_]{2,32}$",
				}
			}
			if r.Object == nil || r.Object.Type == "" {
				return &InvalidFormatError{
					Field:  "rules[*].object.type",
					Reason: "must be non-empty for authz rules",
				}
			}
			if r.Object.ID == "" {
				return &InvalidFormatError{
					Field:  "rules[*].object.id",
					Reason: "must be non-empty for authz rules",
				}
			}
		case RuleKindPercentage:
			if r.BasisPoints < 0 || r.BasisPoints > 10000 {
				return &InvalidFormatError{
					Field:  "rules[*].basis_points",
					Reason: "must be in [0, 10000]",
				}
			}
		default:
			_ = i
			return &InvalidFormatError{
				Field:  "rules[*].kind",
				Reason: `must be "authz" or "percentage"`,
			}
		}
	}
	return nil
}

func cloneRules(rules []Rule) []Rule {
	if rules == nil {
		return nil
	}
	out := make([]Rule, len(rules))
	for i, r := range rules {
		out[i] = r
		if r.Object != nil {
			obj := *r.Object
			out[i].Object = &obj
		}
	}
	return out
}

func cloneFlag(f Flag) Flag {
	f.Rules = cloneRules(f.Rules)
	return f
}

// InMemoryFlagsStore is a thread-safe in-process FlagsStore for testing and
// development (ADR 0021).
type InMemoryFlagsStore struct {
	mu    sync.RWMutex
	flags map[string]*Flag  // id → flag
	byKey map[string]string // scope+"#"+key → id
}

// NewInMemoryFlagsStore returns an empty InMemoryFlagsStore.
func NewInMemoryFlagsStore() *InMemoryFlagsStore {
	return &InMemoryFlagsStore{
		flags: make(map[string]*Flag),
		byKey: make(map[string]string),
	}
}

func (s *InMemoryFlagsStore) CreateFlag(in CreateFlagInput) (Flag, error) {
	if !ids.IsValid(in.Scope, "org") {
		return Flag{}, &InvalidFormatError{Field: "scope", Reason: "must be a valid org_ id"}
	}
	if !keyRe.MatchString(in.Key) {
		return Flag{}, &InvalidFormatError{Field: "key", Reason: `must match ^[a-z0-9._-]{1,128}$`}
	}
	if err := validateRules(in.Rules); err != nil {
		return Flag{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	scopeKey := in.Scope + "#" + in.Key
	if _, exists := s.byKey[scopeKey]; exists {
		return Flag{}, ErrKeyConflict
	}

	id, err := ids.Generate("flag")
	if err != nil {
		return Flag{}, err
	}
	now := time.Now().UTC()
	f := &Flag{
		ID:             id,
		Scope:          in.Scope,
		Key:            in.Key,
		Enabled:        in.Enabled,
		DefaultVariant: in.DefaultVariant,
		Rules:          cloneRules(in.Rules),
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	s.flags[id] = f
	s.byKey[scopeKey] = id
	return cloneFlag(*f), nil
}

func (s *InMemoryFlagsStore) GetFlag(id string) (Flag, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f, ok := s.flags[id]
	if !ok {
		return Flag{}, ErrNotFound
	}
	return cloneFlag(*f), nil
}

func (s *InMemoryFlagsStore) GetFlagByKey(scope, key string) (Flag, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byKey[scope+"#"+key]
	if !ok {
		return Flag{}, ErrNotFound
	}
	return cloneFlag(*s.flags[id]), nil
}

func (s *InMemoryFlagsStore) ListFlags(opts ListFlagsOptions) (FlagsPage, error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var matching []Flag
	for _, f := range s.flags {
		if f.Scope == opts.Scope {
			matching = append(matching, cloneFlag(*f))
		}
	}
	sort.Slice(matching, func(i, j int) bool { return matching[i].ID < matching[j].ID })

	if opts.Cursor != nil {
		pos := -1
		for i, f := range matching {
			if f.ID == *opts.Cursor {
				pos = i
				break
			}
		}
		if pos >= 0 {
			matching = matching[pos+1:]
		}
	}

	var nextCursor *string
	if len(matching) > limit {
		c := matching[limit-1].ID
		nextCursor = &c
		matching = matching[:limit]
	}
	return FlagsPage{Data: matching, NextCursor: nextCursor}, nil
}

func (s *InMemoryFlagsStore) UpdateFlag(in UpdateFlagInput) (Flag, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.flags[in.ID]
	if !ok {
		return Flag{}, ErrNotFound
	}
	if in.Enabled != nil {
		f.Enabled = *in.Enabled
	}
	if in.DefaultVariant != nil {
		f.DefaultVariant = *in.DefaultVariant
	}
	if in.UpdateRules {
		if err := validateRules(in.Rules); err != nil {
			return Flag{}, err
		}
		f.Rules = cloneRules(in.Rules)
	}
	f.UpdatedAt = time.Now().UTC()
	return cloneFlag(*f), nil
}

func (s *InMemoryFlagsStore) DeleteFlag(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.flags[id]
	if !ok {
		return ErrNotFound
	}
	delete(s.byKey, f.Scope+"#"+f.Key)
	delete(s.flags, id)
	return nil
}

func (s *InMemoryFlagsStore) Evaluate(scope, key, subjectID string, check CheckFn) (bool, error) {
	s.mu.RLock()
	id, ok := s.byKey[scope+"#"+key]
	var f Flag
	if ok {
		f = cloneFlag(*s.flags[id])
	}
	s.mu.RUnlock()

	if !ok {
		return false, nil
	}
	if !f.Enabled {
		return f.DefaultVariant, nil
	}
	for _, r := range f.Rules {
		switch r.Kind {
		case RuleKindAuthz:
			if check != nil && check(subjectID, r.Relation, r.Object.Type, r.Object.ID) {
				return r.Variant, nil
			}
		case RuleKindPercentage:
			if AssignBucket(f.Key, subjectID) < uint32(r.BasisPoints) {
				return r.Variant, nil
			}
		}
	}
	return f.DefaultVariant, nil
}
