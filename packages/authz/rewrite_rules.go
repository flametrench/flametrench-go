// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

// Authorization rewrite rules — v0.2 reference implementation.
//
// The v0.1 SDK exposed only direct-tuple matching. v0.2 adds a
// deliberate subset of Zanzibar userset_rewrite: applications declare
// role implication ("admin implies editor") and parent-child
// inheritance ("org viewer implies project viewer") without
// denormalizing tuples into the store.
//
// See ADR 0007 for the design rationale and ADR 0017 for the v0.3
// Postgres-eval extension.

package authz

import "fmt"

// RuleNode is one primitive in a rule's union. Implementations are
// This, ComputedUserset, TupleToUserset.
type RuleNode interface {
	isRuleNode()
}

// This denotes the explicit-tuple set: equivalent to v0.1 Check
// semantics. In v0.2, This is always implicitly part of every rule's
// union — the direct-tuple fast path runs before rule expansion.
// Listing it explicitly is documentation, not behavior.
type This struct{}

func (This) isRuleNode() {}

// ComputedUserset is role implication on the same object.
// `ComputedUserset{Relation: "editor"}` on a rule for proj.viewer means:
// anyone holding editor on this project also has viewer. Recurses with
// the same object but a different relation.
type ComputedUserset struct {
	Relation string
}

func (ComputedUserset) isRuleNode() {}

// TupleToUserset is parent-child inheritance via a relation traversal.
// `TupleToUserset{TuplesetRelation: "parent_org",
// ComputedUsersetRelation: "viewer"}` on a rule for proj.viewer means:
// enumerate all tuples (*, parent_org, proj); for each such tuple's
// subject, recursively check whether the original subject has viewer
// on that org.
type TupleToUserset struct {
	TuplesetRelation        string
	ComputedUsersetRelation string
}

func (TupleToUserset) isRuleNode() {}

// Rule is the union of RuleNode primitives. Order-irrelevant; short-
// circuits on first hit.
type Rule []RuleNode

// Rules is the nested map keyed on (object_type → relation → Rule).
type Rules map[string]map[string]Rule

// Default evaluation limits.
const (
	DefaultMaxDepth   = 8
	DefaultMaxFanOut = 1024
)

// DirectLookup is the callback for "is there a direct (subject, relation,
// object) tuple?" Returns the tup_id on hit, "" on miss.
type DirectLookup func(subjectType, subjectID, relation, objectType, objectID string) (string, bool)

// ListByObject is the callback for the `tuple_to_userset` hop's
// enumeration. Returns the (subject_type, subject_id) pairs for tuples
// matching (object_type, object_id, relation).
type ListByObject func(objectType, objectID, relation string) []SubjectRef

// SubjectRef is the result row of ListByObject — the subject side of
// a `tuple_to_userset` hop.
type SubjectRef struct {
	SubjectType string
	SubjectID   string
	TupleID     string
}

// EvaluationResult is the outcome of Evaluate. MatchedTupleID is the
// id of the underlying direct tuple that ultimately satisfied the
// check; "" means denied.
type EvaluationResult struct {
	Allowed        bool
	MatchedTupleID string
}

type evalFrame struct {
	Relation   string
	ObjectType string
	ObjectID   string
}

// EvaluateOptions carries the per-call evaluation parameters.
type EvaluateOptions struct {
	MaxDepth   int
	MaxFanOut  int
}

func (o EvaluateOptions) maxDepth() int {
	if o.MaxDepth == 0 {
		return DefaultMaxDepth
	}
	return o.MaxDepth
}

func (o EvaluateOptions) maxFanOut() int {
	if o.MaxFanOut == 0 {
		return DefaultMaxFanOut
	}
	return o.MaxFanOut
}

// Evaluate runs the rewrite-rule expansion algorithm per ADR 0007.
//
//  1. Direct lookup. If a tuple matches, return it.
//  2. Rule expansion. If a rule exists for (object_type, relation),
//     expand its primitives. Each primitive recurses with bounded
//     depth and tracks a frame stack for cycle detection.
//  3. Short-circuit on first match.
//
// Cycle detection: per-evaluation, the stack of (relation, object_type,
// object_id) frames is checked before each recursive call. A repeat
// frame returns Denied for that branch (the cycle adds no new
// information) without raising.
//
// Bounds: opts.MaxDepth is the recursion ceiling; opts.MaxFanOut is the
// per-TupleToUserset enumeration ceiling. Exceeding either returns
// ErrEvaluationLimit.
func Evaluate(
	rules Rules,
	subjectType, subjectID, relation, objectType, objectID string,
	directLookup DirectLookup,
	listByObject ListByObject,
	opts EvaluateOptions,
) (EvaluationResult, error) {
	maxDepth := opts.maxDepth()
	maxFanOut := opts.maxFanOut()
	var rec func(relation, objectType, objectID string, stack []evalFrame, depth int) (EvaluationResult, error)
	rec = func(relation, objectType, objectID string, stack []evalFrame, depth int) (EvaluationResult, error) {
		// 1. Direct lookup.
		if tid, ok := directLookup(subjectType, subjectID, relation, objectType, objectID); ok {
			return EvaluationResult{Allowed: true, MatchedTupleID: tid}, nil
		}
		// 2. Rule expansion.
		if rules == nil {
			return EvaluationResult{}, nil
		}
		byObj, ok := rules[objectType]
		if !ok {
			return EvaluationResult{}, nil
		}
		rule, ok := byObj[relation]
		if !ok {
			return EvaluationResult{}, nil
		}
		// Cycle detection.
		frame := evalFrame{Relation: relation, ObjectType: objectType, ObjectID: objectID}
		for _, f := range stack {
			if f == frame {
				return EvaluationResult{}, nil
			}
		}
		// Depth bound.
		if depth >= maxDepth {
			return EvaluationResult{}, fmt.Errorf("depth=%d at %s.%s: %w", maxDepth, objectType, relation, ErrEvaluationLimit)
		}
		newStack := append(append([]evalFrame{}, stack...), frame)

		for _, node := range rule {
			switch n := node.(type) {
			case This:
				// Already covered by direct lookup.
			case ComputedUserset:
				r, err := rec(n.Relation, objectType, objectID, newStack, depth+1)
				if err != nil {
					return EvaluationResult{}, err
				}
				if r.Allowed {
					return r, nil
				}
			case TupleToUserset:
				related := listByObject(objectType, objectID, n.TuplesetRelation)
				if len(related) > maxFanOut {
					return EvaluationResult{}, fmt.Errorf("fan-out=%d at %s.%s via %s: %w", len(related), objectType, relation, n.TuplesetRelation, ErrEvaluationLimit)
				}
				for _, sub := range related {
					r, err := rec(n.ComputedUsersetRelation, sub.SubjectType, sub.SubjectID, newStack, depth+1)
					if err != nil {
						return EvaluationResult{}, err
					}
					if r.Allowed {
						return r, nil
					}
				}
			default:
				return EvaluationResult{}, fmt.Errorf("unknown rule node type: %T", n)
			}
		}
		return EvaluationResult{}, nil
	}
	return rec(relation, objectType, objectID, nil, 0)
}
