// Package flags implements the Flametrench feature-flag primitive (ADR 0021).
// A flag is a named boolean toggle with an ordered list of targeting rules;
// targeting reuses the authz check() predicate rather than introducing a
// parallel rules DSL.
//
// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
package flags

import "time"

// RuleKind discriminates the two targeting-rule types.
type RuleKind string

const (
	RuleKindAuthz      RuleKind = "authz"
	RuleKindPercentage RuleKind = "percentage"
)

// RuleObject is the authz object in an authz-kind targeting rule.
type RuleObject struct {
	Type string
	ID   string
}

// Rule is one entry in a Flag's ordered targeting list.
// For RuleKindAuthz: Relation and Object are set; BasisPoints is ignored.
// For RuleKindPercentage: BasisPoints is set; Relation and Object are ignored.
type Rule struct {
	Kind        RuleKind
	Relation    string      // authz rules only
	Object      *RuleObject // authz rules only
	BasisPoints int         // percentage rules only; [0, 10000]
	Variant     bool
}

// Flag is the entity shape for a feature flag (ADR 0021 §"Entity shape").
type Flag struct {
	ID             string
	Scope          string // org_<32hex>
	Key            string
	Enabled        bool
	DefaultVariant bool
	Rules          []Rule
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// FlagsPage is a cursor-paginated result from ListFlags.
type FlagsPage struct {
	Data       []Flag
	NextCursor *string
}
