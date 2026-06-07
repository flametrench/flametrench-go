// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
package flags

// CheckFn is the authz predicate injected into Evaluate for authz-kind rules.
// It answers: does subjectID hold relation on (objectType, objectID)?
type CheckFn func(subjectID, relation, objectType, objectID string) bool

// CreateFlagInput carries the fields supplied by the caller at flag creation.
type CreateFlagInput struct {
	Scope          string
	Key            string
	Enabled        bool
	DefaultVariant bool
	Rules          []Rule
}

// UpdateFlagInput carries the mutable fields for an update. Nil pointer fields
// are left unchanged. Rules replaces the existing list when UpdateRules is true.
type UpdateFlagInput struct {
	ID             string
	Enabled        *bool
	DefaultVariant *bool
	Rules          []Rule
	UpdateRules    bool
}

// ListFlagsOptions controls cursor-paginated flag enumeration.
type ListFlagsOptions struct {
	Scope  string
	Cursor *string
	Limit  int
}

// FlagsStore is the persistence interface for the flags primitive (ADR 0021).
type FlagsStore interface {
	// CreateFlag registers a new flag; returns ErrKeyConflict if key already
	// exists in scope, InvalidFormatError on constraint violations.
	CreateFlag(in CreateFlagInput) (Flag, error)

	// GetFlag fetches a flag by its wire-format id. Returns ErrNotFound if
	// the flag does not exist.
	GetFlag(id string) (Flag, error)

	// GetFlagByKey fetches a flag by (scope, key). Returns ErrNotFound if
	// no such flag exists.
	GetFlagByKey(scope, key string) (Flag, error)

	// ListFlags returns a cursor-paginated slice of flags scoped to one org.
	ListFlags(opts ListFlagsOptions) (FlagsPage, error)

	// UpdateFlag mutates enabled, default_variant, and/or rules.
	// key and scope are immutable. Returns ErrNotFound if the flag is gone.
	UpdateFlag(in UpdateFlagInput) (Flag, error)

	// DeleteFlag removes the flag permanently. Returns ErrNotFound if the
	// flag does not exist.
	DeleteFlag(id string) error

	// Evaluate resolves a flag for a subject and returns its effective boolean
	// value. If the flag key is not found in scope, false is returned (an
	// undefined flag is safely off — ADR 0021 §"Evaluation"). check is called
	// for authz-kind rules; it may be nil when no authz rules are present.
	Evaluate(scope, key, subjectID string, check CheckFn) (bool, error)
}
