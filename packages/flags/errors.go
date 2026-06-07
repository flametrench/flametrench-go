// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
package flags

import (
	"errors"
	"fmt"
)

// ErrNotFound is returned when a flag lookup finds no matching record.
var ErrNotFound = errors.New("flag not found")

// InvalidFormatError is returned when an input field fails a structural or
// value constraint (ADR 0021 §"Constraints").
type InvalidFormatError struct {
	Field  string
	Reason string
}

func (e *InvalidFormatError) Error() string {
	return fmt.Sprintf("flags: invalid format: field %q: %s", e.Field, e.Reason)
}

// IsInvalidFormat reports whether err is or wraps an InvalidFormatError.
func IsInvalidFormat(err error) bool {
	var e *InvalidFormatError
	return errors.As(err, &e)
}

// PreconditionError is returned for state/constraint violations such as a
// duplicate (scope, key) on create (ADR 0019 uniform error taxonomy).
type PreconditionError struct {
	Reason string
}

func (e *PreconditionError) Error() string {
	return fmt.Sprintf("flags: precondition failed: %s", e.Reason)
}

// IsPreconditionError reports whether err is or wraps a PreconditionError.
func IsPreconditionError(err error) bool {
	var e *PreconditionError
	return errors.As(err, &e)
}
