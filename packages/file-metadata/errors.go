// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
package filemetadata

import (
	"errors"
	"fmt"
)

// ErrNotFound is returned when a file lookup finds no matching record.
var ErrNotFound = errors.New("file metadata not found")

// InvalidFormatError is returned when an input field fails a structural or
// value constraint (ADR 0020 §"Constraints").
type InvalidFormatError struct {
	Field  string
	Reason string
}

func (e *InvalidFormatError) Error() string {
	return fmt.Sprintf("file-metadata: invalid format: field %q: %s", e.Field, e.Reason)
}

// IsInvalidFormat reports whether err is or wraps an InvalidFormatError.
func IsInvalidFormat(err error) bool {
	var e *InvalidFormatError
	return errors.As(err, &e)
}

// PreconditionError is returned for lifecycle/state violations: invalid status
// transitions or attempts to mutate immutable fields (ADR 0020, pinned in PR #51).
type PreconditionError struct{ Reason string }

func (e *PreconditionError) Error() string {
	return "file-metadata: precondition failed: " + e.Reason
}

// IsPreconditionError reports whether err is or wraps a PreconditionError.
func IsPreconditionError(err error) bool {
	var e *PreconditionError
	return errors.As(err, &e)
}
