// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
package notify

import (
	"errors"
	"fmt"
)

// ErrNotFound is returned when a notification does not exist OR when a caller
// attempts to access a notification they do not own. Both cases are
// indistinguishable (ADR 0022 §"Tenancy non-inference").
var ErrNotFound = errors.New("notification not found")

// InvalidFormatError is returned when an input field fails a structural or
// value constraint (ADR 0022 §Constraints).
type InvalidFormatError struct {
	Field  string
	Reason string
}

func (e *InvalidFormatError) Error() string {
	return fmt.Sprintf("notify: invalid format: field %q: %s", e.Field, e.Reason)
}

// IsInvalidFormat reports whether err is or wraps an InvalidFormatError.
func IsInvalidFormat(err error) bool {
	var e *InvalidFormatError
	return errors.As(err, &e)
}

// PreconditionError is returned for state-machine violations such as
// transitioning out of a terminal dismissed state (ADR 0019 taxonomy).
type PreconditionError struct {
	Reason string
}

func (e *PreconditionError) Error() string {
	return fmt.Sprintf("notify: precondition failed: %s", e.Reason)
}

// IsPrecondition reports whether err is or wraps a PreconditionError.
func IsPrecondition(err error) bool {
	var e *PreconditionError
	return errors.As(err, &e)
}
