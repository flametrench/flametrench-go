// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
package flags

import (
	"errors"
	"fmt"
)

// ErrNotFound is returned when a flag lookup finds no matching record.
var ErrNotFound = errors.New("flag not found")

// ErrKeyConflict is returned when creating a flag whose key already exists
// within the requested scope.
var ErrKeyConflict = errors.New("flag key already exists in scope")

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
