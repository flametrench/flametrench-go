// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"fmt"
)

// ErrNotFound is returned when Get is called with an id that does not exist.
var ErrNotFound = errors.New("audit event not found")

// InvalidFormatError is raised by Write when the event payload fails
// shape or value validation (ADR 0019 §Errors). Field names the
// offending part of the event (e.g. "auth", "outcome", "size").
// This is the same cross-cutting error type used by the identity,
// tenancy, and authorization layers — the audit primitive does not
// introduce a separate error class.
type InvalidFormatError struct {
	Field  string
	Reason string
}

func (e *InvalidFormatError) Error() string {
	return fmt.Sprintf("audit: invalid format: field %q: %s", e.Field, e.Reason)
}

// IsInvalidFormat reports whether err is or wraps an InvalidFormatError.
func IsInvalidFormat(err error) bool {
	var e *InvalidFormatError
	return errors.As(err, &e)
}
