// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package audit

import "errors"

// ErrNotFound is returned when Get is called with an id that does not exist.
var ErrNotFound = errors.New("audit event not found")
