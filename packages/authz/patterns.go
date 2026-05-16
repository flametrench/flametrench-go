// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
package authz

import "regexp"

// RelationNamePattern is the cross-SDK regex for a valid relation name.
// 2-32 lowercase ASCII letters or underscores. Mirrors the Python /
// Node / PHP / Java SDKs.
var RelationNamePattern = regexp.MustCompile(`^[a-z_]{2,32}$`)

// TypePrefixPattern is the cross-SDK regex for a valid object_type /
// subject_type prefix. 2-6 lowercase ASCII letters.
var TypePrefixPattern = regexp.MustCompile(`^[a-z]{2,6}$`)
