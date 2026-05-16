// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
package tenancy

import "encoding/json"

// jsonUnmarshalImpl wraps stdlib JSON parsing — used for pre_tuples JSONB
// decoding in postgres.go.
func jsonUnmarshalImpl(data []byte, v any) error {
	return json.Unmarshal(data, v)
}
