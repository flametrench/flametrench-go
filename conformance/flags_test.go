// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
package conformance

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/flametrench/flametrench-go/packages/flags"
)

type assignBucketFixture struct {
	Tests []struct {
		ID    string `json:"id"`
		Input struct {
			Key       string `json:"key"`
			SubjectID string `json:"subject_id"`
		} `json:"input"`
		Expected struct {
			Result int `json:"result"`
		} `json:"expected"`
	} `json:"tests"`
}

func TestAssignBucketConformance(t *testing.T) {
	data, err := os.ReadFile("fixtures/flags/assign-bucket.json")
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	var fixture assignBucketFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	for _, tc := range fixture.Tests {
		tc := tc
		t.Run(tc.ID, func(t *testing.T) {
			got := flags.AssignBucket(tc.Input.Key, tc.Input.SubjectID)
			if int(got) != tc.Expected.Result {
				t.Errorf("AssignBucket(%q, %q) = %d; want %d",
					tc.Input.Key, tc.Input.SubjectID, got, tc.Expected.Result)
			}
		})
	}
}
