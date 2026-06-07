// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

// Conformance runner for the file-metadata lifecycle-shape fixture (ADR 0020).
// Tests create/get/update/delete round-trips asserting structural invariants.
// Matching for get results is SUPERSET (result ⊇ expected).

package conformance

import (
	"path/filepath"
	"reflect"
	"testing"

	filemetadata "github.com/flametrench/flametrench-go/packages/file-metadata"
	"github.com/flametrench/flametrench-go/packages/ids"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func parseCreateFileMetadataInput(input map[string]any) filemetadata.CreateFileMetadataInput {
	var in filemetadata.CreateFileMetadataInput
	in.Scope = strField(input, "scope")
	in.OwnerUsrID = strField(input, "owner_usr_id")
	in.Name = strField(input, "name")
	in.ContentType = strField(input, "content_type")
	in.Status = filemetadata.Status(strField(input, "status"))

	if raw, ok := input["size_bytes"]; ok && raw != nil {
		if n, ok := raw.(float64); ok {
			v := int64(n)
			in.SizeBytes = &v
		}
	}
	if raw, ok := input["checksum"]; ok && raw != nil {
		if m, ok := raw.(map[string]any); ok {
			in.Checksum = &filemetadata.Checksum{
				Algo:  strField(m, "algo"),
				Value: strField(m, "value"),
			}
		}
	}
	if raw, ok := input["storage_ref"]; ok && raw != nil {
		if s, ok := raw.(string); ok {
			in.StorageRef = &s
		}
	}
	return in
}

func parseUpdateFileMetadataInput(input map[string]any) filemetadata.UpdateFileMetadataInput {
	in := filemetadata.UpdateFileMetadataInput{ID: strField(input, "id")}
	if s := strPtr(input, "name"); s != nil {
		in.Name = s
	}
	if s, ok := input["status"].(string); ok {
		st := filemetadata.Status(s)
		in.Status = &st
	}
	if raw, ok := input["size_bytes"]; ok && raw != nil {
		if n, ok := raw.(float64); ok {
			v := int64(n)
			in.SizeBytes = &v
		}
	}
	if raw, ok := input["checksum"]; ok && raw != nil {
		if m, ok := raw.(map[string]any); ok {
			in.Checksum = &filemetadata.Checksum{
				Algo:  strField(m, "algo"),
				Value: strField(m, "value"),
			}
		}
	}
	if raw, ok := input["storage_ref"]; ok && raw != nil {
		if s, ok := raw.(string); ok {
			in.StorageRef = &s
		}
	}
	return in
}

// assertFileMetadataSuperset checks that every field in expected is present
// and equal in actual. Server-set fields (created_at, updated_at) not listed
// in expected are ignored.
func assertFileMetadataSuperset(t *testing.T, caseID, label string, expected map[string]any, actual filemetadata.FileMetadata, captures map[string]string) {
	t.Helper()
	res := expected
	if r, ok := expected["result"].(map[string]any); ok {
		res = r
	}
	res = resolveInput(res, captures)

	for key, wantRaw := range res {
		switch key {
		case "id":
			if s, ok := wantRaw.(string); ok && actual.ID != s {
				t.Errorf("%s/%s: id = %q, want %q", caseID, label, actual.ID, s)
			}
		case "scope":
			if s, ok := wantRaw.(string); ok && actual.Scope != s {
				t.Errorf("%s/%s: scope = %q, want %q", caseID, label, actual.Scope, s)
			}
		case "owner_usr_id":
			if s, ok := wantRaw.(string); ok && actual.OwnerUsrID != s {
				t.Errorf("%s/%s: owner_usr_id = %q, want %q", caseID, label, actual.OwnerUsrID, s)
			}
		case "name":
			if s, ok := wantRaw.(string); ok && actual.Name != s {
				t.Errorf("%s/%s: name = %q, want %q", caseID, label, actual.Name, s)
			}
		case "content_type":
			if s, ok := wantRaw.(string); ok && actual.ContentType != s {
				t.Errorf("%s/%s: content_type = %q, want %q", caseID, label, actual.ContentType, s)
			}
		case "status":
			if s, ok := wantRaw.(string); ok && string(actual.Status) != s {
				t.Errorf("%s/%s: status = %q, want %q", caseID, label, actual.Status, s)
			}
		case "size_bytes":
			if wantRaw == nil {
				if actual.SizeBytes != nil {
					t.Errorf("%s/%s: size_bytes = %v, want null", caseID, label, *actual.SizeBytes)
				}
			} else if n, ok := wantRaw.(float64); ok {
				if actual.SizeBytes == nil || *actual.SizeBytes != int64(n) {
					var got interface{} = nil
					if actual.SizeBytes != nil {
						got = *actual.SizeBytes
					}
					t.Errorf("%s/%s: size_bytes = %v, want %d", caseID, label, got, int64(n))
				}
			}
		case "checksum":
			if wantRaw == nil {
				if actual.Checksum != nil {
					t.Errorf("%s/%s: checksum = %+v, want null", caseID, label, actual.Checksum)
				}
			} else if m, ok := wantRaw.(map[string]any); ok {
				if actual.Checksum == nil {
					t.Errorf("%s/%s: checksum = null, want %v", caseID, label, m)
				} else {
					want := filemetadata.Checksum{Algo: strField(m, "algo"), Value: strField(m, "value")}
					if !reflect.DeepEqual(*actual.Checksum, want) {
						t.Errorf("%s/%s: checksum = %+v, want %+v", caseID, label, *actual.Checksum, want)
					}
				}
			}
		case "storage_ref":
			if wantRaw == nil {
				if actual.StorageRef != nil {
					t.Errorf("%s/%s: storage_ref = %q, want null", caseID, label, *actual.StorageRef)
				}
			} else if s, ok := wantRaw.(string); ok {
				if actual.StorageRef == nil || *actual.StorageRef != s {
					t.Errorf("%s/%s: storage_ref = %v, want %q", caseID, label, actual.StorageRef, s)
				}
			}
		}
	}
}

// ── runner ───────────────────────────────────────────────────────────────────

func runFileMetadataCase(t *testing.T, c StepCase) {
	t.Helper()
	store := filemetadata.NewInMemoryFileMetadataStore()
	captures := make(map[string]string)

	for _, name := range c.Users {
		id, err := ids.Generate("usr")
		if err != nil {
			t.Fatalf("%s: generate usr id for %q: %v", c.ID, name, err)
		}
		captures[name] = id
	}

	for _, step := range c.Steps {
		input := resolveInput(step.Input, captures)

		switch step.Op {
		case "create_file_metadata":
			in := parseCreateFileMetadataInput(input)
			f, err := store.CreateFileMetadata(in)
			if err != nil {
				t.Fatalf("%s/%s: create: %v", c.ID, step.Op, err)
			}
			for varName, path := range step.Captures {
				if path == "id" {
					captures[varName] = f.ID
				}
			}

		case "get_file_metadata":
			fileID := strField(input, "id")
			f, err := store.GetFileMetadata(fileID)
			if err != nil {
				t.Fatalf("%s/%s: get(%q): %v", c.ID, step.Op, fileID, err)
			}
			if res, ok := step.Expected["result"].(map[string]any); ok {
				assertFileMetadataSuperset(t, c.ID, step.Op, res, f, captures)
			}

		case "update_file_metadata":
			in := parseUpdateFileMetadataInput(input)
			if _, err := store.UpdateFileMetadata(in); err != nil {
				t.Fatalf("%s/%s: update(%q): %v", c.ID, step.Op, in.ID, err)
			}

		case "delete_file_metadata":
			fileID := strField(input, "id")
			if err := store.DeleteFileMetadata(fileID); err != nil {
				t.Fatalf("%s/%s: delete(%q): %v", c.ID, step.Op, fileID, err)
			}

		default:
			t.Fatalf("%s: unknown op %q", c.ID, step.Op)
		}
	}
}

func TestFileMetadataLifecycleConformance(t *testing.T) {
	path := filepath.Join("fixtures", "file-metadata", "lifecycle-shape.json")
	f := loadStepFixtureFile(t, path)
	for _, c := range f.Tests {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			runFileMetadataCase(t, c)
		})
	}
}
