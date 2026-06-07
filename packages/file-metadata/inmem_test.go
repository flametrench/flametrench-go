// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
package filemetadata

import (
	"errors"
	"testing"
)

const (
	testScope = "org_0190f2a81b3c7abc8123000000000004"
	testOwner = "usr_0190f2a81b3c7abc8123000000000002"
	testRef   = "s3://bucket/file.bin"
	testHash  = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

func int64p(n int64) *int64 { return &n }
func strp(s string) *string { return &s }
func statusp(s Status) *Status { return &s }

func activeChecksum() *Checksum {
	return &Checksum{Algo: "sha-256", Value: testHash}
}

func TestCreateGetRoundTrip_Active(t *testing.T) {
	s := NewInMemoryFileMetadataStore()
	f, err := s.CreateFileMetadata(CreateFileMetadataInput{
		Scope:       testScope,
		OwnerUsrID:  testOwner,
		Name:        "report.pdf",
		ContentType: "application/pdf",
		SizeBytes:   int64p(1024),
		Checksum:    activeChecksum(),
		StorageRef:  strp(testRef),
		Status:      StatusActive,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.GetFileMetadata(f.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "report.pdf" || got.Status != StatusActive || *got.SizeBytes != 1024 {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestCreatePending_NullByteFactsAllowed(t *testing.T) {
	s := NewInMemoryFileMetadataStore()
	f, err := s.CreateFileMetadata(CreateFileMetadataInput{
		Scope:       testScope,
		OwnerUsrID:  testOwner,
		Name:        "upload.bin",
		ContentType: "application/octet-stream",
		Status:      StatusPending,
	})
	if err != nil {
		t.Fatalf("create pending: %v", err)
	}
	if f.Status != StatusPending || f.SizeBytes != nil || f.Checksum != nil || f.StorageRef != nil {
		t.Errorf("pending state mismatch: %+v", f)
	}
}

func TestPendingToActive(t *testing.T) {
	s := NewInMemoryFileMetadataStore()
	f, _ := s.CreateFileMetadata(CreateFileMetadataInput{
		Scope:       testScope,
		OwnerUsrID:  testOwner,
		Name:        "up.bin",
		ContentType: "application/octet-stream",
		Status:      StatusPending,
	})
	updated, err := s.UpdateFileMetadata(UpdateFileMetadataInput{
		ID:         f.ID,
		Status:     statusp(StatusActive),
		SizeBytes:  int64p(512),
		Checksum:   activeChecksum(),
		StorageRef: strp(testRef),
	})
	if err != nil {
		t.Fatalf("update pending→active: %v", err)
	}
	if updated.Status != StatusActive || *updated.SizeBytes != 512 {
		t.Errorf("after activate: %+v", updated)
	}
}

func TestSoftDelete_RecordRetained(t *testing.T) {
	s := NewInMemoryFileMetadataStore()
	f, _ := s.CreateFileMetadata(CreateFileMetadataInput{
		Scope:       testScope,
		OwnerUsrID:  testOwner,
		Name:        "del.txt",
		ContentType: "text/plain",
		SizeBytes:   int64p(10),
		Checksum:    activeChecksum(),
		StorageRef:  strp(testRef),
		Status:      StatusActive,
	})
	if err := s.DeleteFileMetadata(f.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	got, err := s.GetFileMetadata(f.ID)
	if err != nil {
		t.Fatalf("get after delete: %v", err)
	}
	if got.Status != StatusDeleted || got.Name != "del.txt" {
		t.Errorf("after delete: %+v", got)
	}
}

func TestUpdateName_ImmutableFieldsPreserved(t *testing.T) {
	s := NewInMemoryFileMetadataStore()
	f, _ := s.CreateFileMetadata(CreateFileMetadataInput{
		Scope:       testScope,
		OwnerUsrID:  testOwner,
		Name:        "old.md",
		ContentType: "text/markdown",
		SizeBytes:   int64p(100),
		Checksum:    activeChecksum(),
		StorageRef:  strp(testRef),
		Status:      StatusActive,
	})
	updated, err := s.UpdateFileMetadata(UpdateFileMetadataInput{ID: f.ID, Name: strp("new.md")})
	if err != nil {
		t.Fatalf("update name: %v", err)
	}
	if updated.Name != "new.md" {
		t.Errorf("name not updated: %q", updated.Name)
	}
	if updated.ContentType != "text/markdown" || updated.OwnerUsrID != testOwner || updated.Scope != testScope {
		t.Errorf("immutable fields changed: %+v", updated)
	}
}

func TestGetNotFound(t *testing.T) {
	s := NewInMemoryFileMetadataStore()
	_, err := s.GetFileMetadata("file_0190f2a81b3c7abc8123000000000099")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
}

func TestDeleteNotFound(t *testing.T) {
	s := NewInMemoryFileMetadataStore()
	err := s.DeleteFileMetadata("file_0190f2a81b3c7abc8123000000000099")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
}

func TestCreateActive_MissingByteFactsRejected(t *testing.T) {
	s := NewInMemoryFileMetadataStore()
	_, err := s.CreateFileMetadata(CreateFileMetadataInput{
		Scope:       testScope,
		OwnerUsrID:  testOwner,
		Name:        "f.txt",
		ContentType: "text/plain",
		Status:      StatusActive, // no SizeBytes/Checksum/StorageRef
	})
	if !IsInvalidFormat(err) {
		t.Errorf("missing byte facts: want InvalidFormatError, got %v", err)
	}
}

func TestInvalidChecksum(t *testing.T) {
	s := NewInMemoryFileMetadataStore()
	_, err := s.CreateFileMetadata(CreateFileMetadataInput{
		Scope:       testScope,
		OwnerUsrID:  testOwner,
		Name:        "f.txt",
		ContentType: "text/plain",
		SizeBytes:   int64p(1),
		Checksum:    &Checksum{Algo: "md5", Value: "badvalue"},
		StorageRef:  strp(testRef),
		Status:      StatusActive,
	})
	if !IsInvalidFormat(err) {
		t.Errorf("invalid checksum: want InvalidFormatError, got %v", err)
	}
}

func TestDeletedCannotTransition(t *testing.T) {
	s := NewInMemoryFileMetadataStore()
	f, _ := s.CreateFileMetadata(CreateFileMetadataInput{
		Scope:       testScope,
		OwnerUsrID:  testOwner,
		Name:        "f.txt",
		ContentType: "text/plain",
		Status:      StatusPending,
	})
	s.DeleteFileMetadata(f.ID)
	_, err := s.UpdateFileMetadata(UpdateFileMetadataInput{ID: f.ID, Status: statusp(StatusActive)})
	if !IsPreconditionError(err) {
		t.Errorf("transition from deleted: want PreconditionError, got %v", err)
	}
}

func TestActiveByteFactsImmutable(t *testing.T) {
	s := NewInMemoryFileMetadataStore()
	f, _ := s.CreateFileMetadata(CreateFileMetadataInput{
		Scope:       testScope,
		OwnerUsrID:  testOwner,
		Name:        "f.txt",
		ContentType: "text/plain",
		SizeBytes:   int64p(10),
		Checksum:    activeChecksum(),
		StorageRef:  strp(testRef),
		Status:      StatusActive,
	})
	_, err := s.UpdateFileMetadata(UpdateFileMetadataInput{ID: f.ID, SizeBytes: int64p(20)})
	if !IsPreconditionError(err) {
		t.Errorf("immutable byte-fact update: want PreconditionError, got %v", err)
	}
}
