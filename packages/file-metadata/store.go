// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
package filemetadata

// CreateFileMetadataInput carries fields supplied at file registration.
// If Status is "active", SizeBytes, Checksum, and StorageRef MUST be non-nil.
// If Status is "pending", those three may be nil.
type CreateFileMetadataInput struct {
	Scope       string
	OwnerUsrID  string
	Name        string
	ContentType string
	SizeBytes   *int64
	Checksum    *Checksum
	StorageRef  *string
	Status      Status
}

// UpdateFileMetadataInput carries the mutable fields for an update.
// Setting Status to "active" on a pending file requires SizeBytes, Checksum,
// and StorageRef to be provided (pending→active transition).
// Setting Status to "deleted" soft-deletes the record.
type UpdateFileMetadataInput struct {
	ID         string
	Name       *string
	Status     *Status
	SizeBytes  *int64
	Checksum   *Checksum
	StorageRef *string
}

// ListFileMetadataOptions controls cursor-paginated file enumeration.
type ListFileMetadataOptions struct {
	Scope       string
	OwnerUsrID  *string
	Status      *Status
	ContentType *string
	Cursor      *string
	Limit       int
}

// FileMetadataStore is the persistence interface for the file-metadata
// primitive (ADR 0020).
type FileMetadataStore interface {
	// CreateFileMetadata registers a file's metadata. Returns
	// InvalidFormatError on constraint violations.
	CreateFileMetadata(in CreateFileMetadataInput) (FileMetadata, error)

	// GetFileMetadata fetches a file by its wire-format id.
	// Returns ErrNotFound if no such record exists.
	GetFileMetadata(id string) (FileMetadata, error)

	// ListFileMetadata returns cursor-paginated files scoped to one org,
	// optionally filtered by owner, status, or content-type.
	ListFileMetadata(opts ListFileMetadataOptions) (FileMetadataPage, error)

	// UpdateFileMetadata mutates the mutable subset of a file record.
	// Returns ErrNotFound if the file is gone; PreconditionError for invalid
	// lifecycle transitions or immutable-field mutation.
	UpdateFileMetadata(in UpdateFileMetadataInput) (FileMetadata, error)

	// DeleteFileMetadata soft-deletes a file (transitions to status "deleted").
	// The record is retained for audit reconstruction. Returns ErrNotFound if
	// the record does not exist.
	DeleteFileMetadata(id string) error
}
