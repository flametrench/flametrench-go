// Package filemetadata implements the Flametrench file-metadata primitive
// (ADR 0020). It tracks file metadata and lifecycle without touching blob
// bytes; storage_ref is an opaque adopter pointer that the primitive stores
// verbatim and never dereferences.
//
// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
package filemetadata

import "time"

// Status is the lifecycle state of a FileMetadata record (ADR 0020 §"Lifecycle").
type Status string

const (
	StatusPending Status = "pending"
	StatusActive  Status = "active"
	StatusDeleted Status = "deleted"
)

// Checksum carries the hash of a file's bytes. algo is pinned to "sha-256"
// in v0.4; value is 64 lowercase hex characters.
type Checksum struct {
	Algo  string // "sha-256"
	Value string // 64 lowercase hex
}

// FileMetadata is the entity shape for a registered file (ADR 0020 §"Entity shape").
// SizeBytes, Checksum, and StorageRef are nil when Status is pending;
// they become non-nil and immutable on the pending→active transition (or at
// create when Status is already active).
type FileMetadata struct {
	ID          string
	Scope       string    // org_<32hex>
	OwnerUsrID  string    // usr_<32hex>
	Name        string
	ContentType string
	SizeBytes   *int64
	Checksum    *Checksum
	StorageRef  *string // opaque; never dereferenced by the primitive
	Status      Status
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// FileMetadataPage is a cursor-paginated result from ListFileMetadata.
type FileMetadataPage struct {
	Data       []FileMetadata
	NextCursor *string
}
