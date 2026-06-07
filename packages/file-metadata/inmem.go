// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
package filemetadata

import (
	"regexp"
	"sort"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/flametrench/flametrench-go/packages/ids"
)

var checksumValueRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

func validateChecksum(c *Checksum, field string) error {
	if c.Algo != "sha-256" {
		return &InvalidFormatError{Field: field + ".algo", Reason: `must be "sha-256"`}
	}
	if !checksumValueRe.MatchString(c.Value) {
		return &InvalidFormatError{Field: field + ".value", Reason: "must be 64 lowercase hex characters"}
	}
	return nil
}

func cloneChecksum(c *Checksum) *Checksum {
	if c == nil {
		return nil
	}
	copy := *c
	return &copy
}

func cloneString(s *string) *string {
	if s == nil {
		return nil
	}
	copy := *s
	return &copy
}

func cloneInt64(n *int64) *int64 {
	if n == nil {
		return nil
	}
	copy := *n
	return &copy
}

func cloneFile(f FileMetadata) FileMetadata {
	f.Checksum = cloneChecksum(f.Checksum)
	f.StorageRef = cloneString(f.StorageRef)
	f.SizeBytes = cloneInt64(f.SizeBytes)
	return f
}

// InMemoryFileMetadataStore is a thread-safe in-process FileMetadataStore for
// testing and development (ADR 0020).
type InMemoryFileMetadataStore struct {
	mu    sync.RWMutex
	files map[string]*FileMetadata // id → record
}

// NewInMemoryFileMetadataStore returns an empty InMemoryFileMetadataStore.
func NewInMemoryFileMetadataStore() *InMemoryFileMetadataStore {
	return &InMemoryFileMetadataStore{files: make(map[string]*FileMetadata)}
}

func (s *InMemoryFileMetadataStore) CreateFileMetadata(in CreateFileMetadataInput) (FileMetadata, error) {
	if !ids.IsValid(in.Scope, "org") {
		return FileMetadata{}, &InvalidFormatError{Field: "scope", Reason: "must be a valid org_ id"}
	}
	if !ids.IsValid(in.OwnerUsrID, "usr") {
		return FileMetadata{}, &InvalidFormatError{Field: "owner_usr_id", Reason: "must be a valid usr_ id"}
	}
	nameLen := utf8.RuneCountInString(in.Name)
	if nameLen < 1 || nameLen > 255 {
		return FileMetadata{}, &InvalidFormatError{Field: "name", Reason: "must be 1–255 Unicode code units"}
	}
	if in.ContentType == "" {
		return FileMetadata{}, &InvalidFormatError{Field: "content_type", Reason: "must be non-empty"}
	}
	if in.Status != StatusPending && in.Status != StatusActive {
		return FileMetadata{}, &InvalidFormatError{Field: "status", Reason: `create status must be "pending" or "active"`}
	}
	if in.Status == StatusActive {
		if in.SizeBytes == nil || *in.SizeBytes < 0 {
			return FileMetadata{}, &InvalidFormatError{Field: "size_bytes", Reason: "must be non-negative when status is active"}
		}
		if in.Checksum == nil {
			return FileMetadata{}, &InvalidFormatError{Field: "checksum", Reason: "must be set when status is active"}
		}
		if err := validateChecksum(in.Checksum, "checksum"); err != nil {
			return FileMetadata{}, err
		}
		if in.StorageRef == nil || *in.StorageRef == "" {
			return FileMetadata{}, &InvalidFormatError{Field: "storage_ref", Reason: "must be non-empty when status is active"}
		}
	}

	id, err := ids.Generate("file")
	if err != nil {
		return FileMetadata{}, err
	}
	now := time.Now().UTC()
	f := &FileMetadata{
		ID:          id,
		Scope:       in.Scope,
		OwnerUsrID:  in.OwnerUsrID,
		Name:        in.Name,
		ContentType: in.ContentType,
		SizeBytes:   cloneInt64(in.SizeBytes),
		Checksum:    cloneChecksum(in.Checksum),
		StorageRef:  cloneString(in.StorageRef),
		Status:      in.Status,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	s.mu.Lock()
	s.files[id] = f
	s.mu.Unlock()

	return cloneFile(*f), nil
}

func (s *InMemoryFileMetadataStore) GetFileMetadata(id string) (FileMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f, ok := s.files[id]
	if !ok {
		return FileMetadata{}, ErrNotFound
	}
	return cloneFile(*f), nil
}

func (s *InMemoryFileMetadataStore) ListFileMetadata(opts ListFileMetadataOptions) (FileMetadataPage, error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var matching []FileMetadata
	for _, f := range s.files {
		if f.Scope != opts.Scope {
			continue
		}
		if opts.OwnerUsrID != nil && f.OwnerUsrID != *opts.OwnerUsrID {
			continue
		}
		if opts.Status != nil && f.Status != *opts.Status {
			continue
		}
		if opts.ContentType != nil && f.ContentType != *opts.ContentType {
			continue
		}
		matching = append(matching, cloneFile(*f))
	}
	sort.Slice(matching, func(i, j int) bool { return matching[i].ID < matching[j].ID })

	if opts.Cursor != nil {
		for i, f := range matching {
			if f.ID == *opts.Cursor {
				matching = matching[i+1:]
				break
			}
		}
	}

	var nextCursor *string
	if len(matching) > limit {
		c := matching[limit-1].ID
		nextCursor = &c
		matching = matching[:limit]
	}
	return FileMetadataPage{Data: matching, NextCursor: nextCursor}, nil
}

func (s *InMemoryFileMetadataStore) UpdateFileMetadata(in UpdateFileMetadataInput) (FileMetadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, ok := s.files[in.ID]
	if !ok {
		return FileMetadata{}, ErrNotFound
	}

	if in.Status != nil {
		newStatus := *in.Status
		switch {
		case f.Status == StatusDeleted:
			return FileMetadata{}, &PreconditionError{Reason: "deleted files cannot be transitioned"}
		case f.Status == StatusActive && newStatus == StatusPending:
			return FileMetadata{}, &PreconditionError{Reason: "cannot revert active file to pending"}
		case f.Status == StatusPending && newStatus == StatusActive:
			// pending→active: byte-facts must be supplied
			if in.SizeBytes == nil || *in.SizeBytes < 0 {
				return FileMetadata{}, &InvalidFormatError{Field: "size_bytes", Reason: "must be non-negative for pending→active transition"}
			}
			if in.Checksum == nil {
				return FileMetadata{}, &InvalidFormatError{Field: "checksum", Reason: "must be set for pending→active transition"}
			}
			if err := validateChecksum(in.Checksum, "checksum"); err != nil {
				return FileMetadata{}, err
			}
			if in.StorageRef == nil || *in.StorageRef == "" {
				return FileMetadata{}, &InvalidFormatError{Field: "storage_ref", Reason: "must be non-empty for pending→active transition"}
			}
			f.SizeBytes = cloneInt64(in.SizeBytes)
			f.Checksum = cloneChecksum(in.Checksum)
			f.StorageRef = cloneString(in.StorageRef)
		}
		f.Status = newStatus
	} else if f.Status == StatusActive {
		// Byte-facts are immutable once set (active state).
		if in.SizeBytes != nil || in.Checksum != nil || in.StorageRef != nil {
			return FileMetadata{}, &PreconditionError{Reason: "size_bytes, checksum, and storage_ref are immutable once active"}
		}
	}

	if in.Name != nil {
		nameLen := utf8.RuneCountInString(*in.Name)
		if nameLen < 1 || nameLen > 255 {
			return FileMetadata{}, &InvalidFormatError{Field: "name", Reason: "must be 1–255 Unicode code units"}
		}
		f.Name = *in.Name
	}

	f.UpdatedAt = time.Now().UTC()
	return cloneFile(*f), nil
}

func (s *InMemoryFileMetadataStore) DeleteFileMetadata(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.files[id]
	if !ok {
		return ErrNotFound
	}
	if f.Status != StatusDeleted {
		f.Status = StatusDeleted
		f.UpdatedAt = time.Now().UTC()
	}
	return nil
}
