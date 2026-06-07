// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

// InMemoryTenancyStore — reference in-memory implementation of the
// TenancyStore interface. Spec-correctness reference; PostgresTenancyStore
// (postgres.go) mirrors it against a real database.

package tenancy

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	flametrenchids "github.com/flametrench/flametrench-go/packages/ids"
)

// slugRe enforces the org-slug pattern: lowercase alphanum + hyphens,
// no leading/trailing hyphen, 1–63 chars (DNS-label cap from ADR 0011).
var slugRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func validateSlug(slug string) error {
	if !slugRe.MatchString(slug) {
		return &PreconditionError{Msg: "invalid org slug format", Reason: "invalid_slug"}
	}
	return nil
}

// Compile-time guarantee.
var _ TenancyStore = (*InMemoryTenancyStore)(nil)

// InMemoryTenancyStore is the reference in-memory tenancy store.
// Safe for concurrent use.
type InMemoryTenancyStore struct {
	mu sync.Mutex

	clock func() time.Time

	orgs        map[string]Organization
	memberships map[string]Membership
	invitations map[string]Invitation

	// Tuples by natural-key string. The natural key is
	// "subject_type|subject_id|relation|object_type|object_id".
	tuples map[string]Tuple

	// Index: org slug → org id (active orgs only; case-sensitive).
	orgBySlug map[string]string

	// Index: "org|usr" → mem_id (active memberships only).
	activeMemByOrgUsr map[string]string
}

func NewInMemoryTenancyStore() *InMemoryTenancyStore {
	return &InMemoryTenancyStore{
		clock:             func() time.Time { return time.Now().UTC() },
		orgs:              map[string]Organization{},
		memberships:       map[string]Membership{},
		invitations:       map[string]Invitation{},
		tuples:            map[string]Tuple{},
		orgBySlug:         map[string]string{},
		activeMemByOrgUsr: map[string]string{},
	}
}

func (s *InMemoryTenancyStore) WithClock(clock func() time.Time) *InMemoryTenancyStore {
	s.clock = clock
	return s
}

func (s *InMemoryTenancyStore) now() time.Time { return s.clock() }

func tupleKey(t Tuple) string {
	return t.SubjectType + "|" + t.SubjectID + "|" + t.Relation + "|" + t.ObjectType + "|" + t.ObjectID
}

func orgUsrKey(orgID, usrID string) string { return orgID + "|" + usrID }

// ─── Orgs ───

func (s *InMemoryTenancyStore) CreateOrg(creator string, opts CreateOrgOptions) (CreateOrgResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if opts.Slug != nil {
		if err := validateSlug(*opts.Slug); err != nil {
			return CreateOrgResult{}, err
		}
		if _, taken := s.orgBySlug[*opts.Slug]; taken {
			return CreateOrgResult{}, fmt.Errorf("slug %q: %w", *opts.Slug, ErrOrgSlugConflict)
		}
	}
	orgID, err := flametrenchids.Generate("org")
	if err != nil {
		return CreateOrgResult{}, err
	}
	now := s.now()
	org := Organization{ID: orgID, Status: StatusActive, CreatedAt: now, UpdatedAt: now, Name: opts.Name, Slug: opts.Slug}
	s.orgs[orgID] = org
	if opts.Slug != nil {
		s.orgBySlug[*opts.Slug] = orgID
	}
	// Owner membership.
	memID, err := flametrenchids.Generate("mem")
	if err != nil {
		return CreateOrgResult{}, err
	}
	mem := Membership{
		ID: memID, UsrID: creator, OrgID: orgID, Role: RoleOwner,
		Status: StatusActive, CreatedAt: now, UpdatedAt: now,
	}
	s.memberships[memID] = mem
	s.activeMemByOrgUsr[orgUsrKey(orgID, creator)] = memID
	// Owner tuple.
	t := Tuple{SubjectType: "usr", SubjectID: creator, Relation: "owner", ObjectType: "org", ObjectID: orgID}
	s.tuples[tupleKey(t)] = t
	return CreateOrgResult{Org: org, OwnerMembership: mem}, nil
}

func (s *InMemoryTenancyStore) GetOrg(orgID string) (Organization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.orgs[orgID]
	if !ok {
		return Organization{}, fmt.Errorf("org %s: %w", orgID, ErrNotFound)
	}
	return o, nil
}

func (s *InMemoryTenancyStore) UpdateOrg(orgID string, in UpdateOrgInput) (Organization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.orgs[orgID]
	if !ok {
		return Organization{}, fmt.Errorf("org %s: %w", orgID, ErrNotFound)
	}
	if o.Status == StatusRevoked {
		return Organization{}, fmt.Errorf("org %s revoked: %w", orgID, ErrAlreadyTerminal)
	}
	if in.ClearName {
		o.Name = nil
	} else if in.Name != nil {
		o.Name = in.Name
	}
	if in.ClearSlug {
		if o.Slug != nil {
			delete(s.orgBySlug, *o.Slug)
		}
		o.Slug = nil
	} else if in.Slug != nil {
		newSlug := *in.Slug
		if err := validateSlug(newSlug); err != nil {
			return Organization{}, err
		}
		if existing, taken := s.orgBySlug[newSlug]; taken && existing != orgID {
			return Organization{}, fmt.Errorf("slug %q: %w", newSlug, ErrOrgSlugConflict)
		}
		if o.Slug != nil {
			delete(s.orgBySlug, *o.Slug)
		}
		o.Slug = in.Slug
		s.orgBySlug[newSlug] = orgID
	}
	o.UpdatedAt = s.now()
	s.orgs[orgID] = o
	return o, nil
}

func (s *InMemoryTenancyStore) SuspendOrg(orgID string) (Organization, error) {
	return s.transitionOrg(orgID, StatusSuspended)
}
func (s *InMemoryTenancyStore) ReinstateOrg(orgID string) (Organization, error) {
	return s.transitionOrg(orgID, StatusActive)
}
func (s *InMemoryTenancyStore) RevokeOrg(orgID string) (Organization, error) {
	return s.transitionOrg(orgID, StatusRevoked)
}

func (s *InMemoryTenancyStore) transitionOrg(orgID string, to Status) (Organization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.orgs[orgID]
	if !ok {
		return Organization{}, fmt.Errorf("org %s: %w", orgID, ErrNotFound)
	}
	if o.Status == StatusRevoked {
		return Organization{}, fmt.Errorf("org %s: %w", orgID, ErrAlreadyTerminal)
	}
	if to == StatusActive && o.Status != StatusSuspended {
		return Organization{}, &PreconditionError{Msg: "org not suspended", Reason: "invalid_transition"}
	}
	o = o.WithStatus(to, s.now())
	s.orgs[orgID] = o
	if to == StatusRevoked {
		// Cascade: revoke memberships + drop tuples.
		for mid, m := range s.memberships {
			if m.OrgID == orgID && m.Status == StatusActive {
				m.Status = StatusRevoked
				m.UpdatedAt = s.now()
				s.memberships[mid] = m
				delete(s.activeMemByOrgUsr, orgUsrKey(orgID, m.UsrID))
				tk := tupleKey(Tuple{SubjectType: "usr", SubjectID: m.UsrID, Relation: string(m.Role), ObjectType: "org", ObjectID: orgID})
				delete(s.tuples, tk)
			}
		}
		if o.Slug != nil {
			delete(s.orgBySlug, *o.Slug)
		}
	}
	return o, nil
}

func (s *InMemoryTenancyStore) ListOrgs(opts ListOrgsOptions) (Page[Organization], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	var queryLower string
	if opts.Query != nil {
		queryLower = strings.ToLower(*opts.Query)
	}
	matched := make([]Organization, 0, len(s.orgs))
	for _, o := range s.orgs {
		if opts.Status != nil && o.Status != *opts.Status {
			continue
		}
		if queryLower != "" {
			nameMatch := o.Name != nil && strings.Contains(strings.ToLower(*o.Name), queryLower)
			slugMatch := o.Slug != nil && strings.Contains(strings.ToLower(*o.Slug), queryLower)
			if !nameMatch && !slugMatch {
				continue
			}
		}
		matched = append(matched, o)
	}
	// Sort by id ASC (UUIDv7 ≈ creation-time).
	for i := 1; i < len(matched); i++ {
		for j := i; j > 0; j-- {
			if matched[j].ID < matched[j-1].ID {
				matched[j-1], matched[j] = matched[j], matched[j-1]
			} else {
				break
			}
		}
	}
	startIdx := 0
	if opts.Cursor != nil && *opts.Cursor != "" {
		for i, o := range matched {
			if o.ID == *opts.Cursor {
				startIdx = i + 1
				break
			}
		}
	}
	end := startIdx + limit
	if end > len(matched) {
		end = len(matched)
	}
	data := matched[startIdx:end]
	var next *string
	if end < len(matched) && len(data) > 0 {
		c := data[len(data)-1].ID
		next = &c
	}
	return Page[Organization]{Data: data, NextCursor: next}, nil
}

// ─── Memberships ───

func (s *InMemoryTenancyStore) AddMember(orgID, usrID string, role Role, invitedBy *string) (Membership, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.orgs[orgID]; !ok {
		return Membership{}, fmt.Errorf("org %s: %w", orgID, ErrNotFound)
	}
	if _, taken := s.activeMemByOrgUsr[orgUsrKey(orgID, usrID)]; taken {
		return Membership{}, fmt.Errorf("usr %s in org %s: %w", usrID, orgID, ErrDuplicateMembership)
	}
	memID, err := flametrenchids.Generate("mem")
	if err != nil {
		return Membership{}, err
	}
	now := s.now()
	mem := Membership{
		ID: memID, UsrID: usrID, OrgID: orgID, Role: role,
		Status: StatusActive, InvitedBy: invitedBy,
		CreatedAt: now, UpdatedAt: now,
	}
	s.memberships[memID] = mem
	s.activeMemByOrgUsr[orgUsrKey(orgID, usrID)] = memID
	t := Tuple{SubjectType: "usr", SubjectID: usrID, Relation: string(role), ObjectType: "org", ObjectID: orgID}
	s.tuples[tupleKey(t)] = t
	return mem, nil
}

func (s *InMemoryTenancyStore) GetMembership(memID string) (Membership, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.memberships[memID]
	if !ok {
		return Membership{}, fmt.Errorf("mem %s: %w", memID, ErrNotFound)
	}
	return m, nil
}

func (s *InMemoryTenancyStore) ListMembers(orgID string, opts ListMembersOptions) (Page[Membership], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.orgs[orgID]; !ok {
		return Page[Membership]{}, fmt.Errorf("org %s: %w", orgID, ErrNotFound)
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	matched := make([]Membership, 0)
	for _, m := range s.memberships {
		if m.OrgID != orgID {
			continue
		}
		if opts.Status != nil && m.Status != *opts.Status {
			continue
		}
		matched = append(matched, m)
	}
	// Sort by created_at ASC then id.
	for i := 1; i < len(matched); i++ {
		for j := i; j > 0; j-- {
			if matched[j].CreatedAt.Before(matched[j-1].CreatedAt) ||
				(matched[j].CreatedAt.Equal(matched[j-1].CreatedAt) && matched[j].ID < matched[j-1].ID) {
				matched[j-1], matched[j] = matched[j], matched[j-1]
			} else {
				break
			}
		}
	}
	startIdx := 0
	if opts.Cursor != nil && *opts.Cursor != "" {
		for i, m := range matched {
			if m.ID == *opts.Cursor {
				startIdx = i + 1
				break
			}
		}
	}
	end := startIdx + limit
	if end > len(matched) {
		end = len(matched)
	}
	data := matched[startIdx:end]
	var next *string
	if end < len(matched) && len(data) > 0 {
		c := data[len(data)-1].ID
		next = &c
	}
	return Page[Membership]{Data: data, NextCursor: next}, nil
}

// ChangeRole implements revoke-and-re-add: the old membership is
// marked revoked, a new active membership replaces it, and the tuple
// swap reflects the role change atomically.
func (s *InMemoryTenancyStore) ChangeRole(memID string, newRole Role) (Membership, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.memberships[memID]
	if !ok {
		return Membership{}, fmt.Errorf("mem %s: %w", memID, ErrNotFound)
	}
	if old.Status != StatusActive {
		return Membership{}, &PreconditionError{Msg: "membership not active", Reason: "mem_not_active"}
	}
	if old.Role == newRole {
		return old, nil
	}
	// Owner protection: if old was sole owner and newRole is not owner, reject.
	if old.Role == RoleOwner && newRole != RoleOwner {
		if s.countActiveOwnersLocked(old.OrgID) == 1 {
			return Membership{}, ErrSoleOwner
		}
	}
	now := s.now()
	old.Status = StatusRevoked
	old.UpdatedAt = now
	s.memberships[memID] = old
	delete(s.activeMemByOrgUsr, orgUsrKey(old.OrgID, old.UsrID))
	delete(s.tuples, tupleKey(Tuple{SubjectType: "usr", SubjectID: old.UsrID, Relation: string(old.Role), ObjectType: "org", ObjectID: old.OrgID}))

	newID, err := flametrenchids.Generate("mem")
	if err != nil {
		return Membership{}, err
	}
	nm := Membership{
		ID: newID, UsrID: old.UsrID, OrgID: old.OrgID, Role: newRole,
		Status: StatusActive, Replaces: &memID,
		InvitedBy: old.InvitedBy,
		CreatedAt: now, UpdatedAt: now,
	}
	s.memberships[newID] = nm
	s.activeMemByOrgUsr[orgUsrKey(nm.OrgID, nm.UsrID)] = newID
	t := Tuple{SubjectType: "usr", SubjectID: nm.UsrID, Relation: string(newRole), ObjectType: "org", ObjectID: nm.OrgID}
	s.tuples[tupleKey(t)] = t
	return nm, nil
}

func (s *InMemoryTenancyStore) countActiveOwnersLocked(orgID string) int {
	n := 0
	for _, m := range s.memberships {
		if m.OrgID == orgID && m.Status == StatusActive && m.Role == RoleOwner {
			n++
		}
	}
	return n
}

func (s *InMemoryTenancyStore) SuspendMembership(memID string) (Membership, error) {
	return s.transitionMembership(memID, StatusSuspended, nil)
}
func (s *InMemoryTenancyStore) ReinstateMembership(memID string) (Membership, error) {
	return s.transitionMembership(memID, StatusActive, nil)
}

func (s *InMemoryTenancyStore) transitionMembership(memID string, to Status, removedBy *string) (Membership, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.memberships[memID]
	if !ok {
		return Membership{}, fmt.Errorf("mem %s: %w", memID, ErrNotFound)
	}
	if m.Status == StatusRevoked {
		return Membership{}, fmt.Errorf("mem %s: %w", memID, ErrAlreadyTerminal)
	}
	// Owner protection on transition off active for sole owner.
	if to != StatusActive && m.Status == StatusActive && m.Role == RoleOwner {
		if s.countActiveOwnersLocked(m.OrgID) == 1 {
			return Membership{}, ErrSoleOwner
		}
	}
	if to == StatusActive {
		if m.Status != StatusSuspended {
			return Membership{}, &PreconditionError{Msg: "mem not suspended", Reason: "invalid_transition"}
		}
		// Restoring active conflicts with duplicate-membership rule.
		if _, taken := s.activeMemByOrgUsr[orgUsrKey(m.OrgID, m.UsrID)]; taken {
			return Membership{}, fmt.Errorf("usr in org: %w", ErrDuplicateMembership)
		}
		s.activeMemByOrgUsr[orgUsrKey(m.OrgID, m.UsrID)] = memID
		// Re-insert tuple.
		t := Tuple{SubjectType: "usr", SubjectID: m.UsrID, Relation: string(m.Role), ObjectType: "org", ObjectID: m.OrgID}
		s.tuples[tupleKey(t)] = t
	} else {
		// Suspended / Revoked: drop tuple + active index.
		delete(s.activeMemByOrgUsr, orgUsrKey(m.OrgID, m.UsrID))
		delete(s.tuples, tupleKey(Tuple{SubjectType: "usr", SubjectID: m.UsrID, Relation: string(m.Role), ObjectType: "org", ObjectID: m.OrgID}))
	}
	m.Status = to
	if removedBy != nil {
		m.RemovedBy = removedBy
	}
	m.UpdatedAt = s.now()
	s.memberships[memID] = m
	return m, nil
}

func (s *InMemoryTenancyStore) SelfLeave(memID string, transferTo *string) (Membership, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.memberships[memID]
	if !ok {
		return Membership{}, fmt.Errorf("mem %s: %w", memID, ErrNotFound)
	}
	if m.Status != StatusActive {
		return Membership{}, &PreconditionError{Msg: "mem not active", Reason: "mem_not_active"}
	}
	if m.Role == RoleOwner && s.countActiveOwnersLocked(m.OrgID) == 1 {
		if transferTo == nil {
			return Membership{}, ErrSoleOwner
		}
		// Promote transferTo to owner first.
		ttMemID, ok := s.activeMemByOrgUsr[orgUsrKey(m.OrgID, *transferTo)]
		if !ok {
			return Membership{}, fmt.Errorf("transfer target not a member: %w", ErrNotFound)
		}
		tt := s.memberships[ttMemID]
		if tt.Role == RoleOwner {
			return Membership{}, &PreconditionError{Msg: "transfer target is already owner", Reason: "already_owner"}
		}
		s.changeRoleAtomicLocked(ttMemID, RoleOwner)
	}
	delete(s.activeMemByOrgUsr, orgUsrKey(m.OrgID, m.UsrID))
	delete(s.tuples, tupleKey(Tuple{SubjectType: "usr", SubjectID: m.UsrID, Relation: string(m.Role), ObjectType: "org", ObjectID: m.OrgID}))
	m.Status = StatusRevoked
	uid := m.UsrID
	m.RemovedBy = &uid
	m.UpdatedAt = s.now()
	s.memberships[memID] = m
	return m, nil
}

// changeRoleAtomicLocked is the shared internal of ChangeRole / SelfLeave
// transfer. Caller MUST hold s.mu.
func (s *InMemoryTenancyStore) changeRoleAtomicLocked(memID string, newRole Role) {
	old := s.memberships[memID]
	now := s.now()
	old.Status = StatusRevoked
	old.UpdatedAt = now
	s.memberships[memID] = old
	delete(s.activeMemByOrgUsr, orgUsrKey(old.OrgID, old.UsrID))
	delete(s.tuples, tupleKey(Tuple{SubjectType: "usr", SubjectID: old.UsrID, Relation: string(old.Role), ObjectType: "org", ObjectID: old.OrgID}))
	newID, _ := flametrenchids.Generate("mem")
	nm := Membership{
		ID: newID, UsrID: old.UsrID, OrgID: old.OrgID, Role: newRole,
		Status: StatusActive, Replaces: &memID, InvitedBy: old.InvitedBy,
		CreatedAt: now, UpdatedAt: now,
	}
	s.memberships[newID] = nm
	s.activeMemByOrgUsr[orgUsrKey(nm.OrgID, nm.UsrID)] = newID
	t := Tuple{SubjectType: "usr", SubjectID: nm.UsrID, Relation: string(newRole), ObjectType: "org", ObjectID: nm.OrgID}
	s.tuples[tupleKey(t)] = t
}

func (s *InMemoryTenancyStore) AdminRemove(memID, adminUsrID string) (Membership, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	target, ok := s.memberships[memID]
	if !ok {
		return Membership{}, fmt.Errorf("mem %s: %w", memID, ErrNotFound)
	}
	if target.Status != StatusActive {
		return Membership{}, &PreconditionError{Msg: "target mem not active", Reason: "mem_not_active"}
	}
	adminMemID, ok := s.activeMemByOrgUsr[orgUsrKey(target.OrgID, adminUsrID)]
	if !ok {
		return Membership{}, fmt.Errorf("admin not a member: %w", ErrForbidden)
	}
	admin := s.memberships[adminMemID]
	if admin.Role.AdminRank() < 3 {
		return Membership{}, ErrForbidden
	}
	if admin.Role.AdminRank() < target.Role.AdminRank() {
		return Membership{}, ErrRoleHierarchy
	}
	if target.Role == RoleOwner && s.countActiveOwnersLocked(target.OrgID) == 1 {
		return Membership{}, ErrSoleOwner
	}
	delete(s.activeMemByOrgUsr, orgUsrKey(target.OrgID, target.UsrID))
	delete(s.tuples, tupleKey(Tuple{SubjectType: "usr", SubjectID: target.UsrID, Relation: string(target.Role), ObjectType: "org", ObjectID: target.OrgID}))
	target.Status = StatusRevoked
	target.RemovedBy = &adminUsrID
	target.UpdatedAt = s.now()
	s.memberships[memID] = target
	return target, nil
}

func (s *InMemoryTenancyStore) TransferOwnership(orgID, fromMemID, toMemID string) (TransferOwnershipResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if fromMemID == toMemID {
		return TransferOwnershipResult{}, &PreconditionError{Msg: "cannot transfer ownership to self", Reason: "self_transfer"}
	}
	from, ok := s.memberships[fromMemID]
	if !ok || from.OrgID != orgID || from.Role != RoleOwner || from.Status != StatusActive {
		return TransferOwnershipResult{}, &PreconditionError{Msg: "from is not an active owner", Reason: "not_active_owner"}
	}
	to, ok := s.memberships[toMemID]
	if !ok || to.OrgID != orgID || to.Status != StatusActive {
		return TransferOwnershipResult{}, &PreconditionError{Msg: "to is not an active member", Reason: "not_active_member"}
	}
	// Promote `to` to owner (revoke-and-re-add).
	s.changeRoleAtomicLocked(toMemID, RoleOwner)
	// Demote `from` to member (spec: "atomically promote target to owner and demote donor to member").
	s.changeRoleAtomicLocked(fromMemID, RoleMember)
	// Look up the latest membership records for both (they got new IDs).
	newFromID := s.activeMemByOrgUsr[orgUsrKey(orgID, from.UsrID)]
	newToID := s.activeMemByOrgUsr[orgUsrKey(orgID, to.UsrID)]
	return TransferOwnershipResult{
		FromMembership: s.memberships[newFromID],
		ToMembership:   s.memberships[newToID],
	}, nil
}

// ─── Invitations ───

func (s *InMemoryTenancyStore) CreateInvitation(orgID, identifier string, role Role, invitedBy string, expiresAt time.Time, preTuples []PreTuple) (Invitation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.orgs[orgID]; !ok {
		return Invitation{}, fmt.Errorf("org %s: %w", orgID, ErrNotFound)
	}
	invID, err := flametrenchids.Generate("inv")
	if err != nil {
		return Invitation{}, err
	}
	now := s.now()
	inv := Invitation{
		ID: invID, OrgID: orgID, Identifier: identifier, Role: role,
		Status: InvitationStatusPending, InvitedBy: invitedBy,
		PreTuples: append([]PreTuple(nil), preTuples...),
		CreatedAt: now, ExpiresAt: expiresAt,
	}
	s.invitations[invID] = inv
	return inv, nil
}

func (s *InMemoryTenancyStore) GetInvitation(invID string) (Invitation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inv, ok := s.invitations[invID]
	if !ok {
		return Invitation{}, fmt.Errorf("inv %s: %w", invID, ErrNotFound)
	}
	// Lazy expiry transition.
	if inv.Status == InvitationStatusPending && !s.now().Before(inv.ExpiresAt) {
		now := s.now()
		inv.Status = InvitationStatusExpired
		inv.TerminalAt = &now
		s.invitations[invID] = inv
	}
	return inv, nil
}

func (s *InMemoryTenancyStore) ListInvitations(orgID string, opts ListInvitationsOptions) (Page[Invitation], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.orgs[orgID]; !ok {
		return Page[Invitation]{}, fmt.Errorf("org %s: %w", orgID, ErrNotFound)
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	matched := make([]Invitation, 0)
	for _, inv := range s.invitations {
		if inv.OrgID != orgID {
			continue
		}
		if opts.Status != nil && inv.Status != *opts.Status {
			continue
		}
		matched = append(matched, inv)
	}
	for i := 1; i < len(matched); i++ {
		for j := i; j > 0; j-- {
			if matched[j].CreatedAt.Before(matched[j-1].CreatedAt) ||
				(matched[j].CreatedAt.Equal(matched[j-1].CreatedAt) && matched[j].ID < matched[j-1].ID) {
				matched[j-1], matched[j] = matched[j], matched[j-1]
			} else {
				break
			}
		}
	}
	startIdx := 0
	if opts.Cursor != nil && *opts.Cursor != "" {
		for i, inv := range matched {
			if inv.ID == *opts.Cursor {
				startIdx = i + 1
				break
			}
		}
	}
	end := startIdx + limit
	if end > len(matched) {
		end = len(matched)
	}
	data := matched[startIdx:end]
	var next *string
	if end < len(matched) && len(data) > 0 {
		c := data[len(data)-1].ID
		next = &c
	}
	return Page[Invitation]{Data: data, NextCursor: next}, nil
}

// AcceptInvitation implements the ADR 0009 binding semantics. If
// opts.AsUsrID is non-nil, opts.AcceptingIdentifier MUST be non-nil
// and the SDK enforces byte-equality with invitation.identifier.
func (s *InMemoryTenancyStore) AcceptInvitation(invID string, opts AcceptInvitationOptions) (AcceptInvitationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inv, ok := s.invitations[invID]
	if !ok {
		return AcceptInvitationResult{}, fmt.Errorf("inv %s: %w", invID, ErrNotFound)
	}
	if inv.Status != InvitationStatusPending {
		return AcceptInvitationResult{}, ErrInvitationNotPending
	}
	if !s.now().Before(inv.ExpiresAt) {
		// Eager expiry transition.
		now := s.now()
		inv.Status = InvitationStatusExpired
		inv.TerminalAt = &now
		s.invitations[invID] = inv
		return AcceptInvitationResult{}, ErrInvitationExpired
	}

	// ADR 0009 binding.
	if opts.AsUsrID != nil {
		if opts.AcceptingIdentifier == nil {
			return AcceptInvitationResult{}, ErrIdentifierBindingRequired
		}
		if *opts.AcceptingIdentifier != inv.Identifier {
			return AcceptInvitationResult{}, ErrIdentifierMismatch
		}
	}

	// Mint-new-user path is the responsibility of identity layer in the
	// adopter's app; here we accept AsUsrID as the canonical accepting
	// user. The SDK doesn't create the usr_ row; the adopter does.
	var acceptingUsr string
	if opts.AsUsrID != nil {
		acceptingUsr = *opts.AsUsrID
	} else {
		// "mint new user" — generate a usr_ id placeholder. Adopter is
		// expected to ensure the usr row exists.
		newU, err := flametrenchids.Generate("usr")
		if err != nil {
			return AcceptInvitationResult{}, err
		}
		acceptingUsr = newU
	}

	// Duplicate-membership check.
	if _, taken := s.activeMemByOrgUsr[orgUsrKey(inv.OrgID, acceptingUsr)]; taken {
		return AcceptInvitationResult{}, fmt.Errorf("usr in org: %w", ErrDuplicateMembership)
	}

	// Insert membership + role tuple.
	memID, err := flametrenchids.Generate("mem")
	if err != nil {
		return AcceptInvitationResult{}, err
	}
	now := s.now()
	invBy := inv.InvitedBy
	mem := Membership{
		ID: memID, UsrID: acceptingUsr, OrgID: inv.OrgID, Role: inv.Role,
		Status: StatusActive, InvitedBy: &invBy,
		CreatedAt: now, UpdatedAt: now,
	}
	s.memberships[memID] = mem
	s.activeMemByOrgUsr[orgUsrKey(inv.OrgID, acceptingUsr)] = memID
	roleTuple := Tuple{SubjectType: "usr", SubjectID: acceptingUsr, Relation: string(inv.Role), ObjectType: "org", ObjectID: inv.OrgID}
	s.tuples[tupleKey(roleTuple)] = roleTuple

	// Materialize pre_tuples.
	materialized := []Tuple{roleTuple}
	for _, pt := range inv.PreTuples {
		t := Tuple{SubjectType: "usr", SubjectID: acceptingUsr, Relation: pt.Relation, ObjectType: pt.ObjectType, ObjectID: pt.ObjectID}
		s.tuples[tupleKey(t)] = t
		materialized = append(materialized, t)
	}

	// Transition invitation.
	inv.Status = InvitationStatusAccepted
	inv.TerminalAt = &now
	inv.InvitedUserID = &acceptingUsr
	s.invitations[invID] = inv

	return AcceptInvitationResult{Invitation: inv, Membership: mem, MaterializedTuples: materialized}, nil
}

func (s *InMemoryTenancyStore) DeclineInvitation(invID string, asUsrID *string) (Invitation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inv, ok := s.invitations[invID]
	if !ok {
		return Invitation{}, fmt.Errorf("inv %s: %w", invID, ErrNotFound)
	}
	if inv.Status != InvitationStatusPending {
		return Invitation{}, ErrInvitationNotPending
	}
	now := s.now()
	inv.Status = InvitationStatusDeclined
	inv.TerminalAt = &now
	if asUsrID != nil {
		inv.TerminalBy = asUsrID
		inv.InvitedUserID = asUsrID
	}
	s.invitations[invID] = inv
	return inv, nil
}

func (s *InMemoryTenancyStore) RevokeInvitation(invID, adminUsrID string) (Invitation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inv, ok := s.invitations[invID]
	if !ok {
		return Invitation{}, fmt.Errorf("inv %s: %w", invID, ErrNotFound)
	}
	if inv.Status != InvitationStatusPending {
		return Invitation{}, ErrInvitationNotPending
	}
	now := s.now()
	inv.Status = InvitationStatusRevoked
	inv.TerminalAt = &now
	inv.TerminalBy = &adminUsrID
	s.invitations[invID] = inv
	return inv, nil
}

// ─── Tuple accessors ───

func (s *InMemoryTenancyStore) ListTuplesForSubject(subjectType, subjectID string) ([]Tuple, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Tuple, 0)
	for _, t := range s.tuples {
		if t.SubjectType == subjectType && t.SubjectID == subjectID {
			out = append(out, t)
		}
	}
	return out, nil
}

func (s *InMemoryTenancyStore) ListTuplesForObject(objectType, objectID string, relation *string) ([]Tuple, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Tuple, 0)
	for _, t := range s.tuples {
		if t.ObjectType != objectType || t.ObjectID != objectID {
			continue
		}
		if relation != nil && t.Relation != *relation {
			continue
		}
		out = append(out, t)
	}
	return out, nil
}

// Helper to suppress unused import when strings isn't yet referenced.
var _ = strings.Contains
