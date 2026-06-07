// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

// PostgresTenancyStore — Postgres-backed TenancyStore using pgx/v5.
// ADR 0013 caller-owned-connection pattern.

package tenancy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type PgxExecutor interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Begin(ctx context.Context) (pgx.Tx, error)
}

type PostgresTenancyStore struct {
	exec  PgxExecutor
	clock func() time.Time
	ctx   context.Context
}

var _ TenancyStore = (*PostgresTenancyStore)(nil)

func NewPostgresTenancyStore(ctx context.Context, exec PgxExecutor) *PostgresTenancyStore {
	return &PostgresTenancyStore{exec: exec, clock: func() time.Time { return time.Now().UTC() }, ctx: ctx}
}

func (s *PostgresTenancyStore) WithClock(c func() time.Time) *PostgresTenancyStore { s.clock = c; return s }
func (s *PostgresTenancyStore) WithContext(ctx context.Context) *PostgresTenancyStore {
	c := *s
	c.ctx = ctx
	return &c
}

// ─── wire/uuid helpers ───

func wireToUUID(id string) (uuid.UUID, error) {
	sep := strings.IndexByte(id, '_')
	if sep == -1 {
		return uuid.UUID{}, fmt.Errorf("malformed wire id: %q", id)
	}
	h := id[sep+1:]
	if len(h) != 32 {
		return uuid.UUID{}, fmt.Errorf("malformed wire id payload: %q", id)
	}
	return uuid.Parse(fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32]))
}

func uuidToWire(prefix string, u uuid.UUID) string {
	return prefix + "_" + strings.ReplaceAll(u.String(), "-", "")
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == "23505"
}

func (s *PostgresTenancyStore) inTx(fn func(tx pgx.Tx) error) error {
	tx, err := s.exec.Begin(s.ctx)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback(s.ctx)
		return err
	}
	return tx.Commit(s.ctx)
}

// ─── Orgs ───

func scanOrg(row pgx.Row) (Organization, error) {
	var (
		id           uuid.UUID
		status       Status
		name, slug   *string
		created, up  time.Time
	)
	if err := row.Scan(&id, &status, &name, &slug, &created, &up); err != nil {
		return Organization{}, err
	}
	return Organization{
		ID: uuidToWire("org", id), Status: status,
		CreatedAt: created, UpdatedAt: up,
		Name: name, Slug: slug,
	}, nil
}

const orgCols = `id, status, name, slug, created_at, updated_at`

func (s *PostgresTenancyStore) CreateOrg(creator string, opts CreateOrgOptions) (CreateOrgResult, error) {
	if opts.Slug != nil {
		if err := validateSlug(*opts.Slug); err != nil {
			return CreateOrgResult{}, err
		}
	}
	creatorU, err := wireToUUID(creator)
	if err != nil {
		return CreateOrgResult{}, err
	}
	var res CreateOrgResult
	err = s.inTx(func(tx pgx.Tx) error {
		newOrgID := uuid.Must(uuid.NewV7())
		row := tx.QueryRow(s.ctx, `
			INSERT INTO org (id, name, slug) VALUES ($1, $2, $3)
			RETURNING `+orgCols, newOrgID, opts.Name, opts.Slug)
		org, err := scanOrg(row)
		if err != nil {
			if isUniqueViolation(err) {
				slug := ""
				if opts.Slug != nil {
					slug = *opts.Slug
				}
				return fmt.Errorf("slug %q: %w", slug, ErrOrgSlugConflict)
			}
			return err
		}
		// Owner mem.
		newMemID := uuid.Must(uuid.NewV7())
		var memID uuid.UUID
		var memCreated, memUp time.Time
		err = tx.QueryRow(s.ctx, `
			INSERT INTO mem (id, usr_id, org_id, role, status)
			VALUES ($1, $2, $3, 'owner', 'active')
			RETURNING id, created_at, updated_at`,
			newMemID, creatorU, newOrgID,
		).Scan(&memID, &memCreated, &memUp)
		if err != nil {
			return err
		}
		// Owner tuple.
		if _, err := tx.Exec(s.ctx, `
			INSERT INTO tup (id, subject_type, subject_id, relation, object_type, object_id, created_by)
			VALUES ($1, 'usr', $2, 'owner', 'org', $3, $2)`,
			uuid.Must(uuid.NewV7()), creatorU, newOrgID,
		); err != nil {
			return err
		}
		res.Org = org
		res.OwnerMembership = Membership{
			ID: uuidToWire("mem", memID), UsrID: creator, OrgID: org.ID,
			Role: RoleOwner, Status: StatusActive,
			CreatedAt: memCreated, UpdatedAt: memUp,
		}
		return nil
	})
	return res, err
}

func (s *PostgresTenancyStore) GetOrg(orgID string) (Organization, error) {
	u, err := wireToUUID(orgID)
	if err != nil {
		return Organization{}, err
	}
	row := s.exec.QueryRow(s.ctx, `SELECT `+orgCols+` FROM org WHERE id = $1`, u)
	org, err := scanOrg(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Organization{}, fmt.Errorf("org %s: %w", orgID, ErrNotFound)
	}
	return org, err
}

func (s *PostgresTenancyStore) UpdateOrg(orgID string, in UpdateOrgInput) (Organization, error) {
	u, err := wireToUUID(orgID)
	if err != nil {
		return Organization{}, err
	}
	var out Organization
	err = s.inTx(func(tx pgx.Tx) error {
		row := tx.QueryRow(s.ctx, `SELECT `+orgCols+` FROM org WHERE id = $1 FOR UPDATE`, u)
		org, err := scanOrg(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("org %s: %w", orgID, ErrNotFound)
		}
		if err != nil {
			return err
		}
		if org.Status == StatusRevoked {
			return fmt.Errorf("org %s: %w", orgID, ErrAlreadyTerminal)
		}
		nextName := org.Name
		if in.ClearName {
			nextName = nil
		} else if in.Name != nil {
			nextName = in.Name
		}
		nextSlug := org.Slug
		if in.ClearSlug {
			nextSlug = nil
		} else if in.Slug != nil {
			if err := validateSlug(*in.Slug); err != nil {
				return err
			}
			nextSlug = in.Slug
		}
		row = tx.QueryRow(s.ctx, `
			UPDATE org SET name = $2, slug = $3, updated_at = now() WHERE id = $1
			RETURNING `+orgCols, u, nextName, nextSlug,
		)
		out, err = scanOrg(row)
		if err != nil {
			if isUniqueViolation(err) {
				slug := ""
				if nextSlug != nil {
					slug = *nextSlug
				}
				return fmt.Errorf("slug %q: %w", slug, ErrOrgSlugConflict)
			}
			return err
		}
		return nil
	})
	return out, err
}

func (s *PostgresTenancyStore) SuspendOrg(orgID string) (Organization, error) {
	return s.transOrg(orgID, StatusSuspended)
}
func (s *PostgresTenancyStore) ReinstateOrg(orgID string) (Organization, error) {
	return s.transOrg(orgID, StatusActive)
}
func (s *PostgresTenancyStore) RevokeOrg(orgID string) (Organization, error) {
	return s.transOrg(orgID, StatusRevoked)
}

func (s *PostgresTenancyStore) transOrg(orgID string, to Status) (Organization, error) {
	u, err := wireToUUID(orgID)
	if err != nil {
		return Organization{}, err
	}
	var out Organization
	err = s.inTx(func(tx pgx.Tx) error {
		row := tx.QueryRow(s.ctx, `SELECT `+orgCols+` FROM org WHERE id = $1 FOR UPDATE`, u)
		org, err := scanOrg(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("org %s: %w", orgID, ErrNotFound)
		}
		if err != nil {
			return err
		}
		if org.Status == StatusRevoked {
			return fmt.Errorf("org %s: %w", orgID, ErrAlreadyTerminal)
		}
		if to == StatusActive && org.Status != StatusSuspended {
			return &PreconditionError{Msg: "org not suspended", Reason: "invalid_transition"}
		}
		row = tx.QueryRow(s.ctx, `UPDATE org SET status = $2, updated_at = now() WHERE id = $1 RETURNING `+orgCols, u, to)
		out, err = scanOrg(row)
		if err != nil {
			return err
		}
		if to == StatusRevoked {
			// Cascade: revoke active memberships + drop role tuples.
			if _, err := tx.Exec(s.ctx,
				`UPDATE mem SET status = 'revoked', updated_at = now() WHERE org_id = $1 AND status = 'active'`, u); err != nil {
				return err
			}
			if _, err := tx.Exec(s.ctx,
				`DELETE FROM tup WHERE object_type = 'org' AND object_id = $1 AND relation IN ('owner','admin','member','guest','viewer','editor')`, u); err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}

func (s *PostgresTenancyStore) ListOrgs(opts ListOrgsOptions) (Page[Organization], error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	args := []any{}
	q := `SELECT ` + orgCols + ` FROM org WHERE true`
	idx := 1
	if opts.Status != nil {
		q += fmt.Sprintf(` AND status = $%d`, idx)
		args = append(args, string(*opts.Status))
		idx++
	}
	if opts.Query != nil && *opts.Query != "" {
		q += fmt.Sprintf(` AND (name ILIKE $%d OR slug ILIKE $%d)`, idx, idx)
		args = append(args, "%"+*opts.Query+"%")
		idx++
	}
	if opts.Cursor != nil && *opts.Cursor != "" {
		curU, err := wireToUUID(*opts.Cursor)
		if err != nil {
			return Page[Organization]{}, err
		}
		q += fmt.Sprintf(` AND id > $%d`, idx)
		args = append(args, curU)
		idx++
	}
	q += fmt.Sprintf(` ORDER BY id ASC LIMIT $%d`, idx)
	args = append(args, limit+1)
	rows, err := s.exec.Query(s.ctx, q, args...)
	if err != nil {
		return Page[Organization]{}, err
	}
	defer rows.Close()
	out := make([]Organization, 0, limit)
	for rows.Next() {
		o, err := scanOrg(rows)
		if err != nil {
			return Page[Organization]{}, err
		}
		out = append(out, o)
	}
	var next *string
	if len(out) > limit {
		c := out[limit-1].ID
		next = &c
		out = out[:limit]
	}
	return Page[Organization]{Data: out, NextCursor: next}, nil
}

// ─── Memberships ───

const memCols = `id, usr_id, org_id, role, status, replaces, invited_by, removed_by, created_at, updated_at`

func scanMembership(row pgx.Row) (Membership, error) {
	var (
		id, usrID, orgID    uuid.UUID
		role                Role
		status              Status
		replaces            *uuid.UUID
		invitedBy           *uuid.UUID
		removedBy           *uuid.UUID
		createdAt, updatedAt time.Time
	)
	if err := row.Scan(&id, &usrID, &orgID, &role, &status, &replaces, &invitedBy, &removedBy, &createdAt, &updatedAt); err != nil {
		return Membership{}, err
	}
	m := Membership{
		ID: uuidToWire("mem", id), UsrID: uuidToWire("usr", usrID), OrgID: uuidToWire("org", orgID),
		Role: role, Status: status, CreatedAt: createdAt, UpdatedAt: updatedAt,
	}
	if replaces != nil {
		s := uuidToWire("mem", *replaces)
		m.Replaces = &s
	}
	if invitedBy != nil {
		s := uuidToWire("usr", *invitedBy)
		m.InvitedBy = &s
	}
	if removedBy != nil {
		s := uuidToWire("usr", *removedBy)
		m.RemovedBy = &s
	}
	return m, nil
}

func (s *PostgresTenancyStore) AddMember(orgID, usrID string, role Role, invitedBy *string) (Membership, error) {
	orgU, err := wireToUUID(orgID)
	if err != nil {
		return Membership{}, err
	}
	usrU, err := wireToUUID(usrID)
	if err != nil {
		return Membership{}, err
	}
	var invU *uuid.UUID
	if invitedBy != nil {
		u, err := wireToUUID(*invitedBy)
		if err != nil {
			return Membership{}, err
		}
		invU = &u
	}
	var out Membership
	err = s.inTx(func(tx pgx.Tx) error {
		newID := uuid.Must(uuid.NewV7())
		row := tx.QueryRow(s.ctx, `
			INSERT INTO mem (id, usr_id, org_id, role, status, invited_by)
			VALUES ($1, $2, $3, $4, 'active', $5)
			RETURNING `+memCols, newID, usrU, orgU, role, invU,
		)
		m, err := scanMembership(row)
		if err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("usr %s in org %s: %w", usrID, orgID, ErrDuplicateMembership)
			}
			return err
		}
		if _, err := tx.Exec(s.ctx, `
			INSERT INTO tup (id, subject_type, subject_id, relation, object_type, object_id, created_by)
			VALUES ($1, 'usr', $2, $3, 'org', $4, $5)`,
			uuid.Must(uuid.NewV7()), usrU, role, orgU, usrU,
		); err != nil {
			return err
		}
		out = m
		return nil
	})
	return out, err
}

func (s *PostgresTenancyStore) GetMembership(memID string) (Membership, error) {
	u, err := wireToUUID(memID)
	if err != nil {
		return Membership{}, err
	}
	row := s.exec.QueryRow(s.ctx, `SELECT `+memCols+` FROM mem WHERE id = $1`, u)
	m, err := scanMembership(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Membership{}, fmt.Errorf("mem %s: %w", memID, ErrNotFound)
	}
	return m, err
}

func (s *PostgresTenancyStore) ListMembers(orgID string, opts ListMembersOptions) (Page[Membership], error) {
	u, err := wireToUUID(orgID)
	if err != nil {
		return Page[Membership]{}, err
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	args := []any{u}
	q := `SELECT ` + memCols + ` FROM mem WHERE org_id = $1`
	idx := 2
	if opts.Status != nil {
		q += fmt.Sprintf(` AND status = $%d`, idx)
		args = append(args, *opts.Status)
		idx++
	}
	if opts.Cursor != nil && *opts.Cursor != "" {
		curU, err := wireToUUID(*opts.Cursor)
		if err != nil {
			return Page[Membership]{}, err
		}
		q += fmt.Sprintf(` AND (created_at, id) > (SELECT created_at, id FROM mem WHERE id = $%d)`, idx)
		args = append(args, curU)
		idx++
	}
	q += fmt.Sprintf(` ORDER BY created_at ASC, id ASC LIMIT $%d`, idx)
	args = append(args, limit+1)
	rows, err := s.exec.Query(s.ctx, q, args...)
	if err != nil {
		return Page[Membership]{}, err
	}
	defer rows.Close()
	out := make([]Membership, 0, limit)
	for rows.Next() {
		m, err := scanMembership(rows)
		if err != nil {
			return Page[Membership]{}, err
		}
		out = append(out, m)
	}
	var next *string
	if len(out) > limit {
		c := out[limit-1].ID
		next = &c
		out = out[:limit]
	}
	return Page[Membership]{Data: out, NextCursor: next}, nil
}

func (s *PostgresTenancyStore) countActiveOwners(tx pgx.Tx, orgU uuid.UUID) (int, error) {
	var n int
	err := tx.QueryRow(s.ctx,
		`SELECT count(*) FROM mem WHERE org_id = $1 AND role = 'owner' AND status = 'active'`, orgU,
	).Scan(&n)
	return n, err
}

func (s *PostgresTenancyStore) ChangeRole(memID string, newRole Role) (Membership, error) {
	u, err := wireToUUID(memID)
	if err != nil {
		return Membership{}, err
	}
	var out Membership
	err = s.inTx(func(tx pgx.Tx) error {
		row := tx.QueryRow(s.ctx, `SELECT `+memCols+` FROM mem WHERE id = $1 FOR UPDATE`, u)
		old, err := scanMembership(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("mem %s: %w", memID, ErrNotFound)
		}
		if err != nil {
			return err
		}
		if old.Status != StatusActive {
			return &PreconditionError{Msg: "membership not active", Reason: "mem_not_active"}
		}
		if old.Role == newRole {
			out = old
			return nil
		}
		orgU, _ := wireToUUID(old.OrgID)
		usrU, _ := wireToUUID(old.UsrID)
		if old.Role == RoleOwner && newRole != RoleOwner {
			n, err := s.countActiveOwners(tx, orgU)
			if err != nil {
				return err
			}
			if n == 1 {
				return ErrSoleOwner
			}
		}
		// Revoke old mem + tuple.
		if _, err := tx.Exec(s.ctx, `UPDATE mem SET status = 'revoked', updated_at = now() WHERE id = $1`, u); err != nil {
			return err
		}
		if _, err := tx.Exec(s.ctx,
			`DELETE FROM tup WHERE subject_type = 'usr' AND subject_id = $1 AND relation = $2 AND object_type = 'org' AND object_id = $3`,
			usrU, old.Role, orgU,
		); err != nil {
			return err
		}
		// Insert new mem + tuple.
		newID := uuid.Must(uuid.NewV7())
		row = tx.QueryRow(s.ctx, `
			INSERT INTO mem (id, usr_id, org_id, role, status, replaces, invited_by)
			VALUES ($1, $2, $3, $4, 'active', $5, $6)
			RETURNING `+memCols,
			newID, usrU, orgU, newRole, u,
			func() any {
				if old.InvitedBy != nil {
					ub, _ := wireToUUID(*old.InvitedBy)
					return ub
				}
				return nil
			}(),
		)
		nm, err := scanMembership(row)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(s.ctx, `
			INSERT INTO tup (id, subject_type, subject_id, relation, object_type, object_id, created_by)
			VALUES ($1, 'usr', $2, $3, 'org', $4, $2)`,
			uuid.Must(uuid.NewV7()), usrU, newRole, orgU,
		); err != nil {
			return err
		}
		out = nm
		return nil
	})
	return out, err
}

func (s *PostgresTenancyStore) SuspendMembership(memID string) (Membership, error) {
	return s.transMem(memID, StatusSuspended, nil)
}
func (s *PostgresTenancyStore) ReinstateMembership(memID string) (Membership, error) {
	return s.transMem(memID, StatusActive, nil)
}

func (s *PostgresTenancyStore) transMem(memID string, to Status, removedBy *uuid.UUID) (Membership, error) {
	u, err := wireToUUID(memID)
	if err != nil {
		return Membership{}, err
	}
	var out Membership
	err = s.inTx(func(tx pgx.Tx) error {
		row := tx.QueryRow(s.ctx, `SELECT `+memCols+` FROM mem WHERE id = $1 FOR UPDATE`, u)
		m, err := scanMembership(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("mem %s: %w", memID, ErrNotFound)
		}
		if err != nil {
			return err
		}
		if m.Status == StatusRevoked {
			return fmt.Errorf("mem %s: %w", memID, ErrAlreadyTerminal)
		}
		orgU, _ := wireToUUID(m.OrgID)
		usrU, _ := wireToUUID(m.UsrID)
		if to != StatusActive && m.Status == StatusActive && m.Role == RoleOwner {
			n, err := s.countActiveOwners(tx, orgU)
			if err != nil {
				return err
			}
			if n == 1 {
				return ErrSoleOwner
			}
		}
		if to == StatusActive {
			if m.Status != StatusSuspended {
				return &PreconditionError{Msg: "mem not suspended", Reason: "invalid_transition"}
			}
			// Re-insert tuple.
			if _, err := tx.Exec(s.ctx, `
				INSERT INTO tup (id, subject_type, subject_id, relation, object_type, object_id, created_by)
				VALUES ($1, 'usr', $2, $3, 'org', $4, $2)`,
				uuid.Must(uuid.NewV7()), usrU, m.Role, orgU,
			); err != nil {
				if isUniqueViolation(err) {
					return fmt.Errorf("usr in org: %w", ErrDuplicateMembership)
				}
				return err
			}
		} else {
			if _, err := tx.Exec(s.ctx,
				`DELETE FROM tup WHERE subject_type = 'usr' AND subject_id = $1 AND relation = $2 AND object_type = 'org' AND object_id = $3`,
				usrU, m.Role, orgU,
			); err != nil {
				return err
			}
		}
		row = tx.QueryRow(s.ctx, `
			UPDATE mem SET status = $2, removed_by = COALESCE($3, removed_by), updated_at = now()
			WHERE id = $1 RETURNING `+memCols, u, to, removedBy,
		)
		out, err = scanMembership(row)
		return err
	})
	return out, err
}

func (s *PostgresTenancyStore) SelfLeave(memID string, transferTo *string) (Membership, error) {
	u, err := wireToUUID(memID)
	if err != nil {
		return Membership{}, err
	}
	var out Membership
	err = s.inTx(func(tx pgx.Tx) error {
		row := tx.QueryRow(s.ctx, `SELECT `+memCols+` FROM mem WHERE id = $1 FOR UPDATE`, u)
		m, err := scanMembership(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("mem %s: %w", memID, ErrNotFound)
		}
		if err != nil {
			return err
		}
		if m.Status != StatusActive {
			return &PreconditionError{Msg: "mem not active", Reason: "mem_not_active"}
		}
		orgU, _ := wireToUUID(m.OrgID)
		usrU, _ := wireToUUID(m.UsrID)
		if m.Role == RoleOwner {
			n, err := s.countActiveOwners(tx, orgU)
			if err != nil {
				return err
			}
			if n == 1 {
				if transferTo == nil {
					return ErrSoleOwner
				}
				ttU, err := wireToUUID(*transferTo)
				if err != nil {
					return err
				}
				// Promote target to owner via revoke-and-re-add.
				var ttMemID uuid.UUID
				var ttRole Role
				err = tx.QueryRow(s.ctx,
					`SELECT id, role FROM mem WHERE org_id = $1 AND usr_id = $2 AND status = 'active'`,
					orgU, ttU,
				).Scan(&ttMemID, &ttRole)
				if errors.Is(err, pgx.ErrNoRows) {
					return fmt.Errorf("transfer target not a member: %w", ErrNotFound)
				}
				if err != nil {
					return err
				}
				if ttRole == RoleOwner {
					return &PreconditionError{Msg: "transfer target is already owner", Reason: "already_owner"}
				}
				if err := s.changeRoleLocked(tx, ttMemID, ttU, orgU, ttRole, RoleOwner); err != nil {
					return err
				}
			}
		}
		// Drop the leaving mem + tuple.
		if _, err := tx.Exec(s.ctx,
			`DELETE FROM tup WHERE subject_type = 'usr' AND subject_id = $1 AND relation = $2 AND object_type = 'org' AND object_id = $3`,
			usrU, m.Role, orgU,
		); err != nil {
			return err
		}
		row = tx.QueryRow(s.ctx, `
			UPDATE mem SET status = 'revoked', removed_by = $2, updated_at = now()
			WHERE id = $1 RETURNING `+memCols, u, usrU,
		)
		out, err = scanMembership(row)
		return err
	})
	return out, err
}

func (s *PostgresTenancyStore) changeRoleLocked(tx pgx.Tx, oldMem uuid.UUID, usrU, orgU uuid.UUID, oldRole, newRole Role) error {
	if _, err := tx.Exec(s.ctx, `UPDATE mem SET status = 'revoked', updated_at = now() WHERE id = $1`, oldMem); err != nil {
		return err
	}
	if _, err := tx.Exec(s.ctx,
		`DELETE FROM tup WHERE subject_type = 'usr' AND subject_id = $1 AND relation = $2 AND object_type = 'org' AND object_id = $3`,
		usrU, oldRole, orgU,
	); err != nil {
		return err
	}
	newID := uuid.Must(uuid.NewV7())
	if _, err := tx.Exec(s.ctx, `
		INSERT INTO mem (id, usr_id, org_id, role, status, replaces)
		VALUES ($1, $2, $3, $4, 'active', $5)`,
		newID, usrU, orgU, newRole, oldMem,
	); err != nil {
		return err
	}
	if _, err := tx.Exec(s.ctx, `
		INSERT INTO tup (id, subject_type, subject_id, relation, object_type, object_id, created_by)
		VALUES ($1, 'usr', $2, $3, 'org', $4, $2)`,
		uuid.Must(uuid.NewV7()), usrU, newRole, orgU,
	); err != nil {
		return err
	}
	return nil
}

func (s *PostgresTenancyStore) AdminRemove(memID, adminUsrID string) (Membership, error) {
	u, err := wireToUUID(memID)
	if err != nil {
		return Membership{}, err
	}
	adminU, err := wireToUUID(adminUsrID)
	if err != nil {
		return Membership{}, err
	}
	var out Membership
	err = s.inTx(func(tx pgx.Tx) error {
		row := tx.QueryRow(s.ctx, `SELECT `+memCols+` FROM mem WHERE id = $1 FOR UPDATE`, u)
		target, err := scanMembership(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("mem %s: %w", memID, ErrNotFound)
		}
		if err != nil {
			return err
		}
		if target.Status != StatusActive {
			return &PreconditionError{Msg: "target mem not active", Reason: "mem_not_active"}
		}
		orgU, _ := wireToUUID(target.OrgID)
		usrU, _ := wireToUUID(target.UsrID)
		var adminRole Role
		err = tx.QueryRow(s.ctx,
			`SELECT role FROM mem WHERE org_id = $1 AND usr_id = $2 AND status = 'active'`,
			orgU, adminU,
		).Scan(&adminRole)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("admin not a member: %w", ErrForbidden)
		}
		if err != nil {
			return err
		}
		if adminRole.AdminRank() < 3 {
			return ErrForbidden
		}
		if adminRole.AdminRank() < target.Role.AdminRank() {
			return ErrRoleHierarchy
		}
		if target.Role == RoleOwner {
			n, err := s.countActiveOwners(tx, orgU)
			if err != nil {
				return err
			}
			if n == 1 {
				return ErrSoleOwner
			}
		}
		if _, err := tx.Exec(s.ctx,
			`DELETE FROM tup WHERE subject_type = 'usr' AND subject_id = $1 AND relation = $2 AND object_type = 'org' AND object_id = $3`,
			usrU, target.Role, orgU,
		); err != nil {
			return err
		}
		row = tx.QueryRow(s.ctx, `
			UPDATE mem SET status = 'revoked', removed_by = $2, updated_at = now()
			WHERE id = $1 RETURNING `+memCols, u, adminU,
		)
		out, err = scanMembership(row)
		return err
	})
	return out, err
}

func (s *PostgresTenancyStore) TransferOwnership(orgID, fromMemID, toMemID string) (TransferOwnershipResult, error) {
	orgU, err := wireToUUID(orgID)
	if err != nil {
		return TransferOwnershipResult{}, err
	}
	fromU, err := wireToUUID(fromMemID)
	if err != nil {
		return TransferOwnershipResult{}, err
	}
	toU, err := wireToUUID(toMemID)
	if err != nil {
		return TransferOwnershipResult{}, err
	}
	var out TransferOwnershipResult
	err = s.inTx(func(tx pgx.Tx) error {
		var fromUsr, toUsr uuid.UUID
		var fromRole, toRole Role
		var fromStatus, toStatus Status
		var fromOrg, toOrg uuid.UUID
		err := tx.QueryRow(s.ctx, `SELECT usr_id, org_id, role, status FROM mem WHERE id = $1 FOR UPDATE`, fromU).
			Scan(&fromUsr, &fromOrg, &fromRole, &fromStatus)
		if err != nil {
			return err
		}
		err = tx.QueryRow(s.ctx, `SELECT usr_id, org_id, role, status FROM mem WHERE id = $1 FOR UPDATE`, toU).
			Scan(&toUsr, &toOrg, &toRole, &toStatus)
		if err != nil {
			return err
		}
		if fromOrg != orgU || fromRole != RoleOwner || fromStatus != StatusActive {
			return &PreconditionError{Msg: "from is not an active owner", Reason: "not_active_owner"}
		}
		if toOrg != orgU || toStatus != StatusActive {
			return &PreconditionError{Msg: "to is not an active member", Reason: "not_active_member"}
		}
		if fromU == toU {
			return &PreconditionError{Msg: "cannot transfer ownership to self", Reason: "self_transfer"}
		}
		if err := s.changeRoleLocked(tx, toU, toUsr, orgU, toRole, RoleOwner); err != nil {
			return err
		}
		if err := s.changeRoleLocked(tx, fromU, fromUsr, orgU, RoleOwner, RoleMember); err != nil {
			return err
		}
		// Read back the new memberships for both users.
		row := tx.QueryRow(s.ctx,
			`SELECT `+memCols+` FROM mem WHERE org_id = $1 AND usr_id = $2 AND status = 'active'`,
			orgU, toUsr,
		)
		toMem, err := scanMembership(row)
		if err != nil {
			return err
		}
		row = tx.QueryRow(s.ctx,
			`SELECT `+memCols+` FROM mem WHERE org_id = $1 AND usr_id = $2 AND status = 'active'`,
			orgU, fromUsr,
		)
		fromMem, err := scanMembership(row)
		if err != nil {
			return err
		}
		out = TransferOwnershipResult{FromMembership: fromMem, ToMembership: toMem}
		return nil
	})
	return out, err
}

// ─── Invitations ───

const invCols = `id, org_id, identifier, role, status, pre_tuples, invited_by, invited_user_id,
	created_at, expires_at, terminal_at, terminal_by`

func scanInvitation(row pgx.Row) (Invitation, error) {
	var (
		id, orgID                       uuid.UUID
		identifier                      string
		role                            Role
		status                          InvitationStatus
		preJSON                         []byte
		invitedBy                       uuid.UUID
		invitedUserID, terminalBy       *uuid.UUID
		createdAt, expiresAt            time.Time
		terminalAt                      *time.Time
	)
	if err := row.Scan(&id, &orgID, &identifier, &role, &status, &preJSON, &invitedBy, &invitedUserID, &createdAt, &expiresAt, &terminalAt, &terminalBy); err != nil {
		return Invitation{}, err
	}
	pre, err := unmarshalPreTuples(preJSON)
	if err != nil {
		return Invitation{}, err
	}
	inv := Invitation{
		ID: uuidToWire("inv", id), OrgID: uuidToWire("org", orgID),
		Identifier: identifier, Role: role, Status: status,
		PreTuples: pre, InvitedBy: uuidToWire("usr", invitedBy),
		CreatedAt: createdAt, ExpiresAt: expiresAt, TerminalAt: terminalAt,
	}
	if invitedUserID != nil {
		s := uuidToWire("usr", *invitedUserID)
		inv.InvitedUserID = &s
	}
	if terminalBy != nil {
		s := uuidToWire("usr", *terminalBy)
		inv.TerminalBy = &s
	}
	return inv, nil
}

// pre_tuples are stored as JSONB: array of {relation, object_type, object_id}.
func marshalPreTuples(pre []PreTuple) ([]byte, error) {
	if len(pre) == 0 {
		return []byte("[]"), nil
	}
	var sb strings.Builder
	sb.WriteString("[")
	for i, p := range pre {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `{"relation":%q,"object_type":%q,"object_id":%q}`, p.Relation, p.ObjectType, p.ObjectID)
	}
	sb.WriteString("]")
	return []byte(sb.String()), nil
}

func unmarshalPreTuples(b []byte) ([]PreTuple, error) {
	if len(b) == 0 || string(b) == "[]" || string(b) == "null" {
		return nil, nil
	}
	// Minimal JSON parsing for an array of three-string-field objects.
	// pgx will give us raw JSON bytes; use encoding/json.
	out := []PreTuple{}
	type pre struct {
		Relation   string `json:"relation"`
		ObjectType string `json:"object_type"`
		ObjectID   string `json:"object_id"`
	}
	parsed := []pre{}
	if err := jsonUnmarshal(b, &parsed); err != nil {
		return nil, err
	}
	for _, p := range parsed {
		out = append(out, PreTuple{Relation: p.Relation, ObjectType: p.ObjectType, ObjectID: p.ObjectID})
	}
	return out, nil
}

// Lazy json import via aliased call.
func jsonUnmarshal(data []byte, v any) error {
	return jsonUnmarshalImpl(data, v)
}

func (s *PostgresTenancyStore) CreateInvitation(orgID, identifier string, role Role, invitedBy string, expiresAt time.Time, preTuples []PreTuple) (Invitation, error) {
	orgU, err := wireToUUID(orgID)
	if err != nil {
		return Invitation{}, err
	}
	byU, err := wireToUUID(invitedBy)
	if err != nil {
		return Invitation{}, err
	}
	preJSON, err := marshalPreTuples(preTuples)
	if err != nil {
		return Invitation{}, err
	}
	newID := uuid.Must(uuid.NewV7())
	row := s.exec.QueryRow(s.ctx, `
		INSERT INTO inv (id, org_id, identifier, role, status, pre_tuples, invited_by, expires_at)
		VALUES ($1, $2, $3, $4, 'pending', $5, $6, $7)
		RETURNING `+invCols,
		newID, orgU, identifier, role, preJSON, byU, expiresAt,
	)
	return scanInvitation(row)
}

func (s *PostgresTenancyStore) GetInvitation(invID string) (Invitation, error) {
	u, err := wireToUUID(invID)
	if err != nil {
		return Invitation{}, err
	}
	row := s.exec.QueryRow(s.ctx, `SELECT `+invCols+` FROM inv WHERE id = $1`, u)
	inv, err := scanInvitation(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Invitation{}, fmt.Errorf("inv %s: %w", invID, ErrNotFound)
	}
	if err != nil {
		return Invitation{}, err
	}
	// Lazy expiry.
	if inv.Status == InvitationStatusPending && !s.clock().Before(inv.ExpiresAt) {
		now := s.clock()
		if _, err := s.exec.Exec(s.ctx, `UPDATE inv SET status = 'expired', terminal_at = $2 WHERE id = $1 AND status = 'pending'`, u, now); err != nil {
			return Invitation{}, err
		}
		inv.Status = InvitationStatusExpired
		inv.TerminalAt = &now
	}
	return inv, nil
}

func (s *PostgresTenancyStore) ListInvitations(orgID string, opts ListInvitationsOptions) (Page[Invitation], error) {
	u, err := wireToUUID(orgID)
	if err != nil {
		return Page[Invitation]{}, err
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	args := []any{u}
	q := `SELECT ` + invCols + ` FROM inv WHERE org_id = $1`
	idx := 2
	if opts.Status != nil {
		q += fmt.Sprintf(` AND status = $%d`, idx)
		args = append(args, *opts.Status)
		idx++
	}
	if opts.Cursor != nil && *opts.Cursor != "" {
		curU, err := wireToUUID(*opts.Cursor)
		if err != nil {
			return Page[Invitation]{}, err
		}
		q += fmt.Sprintf(` AND (created_at, id) > (SELECT created_at, id FROM inv WHERE id = $%d)`, idx)
		args = append(args, curU)
		idx++
	}
	q += fmt.Sprintf(` ORDER BY created_at ASC, id ASC LIMIT $%d`, idx)
	args = append(args, limit+1)
	rows, err := s.exec.Query(s.ctx, q, args...)
	if err != nil {
		return Page[Invitation]{}, err
	}
	defer rows.Close()
	out := make([]Invitation, 0, limit)
	for rows.Next() {
		inv, err := scanInvitation(rows)
		if err != nil {
			return Page[Invitation]{}, err
		}
		out = append(out, inv)
	}
	var next *string
	if len(out) > limit {
		c := out[limit-1].ID
		next = &c
		out = out[:limit]
	}
	return Page[Invitation]{Data: out, NextCursor: next}, nil
}

func (s *PostgresTenancyStore) AcceptInvitation(invID string, opts AcceptInvitationOptions) (AcceptInvitationResult, error) {
	u, err := wireToUUID(invID)
	if err != nil {
		return AcceptInvitationResult{}, err
	}
	var out AcceptInvitationResult
	err = s.inTx(func(tx pgx.Tx) error {
		row := tx.QueryRow(s.ctx, `SELECT `+invCols+` FROM inv WHERE id = $1 FOR UPDATE`, u)
		inv, err := scanInvitation(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("inv %s: %w", invID, ErrNotFound)
		}
		if err != nil {
			return err
		}
		if inv.Status != InvitationStatusPending {
			return ErrInvitationNotPending
		}
		now := s.clock()
		if !now.Before(inv.ExpiresAt) {
			if _, err := tx.Exec(s.ctx, `UPDATE inv SET status = 'expired', terminal_at = $2 WHERE id = $1`, u, now); err != nil {
				return err
			}
			return ErrInvitationExpired
		}
		// ADR 0009 binding.
		if opts.AsUsrID != nil {
			if opts.AcceptingIdentifier == nil {
				return ErrIdentifierBindingRequired
			}
			if *opts.AcceptingIdentifier != inv.Identifier {
				return ErrIdentifierMismatch
			}
		}
		var acceptingU uuid.UUID
		if opts.AsUsrID != nil {
			acceptingU, _ = wireToUUID(*opts.AsUsrID)
		} else {
			acceptingU = uuid.Must(uuid.NewV7())
		}
		orgU, _ := wireToUUID(inv.OrgID)
		// Duplicate-membership check.
		var existing uuid.UUID
		err = tx.QueryRow(s.ctx,
			`SELECT id FROM mem WHERE org_id = $1 AND usr_id = $2 AND status = 'active'`,
			orgU, acceptingU,
		).Scan(&existing)
		if err == nil {
			return fmt.Errorf("usr in org: %w", ErrDuplicateMembership)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		invByU, _ := wireToUUID(inv.InvitedBy)
		// Insert membership + role tuple.
		newMemID := uuid.Must(uuid.NewV7())
		row = tx.QueryRow(s.ctx, `
			INSERT INTO mem (id, usr_id, org_id, role, status, invited_by)
			VALUES ($1, $2, $3, $4, 'active', $5)
			RETURNING `+memCols,
			newMemID, acceptingU, orgU, inv.Role, invByU,
		)
		mem, err := scanMembership(row)
		if err != nil {
			return err
		}
		// Role tuple.
		if _, err := tx.Exec(s.ctx, `
			INSERT INTO tup (id, subject_type, subject_id, relation, object_type, object_id, created_by)
			VALUES ($1, 'usr', $2, $3, 'org', $4, $2)`,
			uuid.Must(uuid.NewV7()), acceptingU, inv.Role, orgU,
		); err != nil {
			return err
		}
		materialized := []Tuple{{SubjectType: "usr", SubjectID: uuidToWire("usr", acceptingU), Relation: string(inv.Role), ObjectType: "org", ObjectID: inv.OrgID}}
		// Expand pre_tuples. PreTuple.ObjectID is wire-format
		// (`prefix_<32hex>`); the tup.object_id column is uuid, so the
		// wire form must be parsed before INSERT.
		for _, pt := range inv.PreTuples {
			objU, err := wireToUUID(pt.ObjectID)
			if err != nil {
				return fmt.Errorf("pre_tuple object_id %q: %w", pt.ObjectID, err)
			}
			if _, err := tx.Exec(s.ctx, `
				INSERT INTO tup (id, subject_type, subject_id, relation, object_type, object_id, created_by)
				VALUES ($1, 'usr', $2, $3, $4, $5, $2)`,
				uuid.Must(uuid.NewV7()), acceptingU, pt.Relation, pt.ObjectType, objU,
			); err != nil {
				return err
			}
			materialized = append(materialized, Tuple{SubjectType: "usr", SubjectID: uuidToWire("usr", acceptingU), Relation: pt.Relation, ObjectType: pt.ObjectType, ObjectID: pt.ObjectID})
		}
		// Transition invitation.
		row = tx.QueryRow(s.ctx, `
			UPDATE inv SET status = 'accepted', terminal_at = $2, invited_user_id = $3
			WHERE id = $1 RETURNING `+invCols, u, now, acceptingU,
		)
		invFinal, err := scanInvitation(row)
		if err != nil {
			return err
		}
		out = AcceptInvitationResult{Invitation: invFinal, Membership: mem, MaterializedTuples: materialized}
		return nil
	})
	return out, err
}

func (s *PostgresTenancyStore) DeclineInvitation(invID string, asUsrID *string) (Invitation, error) {
	u, err := wireToUUID(invID)
	if err != nil {
		return Invitation{}, err
	}
	var asU *uuid.UUID
	if asUsrID != nil {
		x, err := wireToUUID(*asUsrID)
		if err != nil {
			return Invitation{}, err
		}
		asU = &x
	}
	now := s.clock()
	row := s.exec.QueryRow(s.ctx, `
		UPDATE inv SET status = 'declined', terminal_at = $2, terminal_by = $3, invited_user_id = COALESCE(invited_user_id, $3)
		WHERE id = $1 AND status = 'pending'
		RETURNING `+invCols, u, now, asU,
	)
	inv, err := scanInvitation(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Invitation{}, ErrInvitationNotPending
	}
	return inv, err
}

func (s *PostgresTenancyStore) RevokeInvitation(invID, adminUsrID string) (Invitation, error) {
	u, err := wireToUUID(invID)
	if err != nil {
		return Invitation{}, err
	}
	adminU, err := wireToUUID(adminUsrID)
	if err != nil {
		return Invitation{}, err
	}
	now := s.clock()
	row := s.exec.QueryRow(s.ctx, `
		UPDATE inv SET status = 'revoked', terminal_at = $2, terminal_by = $3
		WHERE id = $1 AND status = 'pending'
		RETURNING `+invCols, u, now, adminU,
	)
	inv, err := scanInvitation(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Invitation{}, ErrInvitationNotPending
	}
	return inv, err
}

// ─── Tuple accessors ───

func (s *PostgresTenancyStore) ListTuplesForSubject(subjectType, subjectID string) ([]Tuple, error) {
	subjU, err := wireToUUID(subjectID)
	if err != nil {
		return nil, err
	}
	rows, err := s.exec.Query(s.ctx,
		`SELECT subject_type, subject_id, relation, object_type, object_id FROM tup WHERE subject_type = $1 AND subject_id = $2`,
		subjectType, subjU,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Tuple, 0)
	for rows.Next() {
		var t Tuple
		var subj, obj uuid.UUID
		if err := rows.Scan(&t.SubjectType, &subj, &t.Relation, &t.ObjectType, &obj); err != nil {
			return nil, err
		}
		t.SubjectID = uuidToWire(t.SubjectType, subj)
		t.ObjectID = uuidToWire(t.ObjectType, obj)
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *PostgresTenancyStore) ListTuplesForObject(objectType, objectID string, relation *string) ([]Tuple, error) {
	objU, err := wireToUUID(objectID)
	if err != nil {
		return nil, err
	}
	args := []any{objectType, objU}
	q := `SELECT subject_type, subject_id, relation, object_type, object_id FROM tup
	      WHERE object_type = $1 AND object_id = $2`
	if relation != nil {
		q += ` AND relation = $3`
		args = append(args, *relation)
	}
	rows, err := s.exec.Query(s.ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Tuple, 0)
	for rows.Next() {
		var t Tuple
		var subj, obj uuid.UUID
		if err := rows.Scan(&t.SubjectType, &subj, &t.Relation, &t.ObjectType, &obj); err != nil {
			return nil, err
		}
		t.SubjectID = uuidToWire(t.SubjectType, subj)
		t.ObjectID = uuidToWire(t.ObjectType, obj)
		out = append(out, t)
	}
	return out, rows.Err()
}
