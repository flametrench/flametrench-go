// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

// PostgresTupleStore + PostgresShareStore — Postgres-backed authz
// using jackc/pgx/v5. Includes ADR 0017 (v0.3) Postgres-backed
// rewrite-rule evaluation: PostgresTupleStore.Check accepts the same
// rules option as InMemoryTupleStore and evaluates via iterative
// expansion against the database (one indexed SELECT per direct
// lookup / tuple_to_userset enumeration, recursive over
// computed_userset).

package authz

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
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

// ─── helpers ───

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

// idToSubjectUUID parses a wire-format ID like "usr_…" / "org_…" / app-defined
// "proj_…" into a canonical UUID, regardless of prefix.
func idToSubjectUUID(id string) (uuid.UUID, error) {
	return wireToUUID(id)
}

// ─── PostgresTupleStore ───

type PostgresTupleStore struct {
	exec      PgxExecutor
	clock     func() time.Time
	ctx       context.Context
	rules     Rules
	maxDepth  int
	maxFanOut int
}

var _ TupleStore = (*PostgresTupleStore)(nil)

func NewPostgresTupleStore(ctx context.Context, exec PgxExecutor) *PostgresTupleStore {
	return &PostgresTupleStore{exec: exec, clock: func() time.Time { return time.Now().UTC() }, ctx: ctx}
}

// NewPostgresTupleStoreWithRules enables v0.3 ADR 0017 Postgres-backed
// rewrite-rule evaluation. Check accepts the same rule shape as the
// in-memory store; evaluation issues one indexed SELECT per direct
// lookup and per tuple_to_userset hop.
func NewPostgresTupleStoreWithRules(ctx context.Context, exec PgxExecutor, rules Rules, opts EvaluateOptions) *PostgresTupleStore {
	s := NewPostgresTupleStore(ctx, exec)
	s.rules = rules
	s.maxDepth = opts.MaxDepth
	s.maxFanOut = opts.MaxFanOut
	return s
}

func (s *PostgresTupleStore) WithClock(c func() time.Time) *PostgresTupleStore { s.clock = c; return s }

func (s *PostgresTupleStore) CreateTuple(in CreateTupleInput) (Tuple, error) {
	if !RelationNamePattern.MatchString(in.Relation) {
		return Tuple{}, fmt.Errorf("relation %q: %w", in.Relation, ErrInvalidFormat)
	}
	if !TypePrefixPattern.MatchString(in.SubjectType) {
		return Tuple{}, fmt.Errorf("subject_type %q: %w", in.SubjectType, ErrInvalidFormat)
	}
	if !TypePrefixPattern.MatchString(in.ObjectType) {
		return Tuple{}, fmt.Errorf("object_type %q: %w", in.ObjectType, ErrInvalidFormat)
	}
	subjU, err := idToSubjectUUID(in.SubjectID)
	if err != nil {
		return Tuple{}, err
	}
	objU, err := idToSubjectUUID(in.ObjectID)
	if err != nil {
		return Tuple{}, err
	}
	var createdByU *uuid.UUID
	if in.CreatedBy != nil {
		u, err := wireToUUID(*in.CreatedBy)
		if err != nil {
			return Tuple{}, err
		}
		createdByU = &u
	}
	newID := uuid.Must(uuid.NewV7())
	var t Tuple
	err = s.exec.QueryRow(s.ctx, `
		INSERT INTO tup (id, subject_type, subject_id, relation, object_type, object_id, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at`,
		newID, in.SubjectType, subjU, in.Relation, in.ObjectType, objU, createdByU,
	).Scan(&newID, &t.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return Tuple{}, fmt.Errorf("tuple: %w", ErrDuplicateTuple)
		}
		return Tuple{}, err
	}
	t.ID = uuidToWire("tup", newID)
	t.SubjectType = in.SubjectType
	t.SubjectID = in.SubjectID
	t.Relation = in.Relation
	t.ObjectType = in.ObjectType
	t.ObjectID = in.ObjectID
	t.CreatedBy = in.CreatedBy
	return t, nil
}

func (s *PostgresTupleStore) DeleteTuple(tupleID string) error {
	u, err := wireToUUID(tupleID)
	if err != nil {
		return err
	}
	tag, err := s.exec.Exec(s.ctx, `DELETE FROM tup WHERE id = $1`, u)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("tuple %s: %w", tupleID, ErrTupleNotFound)
	}
	return nil
}

func (s *PostgresTupleStore) CascadeRevokeSubject(subjectType, subjectID string) (int, error) {
	subjU, err := idToSubjectUUID(subjectID)
	if err != nil {
		return 0, err
	}
	tag, err := s.exec.Exec(s.ctx,
		`DELETE FROM tup WHERE subject_type = $1 AND subject_id = $2`,
		subjectType, subjU,
	)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func (s *PostgresTupleStore) directLookup(subjectType, subjectIDWire, relation, objectType, objectIDWire string) (string, bool, error) {
	subjU, err := idToSubjectUUID(subjectIDWire)
	if err != nil {
		return "", false, nil
	}
	objU, err := idToSubjectUUID(objectIDWire)
	if err != nil {
		return "", false, nil
	}
	var tupID uuid.UUID
	err = s.exec.QueryRow(s.ctx, `
		SELECT id FROM tup
		WHERE subject_type = $1 AND subject_id = $2 AND relation = $3
		      AND object_type = $4 AND object_id = $5`,
		subjectType, subjU, relation, objectType, objU,
	).Scan(&tupID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return uuidToWire("tup", tupID), true, nil
}

func (s *PostgresTupleStore) listByObject(objectType, objectIDWire, relation string) ([]SubjectRef, error) {
	objU, err := idToSubjectUUID(objectIDWire)
	if err != nil {
		return nil, err
	}
	rows, err := s.exec.Query(s.ctx, `
		SELECT id, subject_type, subject_id FROM tup
		WHERE object_type = $1 AND object_id = $2 AND relation = $3`,
		objectType, objU, relation,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]SubjectRef, 0)
	for rows.Next() {
		var tid, sid uuid.UUID
		var st string
		if err := rows.Scan(&tid, &st, &sid); err != nil {
			return nil, err
		}
		out = append(out, SubjectRef{SubjectType: st, SubjectID: uuidToWire(st, sid), TupleID: uuidToWire("tup", tid)})
	}
	return out, nil
}

func (s *PostgresTupleStore) Check(in CheckInput) (CheckResult, error) {
	if s.rules == nil {
		tupID, ok, err := s.directLookup(in.SubjectType, in.SubjectID, in.Relation, in.ObjectType, in.ObjectID)
		if err != nil {
			return CheckResult{}, err
		}
		if ok {
			return CheckResult{Allowed: true, MatchedTupleID: &tupID}, nil
		}
		return CheckResult{Allowed: false}, nil
	}
	// ADR 0017: rule-aware path. Same algorithm as in-memory; the
	// callbacks issue real SQL queries instead of map lookups.
	var firstErr error
	res, err := Evaluate(
		s.rules,
		in.SubjectType, in.SubjectID, in.Relation, in.ObjectType, in.ObjectID,
		func(st, sid, rel, ot, oid string) (string, bool) {
			id, ok, err := s.directLookup(st, sid, rel, ot, oid)
			if err != nil && firstErr == nil {
				firstErr = err
			}
			return id, ok
		},
		func(ot, oid, rel string) []SubjectRef {
			subs, err := s.listByObject(ot, oid, rel)
			if err != nil && firstErr == nil {
				firstErr = err
			}
			return subs
		},
		EvaluateOptions{MaxDepth: s.maxDepth, MaxFanOut: s.maxFanOut},
	)
	if firstErr != nil {
		return CheckResult{}, firstErr
	}
	if err != nil {
		return CheckResult{}, err
	}
	if res.Allowed {
		mid := res.MatchedTupleID
		return CheckResult{Allowed: true, MatchedTupleID: &mid}, nil
	}
	return CheckResult{Allowed: false}, nil
}

func (s *PostgresTupleStore) CheckAny(in CheckAnyInput) (CheckResult, error) {
	if len(in.Relations) == 0 {
		return CheckResult{}, ErrEmptyRelationSet
	}
	// Fast path: no rules — single SQL query with relation = ANY.
	if s.rules == nil {
		subjU, err := idToSubjectUUID(in.SubjectID)
		if err != nil {
			return CheckResult{}, err
		}
		objU, err := idToSubjectUUID(in.ObjectID)
		if err != nil {
			return CheckResult{}, err
		}
		// Sanity-check relations against the regex before binding.
		// security-audit-v0.3.md C1: validate each element before
		// passing to ANY — protects against an SQL-array smuggle if
		// an adopter's request body manages to bypass type validation.
		for _, rel := range in.Relations {
			if !RelationNamePattern.MatchString(rel) {
				return CheckResult{}, fmt.Errorf("relation %q: %w", rel, ErrInvalidFormat)
			}
		}
		var tupID uuid.UUID
		err = s.exec.QueryRow(s.ctx, `
			SELECT id FROM tup
			WHERE subject_type = $1 AND subject_id = $2
			      AND relation = ANY($3)
			      AND object_type = $4 AND object_id = $5
			LIMIT 1`,
			in.SubjectType, subjU, in.Relations, in.ObjectType, objU,
		).Scan(&tupID)
		if errors.Is(err, pgx.ErrNoRows) {
			return CheckResult{Allowed: false}, nil
		}
		if err != nil {
			return CheckResult{}, err
		}
		w := uuidToWire("tup", tupID)
		return CheckResult{Allowed: true, MatchedTupleID: &w}, nil
	}
	// Rule-aware path: iterate relations.
	for _, rel := range in.Relations {
		r, err := s.Check(CheckInput{
			SubjectType: in.SubjectType, SubjectID: in.SubjectID,
			Relation: rel, ObjectType: in.ObjectType, ObjectID: in.ObjectID,
		})
		if err != nil {
			return CheckResult{}, err
		}
		if r.Allowed {
			return r, nil
		}
	}
	return CheckResult{Allowed: false}, nil
}

func (s *PostgresTupleStore) GetTuple(tupleID string) (Tuple, error) {
	u, err := wireToUUID(tupleID)
	if err != nil {
		return Tuple{}, err
	}
	var (
		id          uuid.UUID
		subjT, objT string
		subjID      uuid.UUID
		relation    string
		objID       uuid.UUID
		createdAt   time.Time
		createdBy   *uuid.UUID
	)
	err = s.exec.QueryRow(s.ctx, `
		SELECT id, subject_type, subject_id, relation, object_type, object_id, created_at, created_by
		FROM tup WHERE id = $1`, u,
	).Scan(&id, &subjT, &subjID, &relation, &objT, &objID, &createdAt, &createdBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return Tuple{}, fmt.Errorf("tuple %s: %w", tupleID, ErrTupleNotFound)
	}
	if err != nil {
		return Tuple{}, err
	}
	t := Tuple{
		ID: uuidToWire("tup", id),
		SubjectType: subjT, SubjectID: uuidToWire(subjT, subjID),
		Relation:   relation,
		ObjectType: objT, ObjectID: uuidToWire(objT, objID),
		CreatedAt: createdAt,
	}
	if createdBy != nil {
		s := uuidToWire("usr", *createdBy)
		t.CreatedBy = &s
	}
	return t, nil
}

func (s *PostgresTupleStore) ListTuplesBySubject(subjectType, subjectID string, opts ListTuplesOptions) (Page[Tuple], error) {
	subjU, err := idToSubjectUUID(subjectID)
	if err != nil {
		return Page[Tuple]{}, err
	}
	return s.listTuples(`subject_type = $1 AND subject_id = $2`, []any{subjectType, subjU}, opts.Cursor, opts.Limit)
}

func (s *PostgresTupleStore) ListTuplesByObject(objectType, objectID string, opts ListByObjectOptions) (Page[Tuple], error) {
	objU, err := idToSubjectUUID(objectID)
	if err != nil {
		return Page[Tuple]{}, err
	}
	args := []any{objectType, objU}
	cond := `object_type = $1 AND object_id = $2`
	if opts.Relation != nil {
		cond += ` AND relation = $3`
		args = append(args, *opts.Relation)
	}
	return s.listTuples(cond, args, opts.Cursor, opts.Limit)
}

func (s *PostgresTupleStore) listTuples(where string, args []any, cursor *string, limit int) (Page[Tuple], error) {
	if limit <= 0 {
		limit = 50
	}
	idx := len(args) + 1
	if cursor != nil && *cursor != "" {
		curU, err := wireToUUID(*cursor)
		if err != nil {
			return Page[Tuple]{}, err
		}
		where += fmt.Sprintf(` AND (created_at, id) > (SELECT created_at, id FROM tup WHERE id = $%d)`, idx)
		args = append(args, curU)
		idx++
	}
	q := fmt.Sprintf(`
		SELECT id, subject_type, subject_id, relation, object_type, object_id, created_at, created_by
		FROM tup WHERE %s ORDER BY created_at ASC, id ASC LIMIT $%d`, where, idx)
	args = append(args, limit+1)
	rows, err := s.exec.Query(s.ctx, q, args...)
	if err != nil {
		return Page[Tuple]{}, err
	}
	defer rows.Close()
	out := make([]Tuple, 0, limit)
	for rows.Next() {
		var (
			id          uuid.UUID
			subjT, objT string
			subjID      uuid.UUID
			relation    string
			objID       uuid.UUID
			createdAt   time.Time
			createdBy   *uuid.UUID
		)
		if err := rows.Scan(&id, &subjT, &subjID, &relation, &objT, &objID, &createdAt, &createdBy); err != nil {
			return Page[Tuple]{}, err
		}
		t := Tuple{
			ID: uuidToWire("tup", id),
			SubjectType: subjT, SubjectID: uuidToWire(subjT, subjID),
			Relation:   relation,
			ObjectType: objT, ObjectID: uuidToWire(objT, objID),
			CreatedAt: createdAt,
		}
		if createdBy != nil {
			c := uuidToWire("usr", *createdBy)
			t.CreatedBy = &c
		}
		out = append(out, t)
	}
	var next *string
	if len(out) > limit {
		c := out[limit-1].ID
		next = &c
		out = out[:limit]
	}
	return Page[Tuple]{Data: out, NextCursor: next}, nil
}

// ─── PostgresShareStore ───

type PostgresShareStore struct {
	exec  PgxExecutor
	clock func() time.Time
	ctx   context.Context
}

var _ ShareStore = (*PostgresShareStore)(nil)

func NewPostgresShareStore(ctx context.Context, exec PgxExecutor) *PostgresShareStore {
	return &PostgresShareStore{exec: exec, clock: func() time.Time { return time.Now().UTC() }, ctx: ctx}
}

func (s *PostgresShareStore) WithClock(c func() time.Time) *PostgresShareStore { s.clock = c; return s }

func (s *PostgresShareStore) CreateShare(in CreateShareInput) (CreateShareResult, error) {
	if !RelationNamePattern.MatchString(in.Relation) {
		return CreateShareResult{}, fmt.Errorf("relation: %w", ErrInvalidFormat)
	}
	if in.ExpiresInSeconds <= 0 || in.ExpiresInSeconds > ShareMaxTTLSeconds {
		return CreateShareResult{}, fmt.Errorf("ttl out of range (1..%d): %w", ShareMaxTTLSeconds, ErrInvalidFormat)
	}
	createdByU, err := wireToUUID(in.CreatedBy)
	if err != nil {
		return CreateShareResult{}, err
	}
	objU, err := idToSubjectUUID(in.ObjectID)
	if err != nil {
		return CreateShareResult{}, err
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return CreateShareResult{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	hSum := sha256.Sum256([]byte(token))
	hashBytes := hSum[:]
	newID := uuid.Must(uuid.NewV7())
	expiresAt := s.clock().Add(time.Duration(in.ExpiresInSeconds) * time.Second)
	var sh Share
	err = s.exec.QueryRow(s.ctx, `
		INSERT INTO shr (id, object_type, object_id, relation, created_by, token_hash, expires_at, single_use)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, expires_at, single_use, consumed_at, revoked_at, created_at`,
		newID, in.ObjectType, objU, in.Relation, createdByU, hashBytes, expiresAt, in.SingleUse,
	).Scan(&newID, &sh.ExpiresAt, &sh.SingleUse, &sh.ConsumedAt, &sh.RevokedAt, &sh.CreatedAt)
	if err != nil {
		return CreateShareResult{}, err
	}
	sh.ID = uuidToWire("shr", newID)
	sh.ObjectType = in.ObjectType
	sh.ObjectID = in.ObjectID
	sh.Relation = in.Relation
	sh.CreatedBy = in.CreatedBy
	return CreateShareResult{Share: sh, Token: token}, nil
}

func (s *PostgresShareStore) GetShare(shareID string) (Share, error) {
	u, err := wireToUUID(shareID)
	if err != nil {
		return Share{}, err
	}
	return s.loadShare(u)
}

func (s *PostgresShareStore) loadShare(u uuid.UUID) (Share, error) {
	var (
		sh           Share
		id           uuid.UUID
		objT         string
		objID        uuid.UUID
		createdBy    uuid.UUID
		consumedAt   *time.Time
		revokedAt    *time.Time
	)
	err := s.exec.QueryRow(s.ctx, `
		SELECT id, object_type, object_id, relation, created_by, expires_at, single_use, consumed_at, revoked_at, created_at
		FROM shr WHERE id = $1`, u,
	).Scan(&id, &objT, &objID, &sh.Relation, &createdBy, &sh.ExpiresAt, &sh.SingleUse, &consumedAt, &revokedAt, &sh.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Share{}, fmt.Errorf("share %s: %w", uuidToWire("shr", u), ErrShareNotFound)
	}
	if err != nil {
		return Share{}, err
	}
	sh.ID = uuidToWire("shr", id)
	sh.ObjectType = objT
	sh.ObjectID = uuidToWire(objT, objID)
	sh.CreatedBy = uuidToWire("usr", createdBy)
	sh.ConsumedAt = consumedAt
	sh.RevokedAt = revokedAt
	return sh, nil
}

func (s *PostgresShareStore) VerifyShareToken(token string) (VerifiedShare, error) {
	hSum := sha256.Sum256([]byte(token))
	hashBytes := hSum[:]
	tx, err := s.exec.Begin(s.ctx)
	if err != nil {
		return VerifiedShare{}, err
	}
	defer func() { _ = tx.Rollback(s.ctx) }()
	var (
		id, objID    uuid.UUID
		objT, rel    string
		storedHash   []byte
		expiresAt    time.Time
		singleUse    bool
		consumedAt   *time.Time
		revokedAt    *time.Time
	)
	err = tx.QueryRow(s.ctx, `
		SELECT id, object_type, object_id, relation, token_hash, expires_at,
		       single_use, consumed_at, revoked_at
		FROM shr WHERE token_hash = $1 FOR UPDATE`, hashBytes,
	).Scan(&id, &objT, &objID, &rel, &storedHash, &expiresAt, &singleUse, &consumedAt, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return VerifiedShare{}, ErrInvalidShareToken
	}
	if err != nil {
		return VerifiedShare{}, err
	}
	if subtle.ConstantTimeCompare(hashBytes, storedHash) != 1 {
		return VerifiedShare{}, ErrInvalidShareToken
	}
	if revokedAt != nil {
		return VerifiedShare{}, ErrShareRevoked
	}
	if singleUse && consumedAt != nil {
		return VerifiedShare{}, ErrShareConsumed
	}
	if !s.clock().Before(expiresAt) {
		return VerifiedShare{}, ErrShareExpired
	}
	if singleUse {
		if _, err := tx.Exec(s.ctx, `UPDATE shr SET consumed_at = $2 WHERE id = $1`, id, s.clock()); err != nil {
			return VerifiedShare{}, err
		}
	}
	if err := tx.Commit(s.ctx); err != nil {
		return VerifiedShare{}, err
	}
	return VerifiedShare{
		ShareID: uuidToWire("shr", id),
		ObjectType: objT, ObjectID: uuidToWire(objT, objID),
		Relation: rel,
	}, nil
}

func (s *PostgresShareStore) RevokeShare(shareID string) (Share, error) {
	u, err := wireToUUID(shareID)
	if err != nil {
		return Share{}, err
	}
	if _, err := s.exec.Exec(s.ctx,
		`UPDATE shr SET revoked_at = COALESCE(revoked_at, $1) WHERE id = $2`,
		s.clock(), u,
	); err != nil {
		return Share{}, err
	}
	return s.loadShare(u)
}

func (s *PostgresShareStore) ListSharesForObject(objectType, objectID string, opts ListSharesOptions) (Page[Share], error) {
	objU, err := idToSubjectUUID(objectID)
	if err != nil {
		return Page[Share]{}, err
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	args := []any{objectType, objU}
	q := `SELECT id, object_type, object_id, relation, created_by, expires_at, single_use, consumed_at, revoked_at, created_at
	      FROM shr WHERE object_type = $1 AND object_id = $2`
	idx := 3
	if opts.Cursor != nil && *opts.Cursor != "" {
		curU, err := wireToUUID(*opts.Cursor)
		if err != nil {
			return Page[Share]{}, err
		}
		q += fmt.Sprintf(` AND (created_at, id) > (SELECT created_at, id FROM shr WHERE id = $%d)`, idx)
		args = append(args, curU)
		idx++
	}
	q += fmt.Sprintf(` ORDER BY created_at ASC, id ASC LIMIT $%d`, idx)
	args = append(args, limit+1)
	rows, err := s.exec.Query(s.ctx, q, args...)
	if err != nil {
		return Page[Share]{}, err
	}
	defer rows.Close()
	out := make([]Share, 0, limit)
	for rows.Next() {
		var (
			sh           Share
			id, objIDU   uuid.UUID
			objT         string
			createdBy    uuid.UUID
			consumedAt   *time.Time
			revokedAt    *time.Time
		)
		if err := rows.Scan(&id, &objT, &objIDU, &sh.Relation, &createdBy, &sh.ExpiresAt, &sh.SingleUse, &consumedAt, &revokedAt, &sh.CreatedAt); err != nil {
			return Page[Share]{}, err
		}
		sh.ID = uuidToWire("shr", id)
		sh.ObjectType = objT
		sh.ObjectID = uuidToWire(objT, objIDU)
		sh.CreatedBy = uuidToWire("usr", createdBy)
		sh.ConsumedAt = consumedAt
		sh.RevokedAt = revokedAt
		out = append(out, sh)
	}
	var next *string
	if len(out) > limit {
		c := out[limit-1].ID
		next = &c
		out = out[:limit]
	}
	return Page[Share]{Data: out, NextCursor: next}, nil
}
