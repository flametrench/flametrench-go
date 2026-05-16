# Changelog

All notable changes to `github.com/flametrench/flametrench-go` are recorded here. Spec-level changes live in [`flametrench/spec`](https://github.com/flametrench/spec/blob/main/CHANGELOG.md).

This is the **5th SDK family** in the Flametrench matrix, added at v0.3.0 per [ADR 0018](https://github.com/flametrench/spec/blob/main/decisions/0018-go-sdk-family-addition.md).

## [v0.3.0] — Unreleased (hold for SDK family parity)

### Added (Go SDK family — Postgres adapters + WebAuthn verifier complete)

WebAuthn assertion verifier (ES256 / RS256 / EdDSA) and full Postgres
adapters across all 4 packages. The Go family now has feature parity
with Python / Node / PHP / Java at the v0.3 spec contract level. Real-
database integration smoke (12 steps including the ADR 0017
Postgres-backed rewrite-rule evaluation) passes.

#### WebAuthn verifier (`packages/identity/webauthn.go`)
- Full COSE_Key parsing (minimal CBOR decoder) + ES256 / RS256 (≥2048-bit) /
  EdDSA dispatch + counter monotonicity per WebAuthn §6.1.1.
- 17 cross-SDK conformance fixtures pass (webauthn-assertion,
  webauthn-assertion-algorithms, webauthn-counter-decrease-rejected).
- Wired into InMemoryIdentityStore's ConfirmWebAuthnFactor + VerifyMfa,
  replacing the previous ErrWebAuthnNotImplemented stubs.

#### Postgres adapters (jackc/pgx/v5)
All three packages now ship Postgres-backed stores with the ADR 0013
caller-owned-connection pattern. The constructor accepts a `PgxExecutor`
interface satisfied by `*pgxpool.Pool`, `*pgx.Conn`, and `pgx.Tx`;
multi-statement operations open a transaction on the executor (or
inherit if one is already active).

- **packages/identity** (`PostgresIdentityStore`) — full surface: users,
  3 credential variants with revoke-and-re-add rotation, sessions with
  refresh-rotates-token, MFA (TOTP + recovery + WebAuthn with the full
  verifier), PATs with H2 timing-oracle defense + last_used_at
  coalescing, `usr_mfa_policy` upsert, cascade revoke on user/credential
  transitions.
- **packages/tenancy** (`PostgresTenancyStore`) — full surface: orgs
  with slug-uniqueness conflict, memberships with revoke-and-re-add
  lifecycle and replaces chain, sole-owner protection on every
  transition, admin-rank hierarchy gating AdminRemove, TransferOwnership
  atomic two-step revoke-and-re-add, 5-state invitation machine with
  lazy + eager expiry, ADR 0009 acceptance binding enforced at the SDK
  layer, tuple accessors for cross-package wiring with authz.
- **packages/authz** (`PostgresTupleStore` + `PostgresShareStore`) —
  full surface: tuple CRUD with natural-key uniqueness, Check + CheckAny
  fast path (single SQL with `relation = ANY(...)`), share tokens with
  SHA-256 BYTEA(32) hashing + single-use atomic consume-on-verify.

#### ADR 0017 — Postgres rewrite-rule evaluation (v0.3)
`NewPostgresTupleStoreWithRules` enables the same rule set as
`InMemoryTupleStore`. Check evaluates via iterative expansion: one
indexed SELECT per direct lookup; one SELECT per `tuple_to_userset`
enumeration; recursive over `computed_userset`. Cycle detection, depth
+ fan-out bounds, and short-circuit semantics from ADR 0007 are
unchanged. The Go integration smoke test exercises the
parent_org → member hop end-to-end against a real database.

#### Integration smoke
`conformance/postgres_integration_test.go` drives a 12-step end-to-end
smoke against a real Postgres database (gated on FT_GO_POSTGRES_URL).
Steps: create user → password credential → verify password → create
session → verify session token → create org with owner mem + tuple →
direct tuple Check → add admin member → CheckAny matches → ChangeRole
replaces-and-re-adds → share-token roundtrip including revoke →
PAT roundtrip including revoke → ADR 0017 rule-eval via parent_org
hop. All 12 pass against Postgres 17.

### Added (Go SDK family — feature parity push, ADR 0018)

The Go family joins the Flametrench SDK matrix as the 5th family. This
release adds full in-memory implementations of all four packages with
spec-conformant behavior at the SDK contract layer. Postgres adapters
are scaffolded; full Postgres parity lands in a follow-up session.

#### `packages/ids`
Full implementation. Wire-format prefixed identifiers (`{prefix}_{32hex}` where
the hex payload is a UUIDv7). Registered prefix registry (`usr`, `org`, `mem`,
`inv`, `ses`, `cred`, `tup`, `mfa`, `shr`, `pat`). API: `Generate`, `Encode`,
`Decode`, `DecodeAny`, `IsValid`, `IsValidShape`, `TypeOf`. **21 unit tests +
48 conformance cases green.**

#### `packages/identity`
Full in-memory implementation. **5 unit tests green.**
- Users with v0.2 `display_name` (ADR 0014) + `ListUsers` cursor pagination (ADR 0015).
- Three credential variants (password / passkey / OIDC) with revoke-and-re-add rotation (ADR 0005).
- Sessions with token-hash storage and refresh-rotates-token semantics.
- Cross-SDK Argon2id PHC string interop (encode + decode) at the spec floor (m=19456, t=2, p=1).
- MFA (ADR 0008): TOTP (RFC 6238 / RFC 4226, ±1 drift window default, configurable algorithm/period/digits) + recovery codes (10 codes, 12-char XXXX-XXXX-XXXX format, 31-char no-confusion alphabet, single-use enforcement).
- Personal access tokens (ADR 0016, v0.3): `pat_<32hex>_<base64url>` wire format, prefix-routed bearer classification (`AuthKind`), H2 timing-oracle defense (dummy Argon2id verify on missing-row path), H6 secret-length cap before Argon2id dispatch, 365-day lifetime cap, last-used-at coalescing.

WebAuthn assertion verification (ES256/RS256/EdDSA over authenticatorData)
is deferred to a follow-up commit — the factor record + enrollment lifecycle
work; verification methods return `ErrWebAuthnNotImplemented`.

#### `packages/tenancy`
Full in-memory implementation. **4 unit tests green.**
- Organizations with v0.2 `name` + `slug` (ADR 0011) including slug-uniqueness conflict semantics.
- Memberships with revoke-and-re-add lifecycle, `replaces` chain, `invited_by` / `removed_by` audit fields.
- Sole-owner protection on demote, self-leave, admin-remove, and transition off active.
- Admin-rank hierarchy (owner=4, admin=3, member=2, guest=1) gating `AdminRemove`.
- 5-state invitation machine (Pending → Accepted | Declined | Revoked | Expired) with lazy + eager expiry.
- ADR 0009 acceptance binding: `AsUsrID` requires byte-equal `AcceptingIdentifier`; mint-new-user path generates a fresh `usr_` ID.
- `TransferOwnership` atomic two-step revoke-and-re-add for both sides.
- Tuple accessors (`ListTuplesForSubject`, `ListTuplesForObject`) for cross-package wiring.

#### `packages/authz`
Full in-memory implementation. **5 unit tests green.**
- Tuple natural-key index with regex validation on `relation` / `subject_type` / `object_type` (matching spec patterns `^[a-z_]{2,32}$` and `^[a-z]{2,6}$`).
- Exact-match `Check` + `CheckAny` (v0.1 fast path).
- Rewrite rules (ADR 0007, v0.2 opt-in via constructor): `This`, `ComputedUserset`, `TupleToUserset` with cycle detection, depth (default 8) + fan-out (default 1024) bounds.
- Share tokens (ADR 0012, v0.2): SHA-256 token hashing, constant-time verify, single-use atomic consume-on-verify, idempotent revoke, 365-day TTL cap. Verification order matches the normative ADR 0012 sequence.

#### `conformance/`
Go test runner consuming `flametrench/spec/conformance/fixtures/` JSON files.
Current coverage: ids fixture group (5 files, 48 cases). Identity, tenancy,
and authz fixture coverage follows once their Postgres adapters land — the
Go in-memory implementations gain that coverage in the same commit that
adds the Postgres adapters.

### Deferred to follow-up

- Postgres adapters across all 4 packages. Scaffolded with `ErrPostgresNotImplemented`; the in-memory implementations are the spec-correctness reference, and the Postgres adapter ports the same surface against a real database.
- WebAuthn assertion verification (ES256 / RS256 / EdDSA).
- Full conformance fixture coverage for identity / tenancy / authz (the spec corpus exercises authz rule eval, share-token semantics, invitation binding — all to be wired alongside the Postgres adapters so the byte-equality assertion runs against both backends).

### Release positioning
- v0.3.0 is held until all 5 SDK families reach parity. Once Postgres adapters and full conformance land, all 5 families tag v0.3.0 in lockstep. See ADR 0018 §"Hold v0.3.0 until all 5 families are ready".
