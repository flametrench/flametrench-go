# Flametrench Go SDK

[![CI](https://github.com/flametrench/flametrench-go/actions/workflows/ci.yml/badge.svg)](https://github.com/flametrench/flametrench-go/actions/workflows/ci.yml)

The Go family of Flametrench SDKs — fifth in the language matrix alongside [Python](https://github.com/flametrench/identity-python), [Node](https://github.com/flametrench/node), [PHP](https://github.com/flametrench/identity-php), and [Java](https://github.com/flametrench/identity-java). Same spec contract, same fixture corpus, same wire format.

## Packages

This is a Go workspace monorepo. Four packages live under `packages/`, each its own Go module:

| Module | Purpose | Status |
|---|---|---|
| [`packages/ids`](packages/ids) | Wire-format prefixed identifiers (UUIDv7) | ✅ v0.3.0 (in-memory + conformance green) |
| [`packages/identity`](packages/identity) | Users, credentials, sessions, MFA, PATs | ✅ v0.3.0 in-memory; 🚧 Postgres adapter scaffolded |
| [`packages/tenancy`](packages/tenancy) | Organizations, memberships, invitations | ✅ v0.3.0 in-memory; 🚧 Postgres adapter scaffolded |
| [`packages/authz`](packages/authz) | Tuples, exact-match `check()`, rewrite rules, share tokens | ✅ v0.3.0 in-memory; 🚧 Postgres adapter scaffolded |

The repo is structured per [ADR 0018](https://github.com/flametrench/spec/blob/main/decisions/0018-go-sdk-family-addition.md). Module path stems are `github.com/flametrench/flametrench-go/packages/{ids,identity,tenancy,authz}`.

## Install

```bash
go get github.com/flametrench/flametrench-go/packages/ids@v0.3.0
go get github.com/flametrench/flametrench-go/packages/identity@v0.3.0
go get github.com/flametrench/flametrench-go/packages/tenancy@v0.3.0
go get github.com/flametrench/flametrench-go/packages/authz@v0.3.0
```

No central registry — Go's module proxy serves directly from this repository's tags.

## Status

This is **first-party SDK family #5**, added at the v0.3.0 spec release per ADR 0018. The driving signal was sitesource/admin's expansion into Go-implemented services in May 2026; the four-family cap was lifted with that adopter signal in hand.

v0.3.0 is held until the Go family reaches parity with the other four. Current state:

- `packages/ids` — full implementation; 21 unit tests + 48 conformance cases green.
- `packages/identity` — full in-memory implementation (users, credentials, sessions, MFA TOTP + recovery codes, PATs with H2 timing-oracle defense + H6 secret length cap). 5 unit tests green. Postgres adapter scaffolded; full implementation lands in a follow-up session. WebAuthn assertion verification (ES256/RS256/EdDSA over authenticatorData) is deferred — factor record + lifecycle work; verification surfaces ErrWebAuthnNotImplemented.
- `packages/tenancy` — full in-memory implementation (orgs, memberships with revoke-and-re-add, 5-state invitation machine including ADR 0009 binding, sole-owner protection, admin-rank hierarchy, transfer-ownership). 4 unit tests green. Postgres adapter scaffolded.
- `packages/authz` — full in-memory implementation (tuples, Check + CheckAny, rewrite rules with ComputedUserset + TupleToUserset hop, share tokens with single-use semantics). 5 unit tests green. Postgres adapter scaffolded.

## Development

```bash
# Clone with all packages in a Go workspace
git clone https://github.com/flametrench/flametrench-go.git
cd flametrench-go

# Build + test the whole tree
go build ./...
go test ./...

# Per-package
cd packages/ids
go test -v
```

The root `go.work` file ties the four `packages/*/go.mod` files into a single workspace for local dev. Adopters never need `go.work` — they `go get` the published modules directly.

## Conformance

The `conformance/` directory runs the spec's JSON fixture corpus (vendored from [`flametrench/spec/conformance/fixtures/`](https://github.com/flametrench/spec/tree/main/conformance/fixtures)) against each Go package. Cross-language parity with Python / Node / PHP / Java is enforced mechanically by this suite — a fixture that passes on Python passes here, byte-identical wire shapes.

To run:

```bash
cd conformance
go test -v ./...
```

## Specification

The Go SDK conforms to the Flametrench specification at [github.com/flametrench/spec](https://github.com/flametrench/spec). Key documents:

- [`docs/ids.md`](https://github.com/flametrench/spec/blob/main/docs/ids.md) — wire-format identifier rules
- [`docs/identity.md`](https://github.com/flametrench/spec/blob/main/docs/identity.md) — users, credentials, sessions, MFA, PATs
- [`docs/tenancy.md`](https://github.com/flametrench/spec/blob/main/docs/tenancy.md) — orgs, memberships, invitations
- [`docs/authorization.md`](https://github.com/flametrench/spec/blob/main/docs/authorization.md) — tuples, check, rewrite rules, share tokens
- [`decisions/0018-go-sdk-family-addition.md`](https://github.com/flametrench/spec/blob/main/decisions/0018-go-sdk-family-addition.md) — why Go was added

## License

Apache License 2.0. Copyright 2026 NDC Digital, LLC. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
