# Changelog

All notable changes to `github.com/flametrench/flametrench-go` are recorded here. Spec-level changes live in [`flametrench/spec`](https://github.com/flametrench/spec/blob/main/CHANGELOG.md).

This is the **5th SDK family** in the Flametrench matrix, added at v0.3.0 per [ADR 0018](https://github.com/flametrench/spec/blob/main/decisions/0018-go-sdk-family-addition.md).

## [v0.3.0] — Unreleased (hold for SDK family parity)

### Added (Go SDK family scaffolding, ADR 0018)
- New monorepo `github.com/flametrench/flametrench-go` joining the Flametrench SDK matrix as the 5th family.
- `packages/ids` — full implementation. Wire-format prefixed identifiers (`{prefix}_{32hex}` where the hex payload is a UUIDv7). Registered prefix registry (`usr`, `org`, `mem`, `inv`, `ses`, `cred`, `tup`, `mfa`, `shr`, `pat`). API: `Generate`, `Encode`, `Decode`, `DecodeAny`, `IsValid`, `IsValidShape`, `TypeOf`. Conformance suite against the spec fixture corpus passes byte-identical with the other SDK families.
- `packages/identity` — scaffolded (`go.mod` + stub README). Implementation deferred to follow-up sessions.
- `packages/tenancy` — scaffolded.
- `packages/authz` — scaffolded.
- `conformance/` — Go test runner consuming `flametrench/spec/conformance/fixtures/` JSON files. Initial coverage: ids fixture group.

### Release positioning
- v0.3.0 is held until all 5 SDK families reach parity. Once identity/tenancy/authz reach the v0.3 surface and conformance is green across the board, all 5 families tag v0.3.0 in lockstep. See ADR 0018 §"Hold v0.3.0 until all 5 families are ready".
