# flametrench-go/packages/ids

[![CI](https://github.com/flametrench/flametrench-go/actions/workflows/ci.yml/badge.svg)](https://github.com/flametrench/flametrench-go/actions/workflows/ci.yml)

Go SDK for the [Flametrench](https://github.com/flametrench/spec) wire-format identifier specification — fifth in the language family alongside Python, Node, PHP, and Java.

The wire format is `{type}_{32-hex}`, where the hex payload is a UUIDv7 (so generated IDs sort by creation time). The same identifiers travel unchanged across all five SDKs; the conformance fixture corpus enforces this mechanically.

```go
import "github.com/flametrench/flametrench-go/packages/ids"

id, _ := ids.Generate("usr")
// → "usr_0190f2a81b3c7abc8123456789abcdef"

decoded, _ := ids.Decode(id)
// → ids.DecodedID{Type: "usr", UUID: "0190f2a8-1b3c-7abc-8123-456789abcdef"}

ids.IsValid(id, "usr")        // true
ids.IsValid(id, "org")        // false
ids.TypeOf(id)                // "usr", nil
```

## Installation

```bash
go get github.com/flametrench/flametrench-go/packages/ids@v0.3.0
```

Requires Go 1.22+. UUIDv7 generation uses `github.com/google/uuid` (v1.6+).

## Registered type prefixes

| Prefix  | Meaning                | Spec version |
| ------- | ---------------------- | ------------ |
| `usr`   | user                   | v0.1         |
| `org`   | organization           | v0.1         |
| `mem`   | membership             | v0.1         |
| `inv`   | invitation             | v0.1         |
| `ses`   | session                | v0.1         |
| `cred`  | credential             | v0.1         |
| `tup`   | authorization tuple    | v0.1         |
| `mfa`   | MFA factor             | v0.2         |
| `shr`   | share token            | v0.2         |
| `pat`   | personal access token  | v0.3         |

The registry is normative; see [docs/ids.md](https://github.com/flametrench/spec/blob/main/docs/ids.md) for the full rules. App-defined prefixes (e.g. `proj_<hex>`, `team_<hex>`) are valid for `object_id` values in authz tuples; use [`DecodeAny`] / [`IsValidShape`] to inspect them without registry checks.

**Status:** v0.3.0 (stable; in development). Tracks the spec at v0.3.0; the `pat_` prefix lands in v0.3 via [ADR 0016](https://github.com/flametrench/spec/blob/main/decisions/0016-personal-access-tokens.md). Added to the Flametrench SDK matrix as the 5th family per [ADR 0018](https://github.com/flametrench/spec/blob/main/decisions/0018-go-sdk-family-addition.md).

## Conformance

The same fixture corpus that gates `@flametrench/ids` (Node), `flametrench/ids` (PHP), `flametrench-ids` (Python), and `dev.flametrench:ids` (Java) runs here. See [`../conformance`](../../conformance) at the repo root.

## License

Apache License 2.0. Copyright 2026 NDC Digital, LLC.
