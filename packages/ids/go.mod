module github.com/flametrench/flametrench-go/packages/ids

go 1.20

require github.com/google/uuid v1.6.0

// v0.3.0 and v0.3.0-rc.1 are retracted: dependent modules (identity, tenancy,
// authz) shipped with workspace-only replace directives that break go get for
// consumers outside the Go workspace. Use v0.3.1 or later.
retract (
	v0.3.0
	v0.3.0-rc.1
)
