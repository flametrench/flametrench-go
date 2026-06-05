module github.com/flametrench/flametrench-go/packages/identity

go 1.20

require (
	github.com/flametrench/flametrench-go/packages/ids v0.3.0
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.5.5
	golang.org/x/crypto v0.20.0
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	golang.org/x/sys v0.17.0 // indirect
	golang.org/x/text v0.14.0 // indirect
)

// v0.3.0 and v0.3.0-rc.1 shipped with workspace-only replace directives that
// break go get for consumers outside the Go workspace. Use v0.3.1 or later.
retract (
	v0.3.0
	v0.3.0-rc.1
)
