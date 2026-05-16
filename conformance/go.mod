module github.com/flametrench/flametrench-go/conformance

go 1.20

require (
	github.com/flametrench/flametrench-go/packages/authz v0.0.0-00010101000000-000000000000
	github.com/flametrench/flametrench-go/packages/identity v0.0.0-00010101000000-000000000000
	github.com/flametrench/flametrench-go/packages/ids v0.0.0-00010101000000-000000000000
	github.com/flametrench/flametrench-go/packages/tenancy v0.0.0-00010101000000-000000000000
	github.com/jackc/pgx/v5 v5.5.5
)

require (
	github.com/google/uuid v1.6.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/jackc/puddle/v2 v2.2.1 // indirect
	golang.org/x/crypto v0.20.0 // indirect
	golang.org/x/sync v0.1.0 // indirect
	golang.org/x/sys v0.17.0 // indirect
	golang.org/x/text v0.14.0 // indirect
)

replace (
	github.com/flametrench/flametrench-go/packages/authz => ../packages/authz
	github.com/flametrench/flametrench-go/packages/identity => ../packages/identity
	github.com/flametrench/flametrench-go/packages/ids => ../packages/ids
	github.com/flametrench/flametrench-go/packages/tenancy => ../packages/tenancy
)
