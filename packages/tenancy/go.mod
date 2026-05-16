module github.com/flametrench/flametrench-go/packages/tenancy

go 1.20

require (
	github.com/flametrench/flametrench-go/packages/ids v0.0.0-00010101000000-000000000000
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.5.5
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	golang.org/x/crypto v0.17.0 // indirect
	golang.org/x/text v0.14.0 // indirect
)

replace github.com/flametrench/flametrench-go/packages/ids => ../ids
