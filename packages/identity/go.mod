module github.com/flametrench/flametrench-go/packages/identity

go 1.20

require (
	github.com/flametrench/flametrench-go/packages/ids v0.0.0-00010101000000-000000000000
	github.com/google/uuid v1.6.0
	golang.org/x/crypto v0.41.0
)

replace github.com/flametrench/flametrench-go/packages/ids => ../ids
