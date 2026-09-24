// Package migrations exposes the SQL migrations embedded in the service binary.
package migrations

import "embed"

// FS contains all Goose migration files in this directory.
//
//go:embed *.sql
var FS embed.FS
