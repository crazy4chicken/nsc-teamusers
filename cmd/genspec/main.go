package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/crazy4chicken/nsc-teamusers/apidocs/go"

	"teamusers/internal/apidocsgen"
	"teamusers/internal/authn"
	"teamusers/internal/authz"
	"teamusers/internal/httpapi"
)

func main() {
	if err := generate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generate() error {
	operations := apidocs.All(authn.DocOperations, httpapi.DocOperations, httpapi.DocOIDCOperations, httpapi.DocSCIMOperations, httpapi.DocImpersonationOperations, authz.DocOperations)
	operations, err := apidocsgen.Operations(operations, func(_ string, path string) (anyKey, teamKey string) {
		area := httpapi.AdminPermissionArea(path)
		anyKey = httpapi.AdminPermissionForPath(path)
		if anyKey != "" && httpapi.IsTeamScopedAdminArea(area) {
			teamKey = "iam:" + area + ":team"
		}
		return anyKey, teamKey
	})
	if err != nil {
		return fmt.Errorf("collect API operations: %w", err)
	}

	mainPath := filepath.Join("docs", "public", "openapi.yaml")
	if err := writeSpec(mainPath, operations); err != nil {
		return fmt.Errorf("write OpenAPI document: %w", err)
	}
	return nil
}

func writeSpec(path string, operations []apidocs.Operation) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".spec.tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	teamusersOptions := apidocs.EmitOptions{
		Title:   "Teamusers API",
		Version: "1.0.0",
		Servers: []apidocs.Server{{
			URL:         "http://localhost:8080",
			Description: "Nekostick /iam Strip forwarding",
		}},
		SecurityScheme: apidocs.SecurityScheme{
			Name:         "bearerAuth",
			Type:         "http",
			Scheme:       "bearer",
			BearerFormat: "EdDSA JWT",
		},
		PermissionExtension: "x-teamusers-permission",
	}
	if err := apidocs.Emit(operations, temporary, teamusersOptions); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("emit document: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return fmt.Errorf("replace document: %w", err)
	}
	return nil
}
