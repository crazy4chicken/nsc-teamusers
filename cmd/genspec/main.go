package main

import (
	"fmt"
	"os"
	"path/filepath"

	"teamusers/internal/apidocs"
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
	operations := apidocs.All(authn.DocOperations, httpapi.DocOperations, authz.DocOperations)
	apidocs.SetOperations(operations)
	operations, err := apidocs.Operations()
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
	temporary, err := os.CreateTemp(directory, ".spec.tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := apidocs.Emit(operations, temporary); err != nil {
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
