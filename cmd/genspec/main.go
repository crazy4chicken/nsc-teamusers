package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

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

	specsDirectory := filepath.Join("docs", "public", "specs")
	if err := writeTagSpecs(specsDirectory, operations); err != nil {
		return fmt.Errorf("write per-tag OpenAPI documents: %w", err)
	}
	return nil
}

func writeTagSpecs(directory string, operations []apidocs.Operation) error {
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("create specs directory: %w", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("read specs directory: %w", err)
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		if err := os.Remove(filepath.Join(directory, entry.Name())); err != nil {
			return fmt.Errorf("remove stale spec %q: %w", entry.Name(), err)
		}
	}

	byTag := make(map[string][]apidocs.Operation)
	for _, operation := range operations {
		if operation.Tag == "" {
			continue
		}
		byTag[operation.Tag] = append(byTag[operation.Tag], operation)
	}
	tags := make([]string, 0, len(byTag))
	for tag := range byTag {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	for _, tag := range tags {
		path := filepath.Join(directory, strings.ToLower(tag)+".yaml")
		if err := writeSpec(path, byTag[tag]); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
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
