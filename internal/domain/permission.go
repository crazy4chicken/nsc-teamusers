package domain

import (
	"fmt"
	"strings"
)

const denyPrefix = "!"

// Permission is a resource/action/scope authorization key.
//
// A deny permission uses Deny=true and is serialized with a leading "!". The
// deny bit is parsed and retained now so the v1.1 evaluation switch can be
// enabled without changing the stored key format.
type Permission struct {
	Resource string
	Action   string
	Scope    string
	Deny     bool
}

// Parse parses a permission key according to the permission grammar.
func Parse(key string) (Permission, error) {
	var permission Permission
	if key == "" {
		return permission, fmt.Errorf("permission key is empty")
	}

	if strings.HasPrefix(key, denyPrefix) {
		permission.Deny = true
		key = key[len(denyPrefix):]
	}

	parts := strings.Split(key, ":")
	if len(parts) != 3 {
		return Permission{}, fmt.Errorf("permission key must contain resource, action, and scope")
	}

	permission.Resource = parts[0]
	permission.Action = parts[1]
	permission.Scope = parts[2]
	if err := permission.Validate(); err != nil {
		return Permission{}, err
	}
	return permission, nil
}

// Validate checks that the permission fields satisfy the write-time grammar.
func (p Permission) Validate() error {
	if err := validateResource(p.Resource); err != nil {
		return err
	}
	if err := validateAction(p.Action); err != nil {
		return err
	}
	if err := validateScope(p.Scope); err != nil {
		return err
	}
	return nil
}

// String serializes a permission in its canonical grammar form.
//
// Callers should call Validate before serializing data supplied at write time.
// For a valid Permission, Parse(p.String()) returns an equivalent value.
func (p Permission) String() string {
	prefix := ""
	if p.Deny {
		prefix = denyPrefix
	}
	return prefix + p.Resource + ":" + p.Action + ":" + p.Scope
}

func validateResource(resource string) error {
	if resource == "" || !isLowerAlpha(resource[0]) {
		return fmt.Errorf("invalid permission resource %q", resource)
	}
	for i := 1; i < len(resource); i++ {
		if !isLowerAlpha(resource[i]) && !isDigit(resource[i]) && resource[i] != '_' && resource[i] != '.' && resource[i] != '-' {
			return fmt.Errorf("invalid permission resource %q", resource)
		}
	}
	return nil
}

func validateAction(action string) error {
	if action == "*" {
		return nil
	}
	if action == "" || !isLowerAlpha(action[0]) {
		return fmt.Errorf("invalid permission action %q", action)
	}
	for i := 1; i < len(action); i++ {
		if !isLowerAlpha(action[i]) && !isDigit(action[i]) && action[i] != '_' && action[i] != '-' {
			return fmt.Errorf("invalid permission action %q", action)
		}
	}
	return nil
}

func validateScope(scope string) error {
	switch scope {
	case "own", "team", "any", "*":
		return nil
	default:
		return fmt.Errorf("invalid permission scope %q", scope)
	}
}

func isLowerAlpha(char byte) bool {
	return char >= 'a' && char <= 'z'
}

func isDigit(char byte) bool {
	return char >= '0' && char <= '9'
}
