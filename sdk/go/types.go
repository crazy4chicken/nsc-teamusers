package iam

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
)

// Claims contains the identity claims carried by a verified access token.
type Claims struct {
	Subject  string
	Team     string
	Kind     string
	PermVer  int64
	Audience string
	Expiry   time.Time
}

// Subject is the subject portion of an authorization condition context.
type Subject struct {
	ID   string `expr:"id"`
	Kind string `expr:"kind"`
}

// Resource is the resource portion of an authorization condition context.
type Resource struct {
	OwnerID string         `expr:"owner_id" json:"owner_id"`
	TeamID  string         `expr:"team_id" json:"team_id"`
	Attrs   map[string]any `expr:"attrs" json:"attrs"`
}

// Request is the request portion of an authorization condition context.
type Request struct {
	Time time.Time `expr:"time" json:"time"`
}

// Context is the complete schema exposed to an authorization condition.
type Context struct {
	Subject  Subject  `expr:"subject"`
	Resource Resource `expr:"resource"`
	Request  Request  `expr:"request"`
}

// ABACContext is an alias for Context for callers that prefer the longer name.
type ABACContext = Context

// SubjectContext, ResourceContext, and RequestContext are aliases that make
// nested context construction self-documenting.
type SubjectContext = Subject
type ResourceContext = Resource
type RequestContext = Request

// CompiledCondition is a compiled, boolean expr authorization condition.
// Evaluation errors are intentionally fail-closed and return false.
type CompiledCondition struct {
	Source  string      `json:"-"`
	program *vm.Program `json:"-"`
}

// CompileCondition compiles source against the fixed Context schema.
func CompileCondition(source string) (*CompiledCondition, error) {
	condition := &CompiledCondition{Source: source}
	if strings.TrimSpace(source) == "" {
		return condition, nil
	}
	program, err := expr.Compile(source, expr.Env(Context{}), expr.AsBool(), expr.MaxNodes(4096), expr.DisableBuiltin("timezone"))
	if err != nil {
		return nil, err
	}
	condition.program = program
	return condition, nil
}

// Eval evaluates a condition. A nil or empty condition allows the grant, and
// every compile/runtime/type error denies it.
func (c *CompiledCondition) Eval(values Context) (allowed bool) {
	if c == nil || c.program == nil {
		return true
	}
	defer func() {
		if recover() != nil {
			allowed = false
		}
	}()
	result, err := expr.Run(c.program, values)
	if err != nil {
		return false
	}
	value, ok := result.(bool)
	return ok && value
}

// Evaluate is a readable alias for Eval.
func (c *CompiledCondition) Evaluate(values Context) bool {
	return c.Eval(values)
}

// EvalWithContext evaluates a condition while observing ctx cancellation. The
// expression VM itself is synchronous; cancellation before evaluation is
// checked and cancellation after it begins is treated as a failed evaluation.
func (c *CompiledCondition) EvalWithContext(ctx context.Context, values Context) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return false
	}
	allowed := c.Eval(values)
	if err := ctx.Err(); err != nil {
		return false
	}
	return allowed
}

// Permission is a resource/action/scope authorization key.
type Permission struct {
	Resource string
	Action   string
	Scope    string
	Deny     bool
}

// Parse parses a permission key according to PLAN.md §5.
func Parse(key string) (Permission, error) {
	if key == "" {
		return Permission{}, fmt.Errorf("permission key is empty")
	}
	deny := false
	if strings.HasPrefix(key, "!") {
		deny = true
		key = strings.TrimPrefix(key, "!")
	}
	parts := strings.Split(key, ":")
	if len(parts) != 3 {
		return Permission{}, fmt.Errorf("permission key must contain resource, action, and scope")
	}
	permission := Permission{Resource: parts[0], Action: parts[1], Scope: parts[2], Deny: deny}
	if err := permission.Validate(); err != nil {
		return Permission{}, err
	}
	return permission, nil
}

// ParsePermission is an explicit alias for Parse.
func ParsePermission(key string) (Permission, error) {
	return Parse(key)
}

// Validate checks the permission grammar.
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

// String serializes a valid permission in canonical form.
func (p Permission) String() string {
	prefix := ""
	if p.Deny {
		prefix = "!"
	}
	return prefix + p.Resource + ":" + p.Action + ":" + p.Scope
}

// Match reports whether grant applies to request. Wildcards match one segment
// only and never cross a colon boundary.
func Match(grant, request Permission) bool {
	if grant.Validate() != nil || request.Validate() != nil {
		return false
	}
	return grant.Deny == request.Deny &&
		matchSegment(grant.Resource, request.Resource) &&
		matchSegment(grant.Action, request.Action) &&
		matchSegment(grant.Scope, request.Scope)
}

// MatchKeys parses and matches two permission strings.
func MatchKeys(grant, request string) bool {
	grantPermission, grantErr := Parse(grant)
	requestPermission, requestErr := Parse(request)
	return grantErr == nil && requestErr == nil && Match(grantPermission, requestPermission)
}

func matchSegment(grant, request string) bool {
	return grant == "*" || grant == request
}

func validateResource(resource string) error {
	if resource == "" || !isLowerAlpha(resource[0]) {
		return fmt.Errorf("invalid permission resource %q", resource)
	}
	for i := 1; i < len(resource); i++ {
		char := resource[i]
		if !isLowerAlpha(char) && !isDigit(char) && char != '_' && char != '.' && char != '-' {
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
		char := action[i]
		if !isLowerAlpha(char) && !isDigit(char) && char != '_' && char != '-' {
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
