package domain

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
)

const (
	// MaxConditionSourceLength is the maximum UTF-8 byte length accepted for a
	// stored ABAC condition.
	MaxConditionSourceLength = 4 * 1024

	conditionMaxNodes = 4096
	conditionTimeout  = 100 * time.Millisecond
)

var (
	ErrConditionSourceTooLong = errors.New("condition source exceeds 4 KiB")
	ErrConditionSandbox       = errors.New("condition uses a disallowed environment escape")
)

// Subject is the subject portion of the ABAC evaluation context.
type Subject struct {
	ID   string `expr:"id"`
	Kind string `expr:"kind"`
}

// Resource is the resource portion of the ABAC evaluation context.
type Resource struct {
	OwnerID string         `expr:"owner_id"`
	TeamID  string         `expr:"team_id"`
	Attrs   map[string]any `expr:"attrs"`
}

// Request is the request portion of the ABAC evaluation context.
type Request struct {
	Time time.Time `expr:"time"`
}

// Context is the complete schema exposed to an ABAC expression. No fields or
// methods outside subject{id, kind}, resource{owner_id, team_id, attrs}, and
// request{time} are exposed as expression variables.
type Context struct {
	Subject  Subject  `expr:"subject"`
	Resource Resource `expr:"resource"`
	Request  Request  `expr:"request"`
}

// ABACContext is an explicit alias for Context for callers that prefer the
// authorization-specific name.
type ABACContext = Context

// SubjectContext, ResourceContext, and RequestContext are schema aliases that
// make nested context construction self-documenting.
type SubjectContext = Subject
type ResourceContext = Resource
type RequestContext = Request

// Condition is a compiled, boolean ABAC expression. A nil or empty condition
// is represented by a Condition with no program and always evaluates true.
type Condition struct {
	source  string
	program *vm.Program
}

// Compile validates and compiles an ABAC condition against the fixed Context
// schema. Empty or whitespace-only source is accepted and evaluates true.
func Compile(source string) (*Condition, error) {
	if len(source) > MaxConditionSourceLength {
		return nil, fmt.Errorf("%w: got %d bytes", ErrConditionSourceTooLong, len(source))
	}
	if strings.Contains(source, "$env") {
		return nil, ErrConditionSandbox
	}

	condition := &Condition{source: source}
	if strings.TrimSpace(source) == "" {
		return condition, nil
	}

	program, err := expr.Compile(
		source,
		expr.Env(conditionEnv{}),
		expr.AsBool(),
		expr.MaxNodes(conditionMaxNodes),
		expr.DisableBuiltin("timezone"),
	)
	if err != nil {
		return nil, err
	}
	condition.program = program
	return condition, nil
}

// Eval evaluates the condition with the supplied ABAC context. Evaluation is
// bounded by an internal deadline; use EvalWithContext when a request deadline
// should also cancel evaluation.
func (c *Condition) Eval(ctx Context) (bool, error) {
	return c.eval(context.Background(), ctx)
}

// EvalWithContext evaluates the condition with both a caller-provided context
// deadline and the package's maximum evaluation duration.
func (c *Condition) EvalWithContext(ctx context.Context, values Context) (bool, error) {
	return c.eval(ctx, values)
}

func (c *Condition) eval(ctx context.Context, values Context) (bool, error) {
	if c == nil || c.program == nil {
		return true, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}

	evalCtx, cancel := context.WithTimeout(ctx, conditionTimeout)
	defer cancel()

	resultCh := make(chan conditionResult, 1)
	go func() {
		result, err := expr.Run(c.program, conditionEnv{
			Subject: values.Subject,
			Resource: Resource{
				OwnerID: values.Resource.OwnerID,
				TeamID:  values.Resource.TeamID,
				Attrs:   sanitizeAttrs(values.Resource.Attrs),
			},
			Request: values.Request,
		})
		resultCh <- conditionResult{value: result, err: err}
	}()

	select {
	case <-evalCtx.Done():
		return false, evalCtx.Err()
	case result := <-resultCh:
		if result.err != nil {
			return false, result.err
		}
		value, ok := result.value.(bool)
		if !ok {
			return false, fmt.Errorf("condition result has type %T, want bool", result.value)
		}
		return value, nil
	}
}

type conditionEnv struct {
	Subject  Subject  `expr:"subject"`
	Resource Resource `expr:"resource"`
	Request  Request  `expr:"request"`
}

type conditionResult struct {
	value any
	err   error
}

func sanitizeAttrs(attrs map[string]any) map[string]any {
	if attrs == nil {
		return nil
	}
	safe := make(map[string]any, len(attrs))
	for key, value := range attrs {
		safe[key] = sanitizeAttrValue(value)
	}
	return safe
}

func sanitizeAttrValue(value any) any {
	if value == nil {
		return nil
	}
	switch value := value.(type) {
	case bool, string:
		return value
	}

	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return value
	case reflect.Array, reflect.Slice:
		items := make([]any, rv.Len())
		for i := range rv.Len() {
			items[i] = sanitizeAttrValue(rv.Index(i).Interface())
		}
		return items
	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			return nil
		}
		items := make(map[string]any, rv.Len())
		for _, key := range rv.MapKeys() {
			items[key.String()] = sanitizeAttrValue(rv.MapIndex(key).Interface())
		}
		return items
	default:
		// Structs, pointers, interfaces containing unsupported values, funcs,
		// and channels are not data attributes and must not reach the VM.
		return nil
	}
}
