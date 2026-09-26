package apidocs

import "reflect"

// Operation describes one HTTP operation in the generated OpenAPI document.
type Operation struct {
	Method          string
	Path            string
	Tag             string
	Summary         string
	Description     string
	Security        string
	Request         any
	Response        any
	RequestExample  any
	ResponseExample any
	Errors          []ErrorDoc
}

// ErrorDoc describes one documented problem response.
type ErrorDoc struct {
	Status int
	Code   string
	Title  string
}

// Reflected is the reflection type used by schema helpers.
type Reflected = reflect.Type

// SchemaOf reflects the type of a zero value into an OpenAPI schema.
func SchemaOf(v any) map[string]any {
	if v == nil {
		return map[string]any{}
	}
	schema := schemaFor(reflect.TypeOf(v), make(map[reflect.Type]bool))
	if schema == true {
		return map[string]any{}
	}
	return schema.(map[string]any)
}
