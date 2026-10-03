package apidocs

import (
	"encoding/json"
	"reflect"
	"time"
)

var timeType = reflect.TypeOf(time.Time{})
var rawMessageType = reflect.TypeOf(json.RawMessage{})

func schemaFor(t reflect.Type, stack map[reflect.Type]bool) any {
	if t == nil {
		return true
	}
	if t == rawMessageType {
		return true
	}
	if t.Kind() == reflect.Pointer {
		return map[string]any{
			"anyOf": []any{
				schemaFor(t.Elem(), stack),
				map[string]any{"type": "null"},
			},
		}
	}
	if t == timeType {
		return map[string]any{"type": "string", "format": "date-time"}
	}

	switch t.Kind() {
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return map[string]any{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Interface:
		return true
	case reflect.Slice, reflect.Array:
		return map[string]any{
			"type":  "array",
			"items": schemaFor(t.Elem(), stack),
		}
	case reflect.Map:
		if t.Key().Kind() != reflect.String {
			return map[string]any{"type": "object"}
		}
		return map[string]any{
			"type":                 "object",
			"additionalProperties": schemaFor(t.Elem(), stack),
		}
	case reflect.Struct:
		if stack[t] {
			return map[string]any{"type": "object"}
		}
		stack[t] = true
		defer delete(stack, t)
		properties := make(map[string]any)
		required := make([]any, 0)
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			if field.PkgPath != "" {
				continue
			}
			name, options, skip := jsonField(field)
			if skip {
				continue
			}
			properties[name] = schemaFor(field.Type, stack)
			if !options["omitempty"] {
				required = append(required, name)
			}
		}
		result := map[string]any{"type": "object", "properties": properties}
		if len(required) > 0 {
			result["required"] = required
		}
		return result
	default:
		return true
	}
}

func jsonField(field reflect.StructField) (string, map[string]bool, bool) {
	tag, ok := field.Tag.Lookup("json")
	if !ok {
		return field.Name, nil, false
	}
	parts := splitJSONTag(tag)
	if parts[0] == "-" {
		return "", nil, true
	}
	name := parts[0]
	if name == "" {
		name = field.Name
	}
	options := make(map[string]bool, len(parts)-1)
	for _, option := range parts[1:] {
		if option != "" {
			options[option] = true
		}
	}
	return name, options, false
}

func splitJSONTag(tag string) []string {
	parts := make([]string, 1, 3)
	start := 0
	for i := 0; i <= len(tag); i++ {
		if i == len(tag) || tag[i] == ',' {
			parts[len(parts)-1] = tag[start:i]
			if i != len(tag) {
				parts = append(parts, "")
			}
			start = i + 1
		}
	}
	return parts
}
