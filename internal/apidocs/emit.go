package apidocs

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Emit writes a deterministic OpenAPI 3.1 document for operations.
func Emit(ops []Operation, w io.Writer) error {
	if w == nil {
		return fmt.Errorf("OpenAPI writer must not be nil")
	}
	tags := make(map[string]struct{})
	for _, operation := range ops {
		if operation.Tag != "" {
			tags[operation.Tag] = struct{}{}
		}
	}
	tagNames := make([]string, 0, len(tags))
	for tag := range tags {
		tagNames = append(tagNames, tag)
	}
	sort.Strings(tagNames)
	tagValues := make([]any, len(tagNames))
	for i, tag := range tagNames {
		tagValues[i] = tag
	}

	paths := make(map[string][]Operation)
	for _, operation := range ops {
		paths[operation.Path] = append(paths[operation.Path], operation)
	}
	pathNames := make([]string, 0, len(paths))
	for path := range paths {
		pathNames = append(pathNames, path)
	}
	sort.Strings(pathNames)
	pathEntries := make([]yamlEntry, 0, len(pathNames))
	for _, path := range pathNames {
		operations := append([]Operation(nil), paths[path]...)
		sort.SliceStable(operations, func(i, j int) bool {
			return strings.ToLower(operations[i].Method) < strings.ToLower(operations[j].Method)
		})
		operationEntries := make([]yamlEntry, 0, len(operations))
		for _, operation := range operations {
			operationEntries = append(operationEntries, yamlEntry{
				key:   strings.ToLower(operation.Method),
				value: operationYAML(operation),
			})
		}
		pathEntries = append(pathEntries, yamlEntry{key: path, value: orderedMap(operationEntries)})
	}

	doc := orderedMap{
		{key: "openapi", value: "3.1.0"},
		{key: "info", value: orderedMap{
			{key: "title", value: "Teamusers API"},
			{key: "version", value: "1.0.0"},
		}},
		{key: "servers", value: []any{orderedMap{
			{key: "url", value: "http://localhost:8080"},
			{key: "description", value: "Nekostick /iam Strip forwarding"},
		}}},
		{key: "tags", value: tagValues},
		{key: "paths", value: orderedMap(pathEntries)},
		{key: "components", value: orderedMap{
			{key: "schemas", value: orderedMap{{key: "ProblemDetails", value: problemDetailsSchema()}}},
			{key: "securitySchemes", value: orderedMap{{key: "bearerAuth", value: orderedMap{
				{key: "type", value: "http"},
				{key: "scheme", value: "bearer"},
				{key: "bearerFormat", value: "EdDSA JWT"},
			}}}},
		}},
	}

	node := yamlNode(doc)
	encoder := yaml.NewEncoder(w)
	encoder.SetIndent(2)
	if err := encoder.Encode(node); err != nil {
		return err
	}
	return encoder.Close()
}

type yamlEntry struct {
	key   string
	value any
}

type orderedMap []yamlEntry

func operationYAML(operation Operation) orderedMap {
	entries := make([]yamlEntry, 0, 7)
	if operation.Tag != "" {
		entries = append(entries, yamlEntry{key: "tags", value: []any{operation.Tag}})
	}
	if operation.Summary != "" {
		entries = append(entries, yamlEntry{key: "summary", value: operation.Summary})
	}
	if operation.Description != "" {
		entries = append(entries, yamlEntry{key: "description", value: operation.Description})
	}
	if parameters := pathParameters(operation.Path); len(parameters) > 0 {
		values := make([]any, len(parameters))
		for i, parameter := range parameters {
			values[i] = orderedMap{
				{key: "name", value: parameter},
				{key: "in", value: "path"},
				{key: "required", value: true},
				{key: "schema", value: orderedMap{{key: "type", value: "string"}}},
			}
		}
		entries = append(entries, yamlEntry{key: "parameters", value: values})
	}
	if operation.Request != nil {
		content := orderedMap{{key: "schema", value: SchemaOf(operation.Request)}}
		if operation.RequestExample != nil {
			content = append(content, yamlEntry{key: "example", value: operation.RequestExample})
		}
		entries = append(entries, yamlEntry{key: "requestBody", value: orderedMap{
			{key: "required", value: true},
			{key: "content", value: orderedMap{{key: "application/json", value: content}}},
		}})
	}

	responses := make([]yamlEntry, 0, len(operation.Errors)+1)
	successStatus := 200
	if operation.Response == nil && operation.ResponseExample == nil {
		successStatus = 204
	}
	success := orderedMap{{key: "description", value: successDescription(successStatus)}}
	if operation.Response != nil || operation.ResponseExample != nil {
		content := orderedMap{}
		if operation.Response != nil {
			content = append(content, yamlEntry{key: "schema", value: SchemaOf(operation.Response)})
		}
		if operation.ResponseExample != nil {
			content = append(content, yamlEntry{key: "example", value: operation.ResponseExample})
		}
		success = append(success, yamlEntry{key: "content", value: orderedMap{{key: "application/json", value: content}}})
	}
	responses = append(responses, yamlEntry{key: strconv.Itoa(successStatus), value: success})
	// Group error variants by status: a YAML mapping cannot hold duplicate
	// keys, so same-status variants merge into one response. A single variant
	// keeps the plain "example"; multiple variants become named "examples".
	errorsByStatus := make(map[int][]ErrorDoc)
	statusOrder := make([]int, 0, len(operation.Errors))
	for _, problem := range operation.Errors {
		if _, seen := errorsByStatus[problem.Status]; !seen {
			statusOrder = append(statusOrder, problem.Status)
		}
		errorsByStatus[problem.Status] = append(errorsByStatus[problem.Status], problem)
	}
	for _, statusCode := range statusOrder {
		status := strconv.Itoa(statusCode)
		variants := errorsByStatus[statusCode]
		content := orderedMap{
			{key: "schema", value: orderedMap{{key: "$ref", value: "#/components/schemas/ProblemDetails"}}},
		}
		description := ""
		if len(variants) == 1 {
			title := variants[0].Title
			if title == "" {
				title = httpStatusTitle(statusCode)
			}
			description = title
			content = append(content, yamlEntry{key: "example", value: problemExample(statusCode, title, variants[0].Code)})
		} else {
			examples := orderedMap{}
			titles := make([]string, 0, len(variants))
			for i, variant := range variants {
				title := variant.Title
				if title == "" {
					title = httpStatusTitle(statusCode)
				}
				titles = append(titles, title)
				name := variant.Code
				if name == "" {
					name = "case-" + strconv.Itoa(i+1)
				}
				examples = append(examples, yamlEntry{key: name, value: orderedMap{
					{key: "value", value: problemExample(statusCode, title, variant.Code)},
				}})
			}
			description = strings.Join(titles, "; ")
			content = append(content, yamlEntry{key: "examples", value: examples})
		}
		responses = append(responses, yamlEntry{key: status, value: orderedMap{
			{key: "description", value: description},
			{key: "content", value: orderedMap{{key: "application/problem+json", value: content}}},
		}})
	}
	sort.SliceStable(responses, func(i, j int) bool {
		left, _ := strconv.Atoi(responses[i].key)
		right, _ := strconv.Atoi(responses[j].key)
		return left < right
	})
	entries = append(entries, yamlEntry{key: "responses", value: orderedMap(responses)})

	security := []any{}
	if operation.Security != "" {
		security = []any{orderedMap{{key: "bearerAuth", value: []any{}}}}
	}
	entries = append(entries, yamlEntry{key: "security", value: security})
	return orderedMap(entries)
}

func problemDetailsSchema() orderedMap {
	return orderedMap{
		{key: "type", value: "object"},
		{key: "properties", value: orderedMap{
			{key: "type", value: orderedMap{{key: "type", value: "string"}}},
			{key: "title", value: orderedMap{{key: "type", value: "string"}}},
			{key: "status", value: orderedMap{{key: "type", value: "integer"}}},
			{key: "detail", value: orderedMap{{key: "type", value: "string"}}},
			{key: "instance", value: orderedMap{{key: "type", value: "string"}}},
		}},
		{key: "required", value: []any{"type", "title", "status"}},
	}
}
func problemExample(status int, title, detail string) orderedMap {
	return orderedMap{
		{key: "type", value: "about:blank"},
		{key: "title", value: title},
		{key: "status", value: status},
		{key: "detail", value: detail},
	}
}

func successDescription(status int) string {
	if status == 204 {
		return "No Content"
	}
	return "Successful response"
}

func httpStatusTitle(status int) string {
	if title := http.StatusText(status); title != "" {
		return title
	}
	return "Error"
}

func pathParameters(path string) []string {
	parameters := make([]string, 0)
	for index := 0; index < len(path); index++ {
		if path[index] != '{' {
			continue
		}
		end := strings.IndexByte(path[index+1:], '}')
		if end < 0 {
			break
		}
		end += index + 1
		name := path[index+1 : end]
		if name != "" {
			parameters = append(parameters, name)
		}
		index = end
	}
	return parameters
}

func yamlNode(value any) *yaml.Node {
	if node, ok := value.(*yaml.Node); ok {
		return node
	}
	switch value := value.(type) {
	case orderedMap:
		node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		for _, entry := range value {
			node.Content = append(node.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: entry.key},
				yamlNode(entry.value))
		}
		return node
	case map[string]any:
		entries := make([]yamlEntry, 0, len(value))
		for key, item := range value {
			entries = append(entries, yamlEntry{key: key, value: item})
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].key < entries[j].key })
		return yamlNode(orderedMap(entries))
	case []any:
		node := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for _, item := range value {
			node.Content = append(node.Content, yamlNode(item))
		}
		return node
	case []string:
		items := make([]any, len(value))
		for i := range value {
			items[i] = value[i]
		}
		return yamlNode(items)
	case nil:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}
	case string:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
	case bool:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: strconv.FormatBool(value)}
	case int:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(value)}
	case int8, int16, int32, int64:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.FormatInt(reflect.ValueOf(value).Int(), 10)}
	case uint, uint8, uint16, uint32, uint64:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.FormatUint(reflect.ValueOf(value).Uint(), 10)}
	case float32, float64:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!float", Value: strconv.FormatFloat(reflect.ValueOf(value).Float(), 'g', -1, 64)}
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: fmt.Sprint(value)}
		}
		var generic any
		if err := json.Unmarshal(encoded, &generic); err != nil {
			return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: string(encoded)}
		}
		return yamlNode(generic)
	}
}
