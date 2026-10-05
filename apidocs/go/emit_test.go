package apidocs

import "testing"

func TestOperationSuccessStatus(t *testing.T) {
	tests := []struct {
		name string
		op   Operation
		want string
	}{
		{
			name: "explicit status overrides response body default",
			op: Operation{
				Response:      struct{}{},
				SuccessStatus: 201,
			},
			want: "201",
		},
		{
			name: "explicit status overrides empty response default",
			op:   Operation{SuccessStatus: 201},
			want: "201",
		},
		{
			name: "response body default remains 200",
			op:   Operation{Response: struct{}{}},
			want: "200",
		},
		{
			name: "empty response default remains 204",
			op:   Operation{},
			want: "204",
		},
		{
			name: "explicit no content remains 204",
			op:   Operation{SuccessStatus: 204},
			want: "204",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var responses orderedMap
			for _, entry := range operationYAML(test.op, EmitOptions{}) {
				if entry.key != "responses" {
					continue
				}
				var ok bool
				responses, ok = entry.value.(orderedMap)
				if !ok {
					t.Fatalf("responses have type %T, want orderedMap", entry.value)
				}
				break
			}
			if len(responses) != 1 {
				t.Fatalf("got %d responses, want one", len(responses))
			}
			if got := responses[0].key; got != test.want {
				t.Errorf("success status = %s, want %s", got, test.want)
			}
		})
	}
}
