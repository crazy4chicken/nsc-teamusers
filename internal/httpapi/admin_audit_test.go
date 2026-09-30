package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuditExportCSVCellPrefixesFormulaCharacters(t *testing.T) {
	for _, prefix := range []byte{'=', '+', '-', '@', '\t', '\r'} {
		value := string([]byte{prefix}) + "1+1"
		if got, want := auditExportCSVCell(value), "'"+value; got != want {
			t.Errorf("auditExportCSVCell(%q) = %q, want %q", value, got, want)
		}
	}
	for _, value := range []string{"", "plain text", "  =1", "1+1"} {
		if got := auditExportCSVCell(value); got != value {
			t.Errorf("auditExportCSVCell(%q) = %q, want unchanged", value, got)
		}
	}
}

func TestRequestTimeoutMiddlewareUsesLongAuditExportDeadline(t *testing.T) {
	for _, test := range []struct {
		name   string
		method string
		path   string
		want   time.Duration
	}{
		{name: "audit export", method: http.MethodGet, path: "/audit/export", want: 10 * time.Minute},
		{name: "other path", method: http.MethodGet, path: "/audit", want: 30 * time.Second},
		{name: "other method", method: http.MethodPost, path: "/audit/export", want: 30 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			started := time.Now()
			var deadline time.Time
			handler := requestTimeoutMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var ok bool
				deadline, ok = r.Context().Deadline()
				if !ok {
					t.Error("request context has no deadline")
					return
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(test.method, test.path, nil))
			if response.Code != http.StatusNoContent {
				t.Fatalf("response status = %d, want %d", response.Code, http.StatusNoContent)
			}
			if got := deadline.Sub(started); got < test.want-time.Second || got > test.want+time.Second {
				t.Fatalf("request deadline = %s from start, want %s", got, test.want)
			}
		})
	}
}
