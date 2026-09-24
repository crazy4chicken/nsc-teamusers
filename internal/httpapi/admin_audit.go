package httpapi

import (
	"net/http"
	"strings"

	"teamusers/internal/store"
)

func (h *adminHandler) listAudit(w http.ResponseWriter, r *http.Request) {
	cursor, limit, ok := parseAuditPage(w, r)
	if !ok {
		return
	}
	var teamID *string
	if value := strings.TrimSpace(r.URL.Query().Get("team_id")); value != "" {
		teamID = &value
	}
	entries, next, err := store.ListAuditLog(r.Context(), h.q, teamID, cursor, limit)
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	writeAuditItems(w, entries, next)
}
