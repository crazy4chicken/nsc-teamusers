package httpapi

import (
	"encoding/csv"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"teamusers/internal/store"
)

func (h *adminHandler) listAudit(w http.ResponseWriter, r *http.Request) {
	cursor, limit, ok := parseAuditPage(w, r)
	if !ok {
		return
	}
	entries, next, err := store.ListAuditLog(r.Context(), h.q, auditTeamFilter(r), cursor, limit)
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	writeAuditItems(w, entries, next)
}

func (h *adminHandler) exportAudit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	format := strings.TrimSpace(r.URL.Query().Get("format"))
	if format == "" {
		format = "jsonl"
	}
	var contentType, extension string
	switch format {
	case "jsonl":
		contentType, extension = "application/x-ndjson; charset=utf-8", "jsonl"
	case "csv":
		contentType, extension = "text/csv; charset=utf-8", "csv"
	default:
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "format must be jsonl or csv")
		return
	}
	responseController := http.NewResponseController(w)

	filename := "audit-" + time.Now().UTC().Format("2006-01-02") + "." + extension
	var started bool
	csvWriter := csv.NewWriter(w)
	jsonWriter := json.NewEncoder(w)
	start := func() error {
		if started {
			return nil
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		started = true
		if format == "csv" {
			if err := csvWriter.Write([]string{"id", "team_id", "actor_id", "action", "target", "diff", "request_id", "at"}); err != nil {
				return err
			}
			_ = responseController.SetWriteDeadline(time.Now().Add(30 * time.Second))
			csvWriter.Flush()
			if err := csvWriter.Error(); err != nil {
				return err
			}
			flushAuditExport(w)
		}
		return nil
	}

	err := store.StreamAuditLog(r.Context(), h.q, auditTeamFilter(r), func(entry store.AuditEntry) error {
		if err := start(); err != nil {
			return err
		}
		if format == "jsonl" {
			_ = responseController.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if err := jsonWriter.Encode(entry); err != nil {
				return err
			}
			flushAuditExport(w)
			return nil
		}
		_ = responseController.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if err := csvWriter.Write([]string{
			auditExportCSVCell(strconv.FormatInt(entry.ID, 10)),
			auditExportCSVCell(auditExportString(entry.TeamID)),
			auditExportCSVCell(auditExportString(entry.ActorID)),
			auditExportCSVCell(entry.Action),
			auditExportCSVCell(entry.Target),
			auditExportCSVCell(string(entry.Diff)),
			auditExportCSVCell(auditExportString(entry.RequestID)),
			auditExportCSVCell(entry.At.UTC().Format(time.RFC3339Nano)),
		}); err != nil {
			return err
		}
		csvWriter.Flush()
		if err := csvWriter.Error(); err != nil {
			return err
		}
		flushAuditExport(w)
		return nil
	})
	if err != nil {
		if !started {
			WriteStoreProblem(w, r, err)
		} else {
			slog.Error("stream audit export failed", "error", err)
		}
		return
	}
	if err := start(); err != nil {
		slog.Error("stream audit export failed", "error", err)
	}
}

func auditTeamFilter(r *http.Request) *string {
	if value := strings.TrimSpace(r.URL.Query().Get("team_id")); value != "" {
		return &value
	}
	return nil
}

func auditExportString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func auditExportCSVCell(value string) string {
	if value == "" {
		return value
	}
	switch value[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + value
	default:
		return value
	}
}

func flushAuditExport(w http.ResponseWriter) {
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}
