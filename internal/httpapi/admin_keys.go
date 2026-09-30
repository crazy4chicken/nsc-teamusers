package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"teamusers/internal/store"
)

type keyRotator interface {
	PrepareSigningKeyRotation() (kid, previousKid string, rotatedAt, retireAt time.Time, err error)
	ActivateSigningKeyRotation(kid string) error
	RollbackSigningKeyRotation(kid string) error
}

type keyRotationResponse struct {
	Kid      string    `json:"kid"`
	RetireAt time.Time `json:"retire_at"`
	Warning  string    `json:"warning,omitempty"`
}

type keyRotatedEvent struct {
	Kid string    `json:"kid"`
	At  time.Time `json:"at"`
}

func (h *adminHandler) rotateSigningKey(w http.ResponseWriter, r *http.Request) {
	if h.keyRotator == nil {
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error", "signing key rotation is unavailable")
		return
	}

	kid, previousKid, rotatedAt, retireAt, err := h.keyRotator.PrepareSigningKeyRotation()
	if err != nil {
		if err.Error() == "signing key rotation already in progress" {
			WriteProblem(w, r, http.StatusConflict, "Conflict", "a signing key rotation is already in progress")
		} else {
			WriteStoreProblem(w, r, err)
		}
		return
	}
	prepared := true
	defer func() {
		if prepared {
			if err := h.keyRotator.RollbackSigningKeyRotation(kid); err != nil {
				slog.Error("failed to remove prepared signing key after rotation transaction failed", "kid", kid, "error", err)
			}
		}
	}()
	commitOutcomeAmbiguous := false

	err = h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		before := map[string]string{"kid": previousKid}
		after := map[string]any{"kid": kid, "retire_at": retireAt}
		if _, err := h.audit.Append(ctx, tx, h.auditEntry(r, nil, "key.rotated", kid, before, after)); err != nil {
			return err
		}
		if err := appendOutboxPayload(ctx, tx, "key.rotated", keyRotatedEvent{Kid: kid, At: rotatedAt}); err != nil {
			return err
		}
		commitOutcomeAmbiguous = true
		return nil
	})
	if err != nil {
		if commitOutcomeAmbiguous {
			prepared = false
			slog.Error("signing key rotation commit outcome was ambiguous; prepared files were retained", "kid", kid, "error", err)
		}
		WriteStoreProblem(w, r, err)
		return
	}
	prepared = false

	response := keyRotationResponse{Kid: kid, RetireAt: retireAt}
	if err := h.keyRotator.ActivateSigningKeyRotation(kid); err != nil {
		response.Warning = "rotation was committed, but this process could not activate the new signing key"
		slog.Error("signing key rotation committed but activation failed", "kid", kid, "previous_kid", previousKid, "error", err)
	}
	writeJSON(w, http.StatusOK, response)
}
