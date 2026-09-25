package authn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"teamusers/internal/httpapi"
	"teamusers/internal/store"
)

var errTOTPAlreadyEnabled = errors.New("TOTP is already enabled")
var errBackupCodeInvalid = errors.New("backup code is invalid")

const backupCodeAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

// MeRoutes returns the authenticated self-service routes owned by Service.
func (s *Service) MeRoutes() chi.Router {
	return httpapi.NewMeRouter(s.Middleware(), httpapi.MeHandlers{
		Profile:                   s.profile,
		PatchProfile:              s.patchProfile,
		ChangePassword:            s.changePassword,
		ListSessions:              s.listOwnSessions,
		DeleteSession:             s.deleteOwnSession,
		EnrollTOTP:                s.enrollTOTP,
		ConfirmTOTP:               s.confirmTOTP,
		DeleteTOTP:                s.deleteTOTP,
		BeginPasskeyRegistration:  s.beginPasskeyRegistration,
		FinishPasskeyRegistration: s.finishPasskeyRegistration,
		ListPasskeys:              s.listPasskeys,
		DeletePasskey:             s.deletePasskey,
	})
}

type totpConfirmRequest struct {
	Code string `json:"code"`
}

type totpResponse struct {
	Secret     string `json:"secret"`
	OTPAuthURL string `json:"otpauth_url"`
}

type backupCodesResponse struct {
	BackupCodes []string `json:"backup_codes"`
}

func (s *Service) enrollTOTP(w http.ResponseWriter, r *http.Request) {
	subject, ok := httpapi.SubjectFrom(r.Context())
	if !ok || subject.UserID == "" {
		writeUnauthorized(w, r)
		return
	}
	user, err := store.GetUser(r.Context(), s.q, subject.UserID)
	if err != nil {
		httpapi.WriteStoreProblem(w, r, err)
		return
	}
	secret, err := GenerateSecret()
	if err != nil {
		writeInternal(w, r)
		return
	}
	err = store.WithAdminTx(r.Context(), s.q, func(ctx context.Context, tx store.Tx) error {
		if _, err := store.GetCredential(ctx, tx, user.ID, "totp"); err == nil {
			return errTOTPAlreadyEnabled
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		pending := store.Credential{UserID: user.ID, Kind: "totp_pending", Hash: secret}
		if _, err := store.UpdateCredential(ctx, tx, pending); err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if _, err := store.CreateCredential(ctx, tx, pending); err != nil {
				return err
			}
		}
		return s.appendAuthAudit(ctx, tx, "auth.totp.enrolled", user.ID, user.ID)
	})
	if errors.Is(err, errTOTPAlreadyEnabled) {
		writeAuthProblem(w, r, http.StatusConflict, "totp_already_enabled")
		return
	}
	if err != nil {
		httpapi.WriteStoreProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, totpResponse{
		Secret:     secret,
		OTPAuthURL: fmt.Sprintf("otpauth://totp/teamusers:%s?secret=%s&issuer=teamusers", url.PathEscape(user.Username), secret),
	})
}

func (s *Service) confirmTOTP(w http.ResponseWriter, r *http.Request) {
	subject, ok := httpapi.SubjectFrom(r.Context())
	if !ok || subject.UserID == "" {
		writeUnauthorized(w, r)
		return
	}
	var request totpConfirmRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	code := strings.TrimSpace(request.Code)
	if code == "" {
		writeUnauthorized(w, r)
		return
	}
	user, err := store.GetUser(r.Context(), s.q, subject.UserID)
	if err != nil {
		httpapi.WriteStoreProblem(w, r, err)
		return
	}
	pending, err := store.GetCredential(r.Context(), s.q, user.ID, "totp_pending")
	if errors.Is(err, pgx.ErrNoRows) {
		writeUnauthorized(w, r)
		return
	}
	if err != nil {
		httpapi.WriteStoreProblem(w, r, err)
		return
	}
	if !ValidateCode(pending.Hash, code, s.now()) {
		writeUnauthorized(w, r)
		return
	}
	codes := make([]string, 0, 10)
	digests := make([]string, 0, 10)
	seen := make(map[string]struct{}, 10)
	for len(codes) < 10 {
		displayCode, canonicalCode, err := newBackupCode()
		if err != nil {
			writeInternal(w, r)
			return
		}
		if _, exists := seen[canonicalCode]; exists {
			continue
		}
		seen[canonicalCode] = struct{}{}
		digest, ok := backupCodeDigest(canonicalCode)
		if !ok {
			writeInternal(w, r)
			return
		}
		codes = append(codes, displayCode)
		digests = append(digests, digest)
	}
	encodedDigests, err := json.Marshal(digests)
	if err != nil {
		writeInternal(w, r)
		return
	}
	err = store.WithAdminTx(r.Context(), s.q, func(ctx context.Context, tx store.Tx) error {
		if _, err := store.GetCredential(ctx, tx, user.ID, "totp"); err == nil {
			return errTOTPAlreadyEnabled
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if _, err := store.ActivateTOTPCredential(ctx, tx, user.ID); err != nil {
			return err
		}
		if _, err := store.CreateCredential(ctx, tx, store.Credential{
			UserID: user.ID,
			Kind:   "backup_codes",
			Hash:   string(encodedDigests),
		}); err != nil {
			return err
		}
		return s.appendAuthAudit(ctx, tx, "auth.totp.confirmed", user.ID, user.ID)
	})
	if errors.Is(err, errTOTPAlreadyEnabled) {
		writeAuthProblem(w, r, http.StatusConflict, "totp_already_enabled")
		return
	}
	if err != nil {
		httpapi.WriteStoreProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, backupCodesResponse{BackupCodes: codes})
}

func (s *Service) deleteTOTP(w http.ResponseWriter, r *http.Request) {
	subject, ok := httpapi.SubjectFrom(r.Context())
	if !ok || subject.UserID == "" {
		writeUnauthorized(w, r)
		return
	}
	var request totpConfirmRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	code := strings.TrimSpace(request.Code)
	if code == "" {
		writeUnauthorized(w, r)
		return
	}
	user, err := store.GetUser(r.Context(), s.q, subject.UserID)
	if err != nil {
		httpapi.WriteStoreProblem(w, r, err)
		return
	}
	active, err := store.GetCredential(r.Context(), s.q, user.ID, "totp")
	if errors.Is(err, pgx.ErrNoRows) {
		writeUnauthorized(w, r)
		return
	}
	if err != nil {
		httpapi.WriteStoreProblem(w, r, err)
		return
	}
	validTOTP := ValidateCode(active.Hash, code, s.now())
	backupDigest, validBackup := backupCodeDigest(code)
	if !validTOTP && !validBackup {
		writeUnauthorized(w, r)
		return
	}
	err = store.WithAdminTx(r.Context(), s.q, func(ctx context.Context, tx store.Tx) error {
		if !validTOTP {
			consumed, err := store.ConsumeBackupCredential(ctx, tx, user.ID, backupDigest)
			if err != nil {
				return err
			}
			if !consumed {
				return errBackupCodeInvalid
			}
		}
		if err := store.DeleteCredential(ctx, tx, user.ID, "totp"); err != nil {
			return err
		}
		if err := store.DeleteCredential(ctx, tx, user.ID, "totp_pending"); err != nil {
			return err
		}
		if err := store.DeleteCredential(ctx, tx, user.ID, "backup_codes"); err != nil {
			return err
		}
		return s.appendAuthAudit(ctx, tx, "auth.totp.deleted", user.ID, user.ID)
	})
	if errors.Is(err, errBackupCodeInvalid) {
		writeUnauthorized(w, r)
		return
	}
	if err != nil {
		httpapi.WriteStoreProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func newBackupCode() (display, canonical string, err error) {
	var code [16]byte
	var random [16]byte
	filled := 0
	limit := byte(256 - (256 % len(backupCodeAlphabet)))
	for filled < len(code) {
		if _, err := rand.Read(random[:]); err != nil {
			return "", "", err
		}
		for _, value := range random {
			if value >= limit {
				continue
			}
			code[filled] = backupCodeAlphabet[int(value)%len(backupCodeAlphabet)]
			filled++
			if filled == len(code) {
				break
			}
		}
	}
	canonical = string(code[:])
	display = canonical[:4] + "-" + canonical[4:8] + "-" + canonical[8:12] + "-" + canonical[12:]
	return display, canonical, nil
}

func backupCodeDigest(code string) (string, bool) {
	canonical := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	if len(canonical) != 16 {
		return "", false
	}
	for index := 0; index < len(canonical); index++ {
		value := canonical[index]
		if (value < 'a' || value > 'z') && (value < '0' || value > '9') {
			return "", false
		}
	}
	digest := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(digest[:]), true
}
