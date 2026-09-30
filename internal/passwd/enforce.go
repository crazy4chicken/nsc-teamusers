package passwd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"teamusers/internal/store"
)

const (
	pwnedPasswordsRangeURL = "https://api.pwnedpasswords.com/range"
	pwnedPasswordsTimeout  = 5 * time.Second
	maxPwnedResponseBytes  = 2 << 20
)

var (
	pwnedPasswordsHTTPClient = &http.Client{Timeout: pwnedPasswordsTimeout}
	// ErrPolicyRejected indicates the replacement password violates its policy.
	ErrPolicyRejected        = errors.New("password rejected by policy")
)

// ResolvePolicy loads the effective password rules for userID and merges their
// field-level overrides. A failed lookup never weakens the policy.
func ResolvePolicy(ctx context.Context, q store.Q, userID string, now time.Time) (Policy, error) {
	policies, err := store.ListEffectivePasswordPolicies(ctx, q, userID, now)
	if err != nil {
		return Policy{}, fmt.Errorf("resolve password policy for user %q: %w", userID, err)
	}
	rules := make([]PolicyRule, len(policies))
	for i, policy := range policies {
		rules[i] = PolicyRule{
			MinLength:     policy.MinLength,
			RequireLetter: policy.RequireLetter,
			RequireUpper:  policy.RequireUpper,
			RequireLower:  policy.RequireLower,
			RequireDigit:  policy.RequireDigit,
			RequireSymbol: policy.RequireSymbol,
			HistoryCount:  policy.HistoryCount,
			BreachCheck:   policy.BreachCheck,
		}
	}
	return MergePolicy(rules), nil
}

// CheckedSet contains a password hash prepared before the caller's transaction.
// RecordSet persists its history once the credential update is ready to commit.
type CheckedSet struct {
	Hash string

	userID       string
	historyCount int
	historyHashes []string
	currentHash  string
	currentSetAt time.Time
	setAt        time.Time
}

// ErrPasswordStateChanged indicates that password history changed after the
// password was checked and before its history was recorded.
var ErrPasswordStateChanged = errors.New("password state changed during check")

// CheckSet resolves policy, checks history and HIBP, and hashes newPassword.
// Call it before opening the transaction that updates the credential.
func CheckSet(ctx context.Context, q store.Q, userID, newPassword string, pwnedPasswordsEnabled bool, now time.Time) (CheckedSet, error) {
	now = now.UTC()
	policy, err := ResolvePolicy(ctx, q, userID, now)
	if err != nil {
		return CheckedSet{}, err
	}
	if !policy.Validate(newPassword) {
		return CheckedSet{}, ErrPolicyRejected
	}

	checked := CheckedSet{userID: userID, historyCount: policy.HistoryCount, setAt: now}
	if policy.HistoryCount > 0 {
		checked.historyHashes, err = store.ListPasswordHistoryHashes(ctx, q, userID, policy.HistoryCount)
		if err != nil {
			return CheckedSet{}, fmt.Errorf("list password history for user %q: %w", userID, err)
		}
		current, currentErr := store.GetCredential(ctx, q, userID, "password")
		if currentErr != nil && !errors.Is(currentErr, pgx.ErrNoRows) {
			return CheckedSet{}, fmt.Errorf("get current password credential for user %q: %w", userID, currentErr)
		}
		if currentErr == nil {
			checked.currentHash = current.Hash
			checked.currentSetAt = current.CreatedAt
			if current.RotatedAt != nil {
				checked.currentSetAt = *current.RotatedAt
			}
		}
		matches, err := passwordInHistory(ctx, newPassword, checked.historyHashes, checked.currentHash)
		if err != nil {
			return CheckedSet{}, fmt.Errorf("verify password history for user %q: %w", userID, err)
		}
		if matches {
			return CheckedSet{}, ErrPolicyRejected
		}
	}

	if policy.BreachCheck && pwnedPasswordsEnabled {
		breached, err := CheckPwnedPassword(ctx, newPassword)
		if err != nil {
			slog.Warn("HIBP password screening failed; allowing password", "user_id", userID, "error", err)
		} else if breached {
			return CheckedSet{}, ErrPolicyRejected
		}
	}

	checked.Hash, err = Hash(newPassword)
	if err != nil {
		return CheckedSet{}, fmt.Errorf("hash password: %w", err)
	}
	return checked, nil
}

// RecordSet writes the checked password and prior credential into history.
// q must be the caller's transaction so the history and credential commit together.
func RecordSet(ctx context.Context, q store.Q, checked CheckedSet) error {
	if checked.Hash == "" || checked.userID == "" {
		return errors.New("checked password set is incomplete")
	}
	if checked.historyCount == 0 {
		return nil
	}
	if err := store.LockPasswordHistory(ctx, q, checked.userID); err != nil {
		return fmt.Errorf("lock password history for user %q: %w", checked.userID, err)
	}
	historyHashes, err := store.ListPasswordHistoryHashes(ctx, q, checked.userID, checked.historyCount)
	if err != nil {
		return fmt.Errorf("recheck password history for user %q: %w", checked.userID, err)
	}
	if !equalStrings(historyHashes, checked.historyHashes) {
		return ErrPasswordStateChanged
	}
	current, err := store.GetCredential(ctx, q, checked.userID, "password")
	currentHash := ""
	currentSetAt := time.Time{}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("recheck current password credential for user %q: %w", checked.userID, err)
	}
	if err == nil {
		currentHash = current.Hash
		currentSetAt = current.CreatedAt
		if current.RotatedAt != nil {
			currentSetAt = *current.RotatedAt
		}
	}
	if currentHash != checked.currentHash || !currentSetAt.Equal(checked.currentSetAt) {
		return ErrPasswordStateChanged
	}
	if checked.currentHash != "" {
		setAt := checked.currentSetAt
		if setAt.IsZero() {
			setAt = checked.setAt
		}
		if err := store.RecordPasswordHistoryForCount(ctx, q, checked.userID, checked.currentHash, setAt, checked.historyCount); err != nil {
			return fmt.Errorf("record previous password for user %q: %w", checked.userID, err)
		}
	}
	if err := store.RecordPasswordHistoryForCount(ctx, q, checked.userID, checked.Hash, checked.setAt, checked.historyCount); err != nil {
		return fmt.Errorf("record password history for user %q: %w", checked.userID, err)
	}
	return nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

// ValidatePassword reports whether password satisfies policy, does not reuse a
// recent password, and is not known breached when both policy and process
// configuration enable HIBP screening. HIBP errors fail open and are warned.
func ValidatePassword(ctx context.Context, policy Policy, password string, historyHashes []string, currentHash string, pwnedPasswordsEnabled bool) bool {
	return validatePassword(ctx, policy, password, historyHashes, currentHash, pwnedPasswordsEnabled, CheckPwnedPassword)
}

func validatePassword(ctx context.Context, policy Policy, password string, historyHashes []string, currentHash string, pwnedPasswordsEnabled bool, checkPwned func(context.Context, string) (bool, error)) bool {
	if !policy.Validate(password) {
		return false
	}
	if policy.HistoryCount > 0 && PasswordInHistory(password, historyHashes, currentHash) {
		return false
	}
	if !policy.BreachCheck || !pwnedPasswordsEnabled {
		return true
	}
	breached, err := checkPwned(ctx, password)
	if err != nil {
		slog.Warn("HIBP password screening failed; allowing password", "error", err)
		return true
	}
	return !breached
}

// PasswordInHistory reports whether password verifies against any supplied
// history hash or the current credential hash. It fails closed if Argon2
// verification cannot acquire capacity within the shared wait limit.
func PasswordInHistory(password string, historyHashes []string, currentHash string) bool {
	matches, err := passwordInHistory(context.Background(), password, historyHashes, currentHash)
	return err != nil || matches
}

func passwordInHistory(ctx context.Context, password string, historyHashes []string, currentHash string) (bool, error) {
	for _, encoded := range historyHashes {
		matches, err := VerifyContext(ctx, encoded, password)
		if err != nil {
			return false, err
		}
		if matches {
			return true, nil
		}
	}
	if currentHash == "" {
		return false, nil
	}
	for _, encoded := range historyHashes {
		if encoded == currentHash {
			return false, nil
		}
	}
	return VerifyContext(ctx, currentHash, password)
}

// CheckPwnedPassword queries the HIBP range API using a five-character SHA-1
// prefix and reports whether the remaining hash suffix is present.
func CheckPwnedPassword(ctx context.Context, password string) (bool, error) {
	return checkPwnedPassword(ctx, password, pwnedPasswordsHTTPClient, pwnedPasswordsRangeURL)
}

func checkPwnedPassword(ctx context.Context, password string, client *http.Client, endpoint string) (bool, error) {
	digest := sha1.Sum([]byte(password))
	encoded := strings.ToUpper(hex.EncodeToString(digest[:]))
	prefix, suffix := encoded[:5], encoded[5:]
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(endpoint, "/")+"/"+prefix, nil)
	if err != nil {
		return false, fmt.Errorf("create HIBP range request: %w", err)
	}
	request.Header.Set("Add-Padding", "true")
	response, err := client.Do(request)
	if err != nil {
		return false, fmt.Errorf("request HIBP range: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return false, fmt.Errorf("HIBP range API returned %s", response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxPwnedResponseBytes+1))
	if err != nil {
		return false, fmt.Errorf("read HIBP range response: %w", err)
	}
	if len(body) > maxPwnedResponseBytes {
		return false, errors.New("HIBP range response exceeds the size limit")
	}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		candidate, countText, ok := strings.Cut(line, ":")
		if !ok {
			return false, errors.New("HIBP range response contains an invalid entry")
		}
		count, err := strconv.ParseUint(strings.TrimSpace(countText), 10, 64)
		if err != nil {
			return false, errors.New("HIBP range response contains an invalid count")
		}
		if count > 0 && strings.EqualFold(strings.TrimSpace(candidate), suffix) {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("scan HIBP range response: %w", err)
	}
	return false, nil
}
