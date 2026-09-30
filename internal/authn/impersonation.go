package authn

import (
	"context"
	"errors"
	"time"

	"teamusers/internal/store"
)

const maxImpersonationTokenTTL = 15 * time.Minute

// MintImpersonationToken signs a short-lived user token without creating a refresh session.
// The returned denied flag indicates that the target is not eligible for impersonation.
func (s *Service) MintImpersonationToken(ctx context.Context, target store.User, actorID string, ttl time.Duration) (string, time.Time, string, bool, error) {
	if s == nil {
		return "", time.Time{}, "", false, errors.New("nil authentication service")
	}
	if target.ID == "" || actorID == "" || ttl <= 0 || ttl > maxImpersonationTokenTTL {
		return "", time.Time{}, "", false, errors.New("invalid impersonation token request")
	}
	if target.ID == actorID || target.Status != "active" {
		return "", time.Time{}, "", true, nil
	}

	currentTarget, err := store.GetUser(ctx, s.q, target.ID)
	if err != nil {
		return "", time.Time{}, "", false, err
	}
	if currentTarget.Status != "active" {
		return "", time.Time{}, "", true, nil
	}
	hasIAMPermission, err := store.UserHasIAMPermission(ctx, s.q, target.ID)
	if err != nil {
		return "", time.Time{}, "", false, err
	}
	if hasIAMPermission {
		return "", time.Time{}, "", true, nil
	}

	target.PermVer = currentTarget.PermVer
	team, err := store.GetUserTeamID(ctx, s.q, target.ID)
	if err != nil {
		return "", time.Time{}, "", false, err
	}
	issuedAt := s.now().UTC().Truncate(time.Second)
	expiresAt := issuedAt.Add(ttl)
	jti := store.NewID()
	accessToken, err := s.signAccessTokenAt(target, team, "user", 0, []string{"impersonation"}, issuedAt, expiresAt, map[string]interface{}{
		"act": map[string]string{"sub": actorID},
		"imp": true,
		"jti": jti,
	})
	if err != nil {
		return "", time.Time{}, "", false, err
	}
	return accessToken, expiresAt, jti, false, nil
}

