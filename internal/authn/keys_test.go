package authn

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"teamusers/internal/config"
)

func TestSigningKeyRotationPublishesOverlapUntilRetirement(t *testing.T) {
	keyDir := t.TempDir()
	keys, previousKid, err := loadSigningKeys(keyDir, time.Minute)
	if err != nil {
		t.Fatalf("load initial signing key: %v", err)
	}
	now := time.Date(2026, time.September, 30, 12, 0, 0, 0, time.UTC)
	service := &Service{
		cfg:       config.Config{KeyDir: keyDir, AccessTokenTTL: time.Minute},
		keys:      keys,
		activeKid: previousKid,
		now:       func() time.Time { return now },
	}

	kid, retiredKid, rotatedAt, retireAt, err := service.PrepareSigningKeyRotation()
	if err != nil {
		t.Fatalf("rotate signing key: %v", err)
	}
	activeBytes, err := os.ReadFile(filepath.Join(keyDir, "ACTIVE"))
	if err != nil {
		t.Fatalf("read ACTIVE marker after prepare: %v", err)
	}
	if string(activeBytes) != previousKid+"\n" || service.activeKid != previousKid {
		t.Fatalf("prepare changed active key: marker = %q, in-memory kid = %q", activeBytes, service.activeKid)
	}
	if _, err := os.Stat(signingKeyRetirementPath(keyDir, previousKid)); !os.IsNotExist(err) {
		t.Fatalf("pre-activation retirement marker stat error = %v, want not-exist", err)
	}
	if _, ok := service.keys[kid]; ok {
		t.Fatalf("prepared key %q was added to the active in-memory key set", kid)
	}
	if err := service.ActivateSigningKeyRotation(kid); err != nil {
		t.Fatalf("activate prepared signing key: %v", err)
	}
	if kid == previousKid || retiredKid != previousKid || service.activeKid != kid {
		t.Fatalf("rotation active kid = %q, retired kid = %q, previous kid = %q", kid, retiredKid, previousKid)
	}
	if !rotatedAt.Equal(now) || !retireAt.Equal(rotatedAt.Add(20*time.Minute)) {
		t.Fatalf("rotation times = %s, retire at %s", rotatedAt, retireAt)
	}
	if ids := publicKeyIDs(t, service); !ids[previousKid] || !ids[kid] {
		t.Fatalf("JWKS key IDs during overlap = %v", ids)
	}

	now = retireAt
	if ids := publicKeyIDs(t, service); ids[previousKid] || !ids[kid] {
		t.Fatalf("JWKS key IDs at retirement = %v", ids)
	}
	for _, path := range []string{
		filepath.Join(keyDir, "ed25519-"+previousKid+".pem"),
		filepath.Join(keyDir, "ed25519-"+previousKid+".jwk"),
		signingKeyRetirementPath(keyDir, previousKid),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("retired key file %q was not retained: %v", filepath.Base(path), err)
		}
	}

	loaded, activeKid, err := loadSigningKeys(keyDir, time.Minute)
	if err != nil {
		t.Fatalf("reload signing keys: %v", err)
	}
	if activeKid != kid || !loaded[previousKid].retireAt.Equal(retireAt) {
		t.Fatalf("reloaded active kid = %q, previous retirement = %s", activeKid, loaded[previousKid].retireAt)
	}
}

func publicKeyIDs(t *testing.T, service *Service) map[string]bool {
	t.Helper()
	data, err := json.Marshal(service.publicSet())
	if err != nil {
		t.Fatalf("marshal public key set: %v", err)
	}
	var document struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode public key IDs: %v", err)
	}
	ids := make(map[string]bool, len(document.Keys))
	for _, key := range document.Keys {
		ids[key.Kid] = true
	}
	return ids
}

func TestLoadSigningKeysRetiresUnmarkedNonActiveKey(t *testing.T) {
	keyDir := t.TempDir()
	_, activeKid, err := loadSigningKeys(keyDir, time.Minute)
	if err != nil {
		t.Fatalf("load initial signing key: %v", err)
	}
	activeBefore, err := os.ReadFile(filepath.Join(keyDir, "ACTIVE"))
	if err != nil {
		t.Fatalf("read initial ACTIVE marker: %v", err)
	}
	orphan, private, err := generateSigningKeyMaterial()
	if err != nil {
		t.Fatalf("generate unmarked signing key: %v", err)
	}
	if err := persistSigningKeyFiles(keyDir, orphan, private); err != nil {
		t.Fatalf("persist unmarked signing key: %v", err)
	}

	loadStarted := time.Now().UTC()
	loaded, loadedActiveKid, err := loadSigningKeys(keyDir, time.Minute)
	loadFinished := time.Now().UTC()
	if err != nil {
		t.Fatalf("reload signing keys with unmarked key: %v", err)
	}
	if loadedActiveKid != activeKid {
		t.Fatalf("active kid after recovery = %q, want %q", loadedActiveKid, activeKid)
	}
	retireAt := loaded[orphan.kid].retireAt
	retirementWindow := signingKeyRetirementWindow(time.Minute)
	if retireAt.Before(loadStarted.Add(retirementWindow)) || retireAt.After(loadFinished.Add(retirementWindow)) {
		t.Fatalf("recovered key retirement = %s, want load time plus %s", retireAt, retirementWindow)
	}
	persistedRetireAt, err := loadSigningKeyRetirement(keyDir, orphan.kid)
	if err != nil || !persistedRetireAt.Equal(retireAt) {
		t.Fatalf("persisted recovered retirement = %s, %v; want %s", persistedRetireAt, err, retireAt)
	}
	activeAfter, err := os.ReadFile(filepath.Join(keyDir, "ACTIVE"))
	if err != nil || string(activeAfter) != string(activeBefore) {
		t.Fatalf("recovery changed ACTIVE marker: %q, %v", activeAfter, err)
	}

	reloaded, reloadedActiveKid, err := loadSigningKeys(keyDir, time.Minute)
	if err != nil {
		t.Fatalf("reload recovered signing keys: %v", err)
	}
	if reloadedActiveKid != activeKid || !reloaded[orphan.kid].retireAt.Equal(retireAt) {
		t.Fatalf("reloaded active kid = %q, orphan retirement = %s; want %q and %s", reloadedActiveKid, reloaded[orphan.kid].retireAt, activeKid, retireAt)
	}
}

func TestLoadSigningKeysRemovesRetirementMarkerFromActiveKey(t *testing.T) {
	keyDir := t.TempDir()
	_, activeKid, err := loadSigningKeys(keyDir, time.Minute)
	if err != nil {
		t.Fatalf("load initial signing key: %v", err)
	}
	if err := persistSigningKeyRetirement(keyDir, activeKid, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatalf("persist stale active retirement marker: %v", err)
	}

	keys, loadedActiveKid, err := loadSigningKeys(keyDir, time.Minute)
	if err != nil {
		t.Fatalf("reload signing keys with stale active marker: %v", err)
	}
	if loadedActiveKid != activeKid || !keys[activeKid].retireAt.IsZero() {
		t.Fatalf("loaded active kid = %q, retirement = %s", loadedActiveKid, keys[activeKid].retireAt)
	}
	if _, err := os.Stat(signingKeyRetirementPath(keyDir, activeKid)); !os.IsNotExist(err) {
		t.Fatalf("stale active retirement marker stat error = %v, want not-exist", err)
	}
}

func TestSigningKeyRetirementWindowUsesLongestTokenLifetime(t *testing.T) {
	tests := []struct {
		name           string
		accessTokenTTL time.Duration
		want           time.Duration
	}{
		{name: "password-change lifetime exceeds access TTL", accessTokenTTL: time.Minute, want: 20 * time.Minute},
		{name: "access TTL exceeds fixed token lifetimes", accessTokenTTL: 30 * time.Minute, want: time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := signingKeyRetirementWindow(tt.accessTokenTTL); got != tt.want {
				t.Fatalf("signing key retirement window = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestPrepareSigningKeyRotationPersistsMissingActiveMarker(t *testing.T) {
	keyDir := t.TempDir()
	keys, activeKid, err := loadSigningKeys(keyDir, time.Minute)
	if err != nil {
		t.Fatalf("load initial signing key: %v", err)
	}
	if err := os.Remove(filepath.Join(keyDir, "ACTIVE")); err != nil {
		t.Fatalf("remove ACTIVE marker: %v", err)
	}
	service := &Service{
		cfg:       config.Config{KeyDir: keyDir, AccessTokenTTL: time.Minute},
		keys:      keys,
		activeKid: activeKid,
	}
	kid, _, _, _, err := service.PrepareSigningKeyRotation()
	if err != nil {
		t.Fatalf("prepare signing key rotation: %v", err)
	}
	t.Cleanup(func() {
		if err := service.RollbackSigningKeyRotation(kid); err != nil {
			t.Errorf("remove prepared signing key: %v", err)
		}
	})

	activeBytes, err := os.ReadFile(filepath.Join(keyDir, "ACTIVE"))
	if err != nil {
		t.Fatalf("read restored ACTIVE marker: %v", err)
	}
	if string(activeBytes) != activeKid+"\n" {
		t.Fatalf("ACTIVE marker after prepare = %q, want current active kid %q", activeBytes, activeKid)
	}
}

func TestPrepareSigningKeyRotationRefusesMissingActiveMarkerWithoutCurrentKid(t *testing.T) {
	keyDir := t.TempDir()
	service := &Service{
		cfg:  config.Config{KeyDir: keyDir, AccessTokenTTL: time.Minute},
		keys: map[string]signingKey{},
	}
	_, _, _, _, err := service.PrepareSigningKeyRotation()
	if err == nil || err.Error() != "cannot determine current active signing key while ACTIVE marker is missing" {
		t.Fatalf("prepare error = %v, want explicit missing ACTIVE/current key error", err)
	}
	if _, err := os.Stat(filepath.Join(keyDir, "ACTIVE")); !os.IsNotExist(err) {
		t.Fatalf("ACTIVE marker was created without a current kid: %v", err)
	}
}
