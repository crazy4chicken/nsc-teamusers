package authn

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"teamusers/internal/store"
)

var errSigningKeyRotationInProgress = errors.New("signing key rotation already in progress")

type signingKey struct {
	kid      string
	private  jwk.Key
	public   jwk.Key
	retireAt time.Time
}

func loadSigningKeys(dir string, accessTokenTTL time.Duration) (map[string]signingKey, string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, "", fmt.Errorf("create key directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, "", fmt.Errorf("secure key directory: %w", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, "", fmt.Errorf("read key directory: %w", err)
	}
	loadTime := time.Now().UTC()
	keys := make(map[string]signingKey)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "ed25519-") || !strings.HasSuffix(entry.Name(), ".pem") {
			continue
		}
		kid := strings.TrimSuffix(strings.TrimPrefix(entry.Name(), "ed25519-"), ".pem")
		if kid == "" {
			return nil, "", fmt.Errorf("invalid signing key filename %q", entry.Name())
		}
		privatePath := filepath.Join(dir, entry.Name())
		privateBytes, err := os.ReadFile(privatePath)
		if err != nil {
			return nil, "", fmt.Errorf("read signing key %q: %w", entry.Name(), err)
		}
		if err := os.Chmod(privatePath, 0o600); err != nil {
			return nil, "", fmt.Errorf("secure signing key %q: %w", entry.Name(), err)
		}
		private, err := parsePrivateKey(privateBytes)
		if err != nil {
			return nil, "", fmt.Errorf("parse signing key %q: %w", entry.Name(), err)
		}
		key, err := makeSigningKey(kid, private)
		if err != nil {
			return nil, "", err
		}
		keys[kid] = key
		if err := persistPublicKey(dir, key.kid, key.public); err != nil {
			return nil, "", err
		}
	}
	if len(keys) == 0 {
		key, err := generateSigningKey(dir)
		if err != nil {
			return nil, "", err
		}
		keys[key.kid] = key
		slog.Warn("no signing keys found; generated an EdDSA signing key", "key_dir", dir, "kid", key.kid)
	}

	kids := make([]string, 0, len(keys))
	for kid := range keys {
		kids = append(kids, kid)
	}
	sort.Strings(kids)
	activeKid := kids[len(kids)-1]
	activePath := filepath.Join(dir, "ACTIVE")
	activeBytes, err := os.ReadFile(activePath)
	switch {
	case err == nil:
		activeKid = strings.TrimSpace(string(activeBytes))
		if activeKid == "" {
			return nil, "", errors.New("ACTIVE marker is empty")
		}
		if _, ok := keys[activeKid]; !ok {
			return nil, "", fmt.Errorf("ACTIVE marker refers to unavailable signing key %q", activeKid)
		}
	case errors.Is(err, os.ErrNotExist):
		slog.Warn("ACTIVE signing key marker is missing; using newest key", "key_dir", dir, "kid", activeKid)
	default:
		return nil, "", fmt.Errorf("read ACTIVE signing key marker: %w", err)
	}

	retirementWindow := signingKeyRetirementWindow(accessTokenTTL)
	for kid, key := range keys {
		retirementPath := signingKeyRetirementPath(dir, kid)
		if kid == activeKid {
			if err := os.Remove(retirementPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, "", fmt.Errorf("remove ACTIVE signing key retirement marker: %w", err)
			}
			key.retireAt = time.Time{}
			keys[kid] = key
			continue
		}
		key.retireAt, err = loadSigningKeyRetirement(dir, kid)
		if err != nil {
			return nil, "", fmt.Errorf("read signing key retirement %q: %w", kid, err)
		}
		if key.retireAt.IsZero() {
			key.retireAt = loadTime.Add(retirementWindow)
			if err := persistSigningKeyRetirement(dir, kid, key.retireAt); err != nil {
				return nil, "", fmt.Errorf("retire signing key without metadata %q: %w", kid, err)
			}
		}
		keys[kid] = key
	}
	return keys, activeKid, nil
}

func generateSigningKey(dir string) (signingKey, error) {
	key, private, err := generateSigningKeyMaterial()
	if err != nil {
		return signingKey{}, err
	}
	if err := persistSigningKeyFiles(dir, key, private); err != nil {
		return signingKey{}, err
	}
	if err := persistActiveSigningKey(dir, key.kid); err != nil {
		return signingKey{}, err
	}
	return key, nil
}

func generateSigningKeyMaterial() (signingKey, ed25519.PrivateKey, error) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return signingKey{}, nil, fmt.Errorf("generate EdDSA key: %w", err)
	}
	key, err := makeSigningKey(store.NewID(), private)
	if err != nil {
		return signingKey{}, nil, err
	}
	return key, private, nil
}

func persistSigningKeyFiles(dir string, key signingKey, private ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return fmt.Errorf("marshal EdDSA key: %w", err)
	}
	privatePath := filepath.Join(dir, "ed25519-"+key.kid+".pem")
	file, err := os.OpenFile(privatePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create signing key: %w", err)
	}
	if _, writeErr := file.Write(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); writeErr != nil {
		_ = file.Close()
		return fmt.Errorf("write signing key: %w", writeErr)
	}
	if syncErr := file.Sync(); syncErr != nil {
		_ = file.Close()
		return fmt.Errorf("sync signing key: %w", syncErr)
	}
	if closeErr := file.Close(); closeErr != nil {
		return fmt.Errorf("close signing key: %w", closeErr)
	}
	if err := os.Chmod(privatePath, 0o600); err != nil {
		return fmt.Errorf("secure signing key: %w", err)
	}
	if err := persistPublicKey(dir, key.kid, key.public); err != nil {
		return err
	}
	if err := syncKeyDirectory(dir); err != nil {
		return fmt.Errorf("sync signing key directory: %w", err)
	}
	return nil
}

func persistActiveSigningKey(dir, kid string) error {
	if kid == "" {
		return errors.New("active signing key id is empty")
	}
	path := filepath.Join(dir, "ACTIVE")
	if err := writeAtomicKeyFile(dir, path, []byte(kid+"\n")); err != nil {
		return fmt.Errorf("write ACTIVE signing key marker: %w", err)
	}
	return nil
}

func persistSigningKeyRetirement(dir, kid string, retireAt time.Time) error {
	if kid == "" || retireAt.IsZero() {
		return errors.New("signing key retirement metadata is incomplete")
	}
	path := signingKeyRetirementPath(dir, kid)
	data := []byte(retireAt.UTC().Format(time.RFC3339Nano) + "\n")
	if err := writeAtomicKeyFile(dir, path, data); err != nil {
		return fmt.Errorf("write signing key retirement: %w", err)
	}
	return nil
}

func loadSigningKeyRetirement(dir, kid string) (time.Time, error) {
	data, err := os.ReadFile(signingKeyRetirementPath(dir, kid))
	if errors.Is(err, os.ErrNotExist) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	retireAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(data)))
	if err != nil {
		return time.Time{}, fmt.Errorf("parse retirement timestamp: %w", err)
	}
	return retireAt.UTC(), nil
}

func signingKeyRetirementPath(dir, kid string) string {
	return filepath.Join(dir, "ed25519-"+kid+".retire")
}

func writeAtomicKeyFile(dir, path string, data []byte) error {
	file, err := os.CreateTemp(dir, ".key-state-*")
	if err != nil {
		return err
	}
	temporaryPath := file.Name()
	defer func() {
		_ = file.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	if err := syncKeyDirectory(dir); err != nil {
		return fmt.Errorf("sync key directory: %w", err)
	}
	return nil
}

func syncKeyDirectory(dir string) error {
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	return directory.Close()
}

type preparedSigningKeyRotation struct {
	key         signingKey
	previousKid string
	retireAt    time.Time
}

func signingKeyRetirementWindow(accessTokenTTL time.Duration) time.Duration {
	maxTTL := accessTokenTTL
	if mfaTokenTTL > maxTTL {
		maxTTL = mfaTokenTTL
	}
	if passwordChangeTokenTTL > maxTTL {
		maxTTL = passwordChangeTokenTTL
	}
	return 2 * maxTTL
}

func removeSigningKeyFiles(dir, kid string) error {
	var firstErr error
	for _, path := range []string{
		filepath.Join(dir, "ed25519-"+kid+".pem"),
		filepath.Join(dir, "ed25519-"+kid+".jwk"),
		signingKeyRetirementPath(dir, kid),
	} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
			firstErr = fmt.Errorf("remove signing key file %q: %w", filepath.Base(path), err)
		}
	}
	return firstErr
}

// PrepareSigningKeyRotation writes a new key without activating it.
func (s *Service) PrepareSigningKeyRotation() (string, string, time.Time, time.Time, error) {
	if s == nil {
		return "", "", time.Time{}, time.Time{}, errors.New("nil authentication service")
	}
	s.rotationMu.Lock()
	defer s.rotationMu.Unlock()
	if s.pendingRotation != nil {
		return "", "", time.Time{}, time.Time{}, errSigningKeyRotationInProgress
	}
	if s.cfg.AccessTokenTTL <= 0 {
		return "", "", time.Time{}, time.Time{}, errors.New("access token TTL must be positive")
	}
	s.keyMu.RLock()
	previousKid := s.activeKid
	previous, ok := s.keys[previousKid]
	s.keyMu.RUnlock()
	_, activeMarkerErr := os.ReadFile(filepath.Join(s.cfg.KeyDir, "ACTIVE"))
	activeMarkerMissing := errors.Is(activeMarkerErr, os.ErrNotExist)
	if activeMarkerErr != nil && !activeMarkerMissing {
		return "", "", time.Time{}, time.Time{}, fmt.Errorf("read ACTIVE signing key marker: %w", activeMarkerErr)
	}
	if activeMarkerMissing && (previousKid == "" || !ok) {
		return "", "", time.Time{}, time.Time{}, errors.New("cannot determine current active signing key while ACTIVE marker is missing")
	}
	if !ok {
		return "", "", time.Time{}, time.Time{}, errors.New("active signing key unavailable")
	}
	if !previous.retireAt.IsZero() {
		return "", "", time.Time{}, time.Time{}, errors.New("active signing key is already retired")
	}
	if activeMarkerMissing {
		if err := persistActiveSigningKey(s.cfg.KeyDir, previousKid); err != nil {
			return "", "", time.Time{}, time.Time{}, fmt.Errorf("persist ACTIVE marker for current active signing key: %w", err)
		}
	}
	key, private, err := generateSigningKeyMaterial()
	if err != nil {
		return "", "", time.Time{}, time.Time{}, err
	}
	if err := persistSigningKeyFiles(s.cfg.KeyDir, key, private); err != nil {
		if cleanupErr := removeSigningKeyFiles(s.cfg.KeyDir, key.kid); cleanupErr != nil {
			return "", "", time.Time{}, time.Time{}, fmt.Errorf("%w; remove partial signing key files: %v", err, cleanupErr)
		}
		return "", "", time.Time{}, time.Time{}, err
	}
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	rotatedAt := now().UTC()
	retireAt := rotatedAt.Add(signingKeyRetirementWindow(s.cfg.AccessTokenTTL))
	s.pendingRotation = &preparedSigningKeyRotation{
		key: key, previousKid: previousKid, retireAt: retireAt,
	}
	return key.kid, previousKid, rotatedAt, retireAt, nil
}

// ActivateSigningKeyRotation activates a prepared key after its audit transaction commits.
func (s *Service) ActivateSigningKeyRotation(kid string) error {
	if s == nil {
		return errors.New("nil authentication service")
	}
	s.rotationMu.Lock()
	defer s.rotationMu.Unlock()
	rotation := s.pendingRotation
	if rotation == nil || rotation.key.kid != kid {
		return errors.New("prepared signing key rotation unavailable")
	}
	s.pendingRotation = nil
	if err := persistSigningKeyRetirement(s.cfg.KeyDir, rotation.previousKid, rotation.retireAt); err != nil {
		return err
	}
	if err := persistActiveSigningKey(s.cfg.KeyDir, rotation.key.kid); err != nil {
		return err
	}

	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	if s.activeKid != rotation.previousKid {
		return errors.New("active signing key changed since rotation was prepared")
	}
	previous, ok := s.keys[rotation.previousKid]
	if !ok {
		return errors.New("active signing key unavailable")
	}
	if !previous.retireAt.IsZero() {
		return errors.New("active signing key is already retired")
	}
	previous.retireAt = rotation.retireAt
	s.keys[rotation.previousKid] = previous
	s.keys[rotation.key.kid] = rotation.key
	s.activeKid = rotation.key.kid
	return nil
}

// RollbackSigningKeyRotation removes a prepared key when its audit transaction fails.
func (s *Service) RollbackSigningKeyRotation(kid string) error {
	if s == nil {
		return errors.New("nil authentication service")
	}
	s.rotationMu.Lock()
	defer s.rotationMu.Unlock()
	rotation := s.pendingRotation
	if rotation == nil || rotation.key.kid != kid {
		return errors.New("prepared signing key rotation unavailable")
	}
	s.pendingRotation = nil
	if err := removeSigningKeyFiles(s.cfg.KeyDir, rotation.key.kid); err != nil {
		return fmt.Errorf("remove prepared signing key files: %w", err)
	}
	return nil
}

func (s *Service) activeSigningKey() (signingKey, bool) {
	s.keyMu.RLock()
	defer s.keyMu.RUnlock()
	key, ok := s.keys[s.activeKid]
	return key, ok
}
func makeSigningKey(kid string, private ed25519.PrivateKey) (signingKey, error) {
	if len(private) != ed25519.PrivateKeySize {
		return signingKey{}, errors.New("invalid EdDSA private key length")
	}
	privateJWK, err := jwk.FromRaw(private)
	if err != nil {
		return signingKey{}, fmt.Errorf("convert EdDSA private key: %w", err)
	}
	publicJWK, err := jwk.FromRaw(private.Public())
	if err != nil {
		return signingKey{}, fmt.Errorf("convert EdDSA public key: %w", err)
	}
	for _, key := range []jwk.Key{privateJWK, publicJWK} {
		if err := key.Set(jwk.KeyIDKey, kid); err != nil {
			return signingKey{}, fmt.Errorf("set signing key id: %w", err)
		}
		if err := key.Set(jwk.AlgorithmKey, jwa.EdDSA); err != nil {
			return signingKey{}, fmt.Errorf("set signing algorithm: %w", err)
		}
		if err := key.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil {
			return signingKey{}, fmt.Errorf("set signing key usage: %w", err)
		}
	}
	return signingKey{kid: kid, private: privateJWK, public: publicJWK}, nil
}

func parsePrivateKey(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("expected PKCS#8 PRIVATE KEY PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8: %w", err)
	}
	private, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("signing key is not Ed25519")
	}
	return private, nil
}

func persistPublicKey(dir, kid string, key jwk.Key) error {
	if kid == "" {
		return errors.New("public signing key has no kid")
	}
	data, err := json.Marshal(key)
	if err != nil {
		return fmt.Errorf("marshal public JWK: %w", err)
	}
	path := filepath.Join(dir, "ed25519-"+kid+".jwk")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("write public JWK: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write public JWK: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync public JWK: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close public JWK: %w", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		return fmt.Errorf("secure public JWK: %w", err)
	}
	return nil
}
