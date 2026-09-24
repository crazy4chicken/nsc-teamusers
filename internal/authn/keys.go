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

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"nsc-teamusers/internal/store"
)

type signingKey struct {
	kid     string
	private jwk.Key
	public  jwk.Key
}

func loadSigningKeys(dir string) (map[string]signingKey, string, error) {
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
	// Key rotation hook: emit a key.rotated outbox event when runtime rotation is added.
	return keys, activeKid, nil
}

func generateSigningKey(dir string) (signingKey, error) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return signingKey{}, fmt.Errorf("generate EdDSA key: %w", err)
	}
	key, err := makeSigningKey(store.NewID(), private)
	if err != nil {
		return signingKey{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return signingKey{}, fmt.Errorf("marshal EdDSA key: %w", err)
	}
	privatePath := filepath.Join(dir, "ed25519-"+key.kid+".pem")
	file, err := os.OpenFile(privatePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return signingKey{}, fmt.Errorf("create signing key: %w", err)
	}
	if _, writeErr := file.Write(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); writeErr != nil {
		_ = file.Close()
		return signingKey{}, fmt.Errorf("write signing key: %w", writeErr)
	}
	if closeErr := file.Close(); closeErr != nil {
		return signingKey{}, fmt.Errorf("close signing key: %w", closeErr)
	}
	if err := os.Chmod(privatePath, 0o600); err != nil {
		return signingKey{}, fmt.Errorf("secure signing key: %w", err)
	}
	if err := persistPublicKey(dir, key.kid, key.public); err != nil {
		return signingKey{}, err
	}
	activePath := filepath.Join(dir, "ACTIVE")
	if err := os.WriteFile(activePath, []byte(key.kid+"\n"), 0o600); err != nil {
		return signingKey{}, fmt.Errorf("write ACTIVE signing key marker: %w", err)
	}
	if err := os.Chmod(activePath, 0o600); err != nil {
		return signingKey{}, fmt.Errorf("secure ACTIVE signing key marker: %w", err)
	}
	return key, nil
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
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write public JWK: %w", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		return fmt.Errorf("secure public JWK: %w", err)
	}
	return nil
}
