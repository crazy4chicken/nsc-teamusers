package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	envConnectionString      = "TEAMUSERS_CONNECTION_STRING"
	envListenAddress         = "TEAMUSERS_LISTEN_ADDRESS"
	envListenPort            = "TEAMUSERS_LISTEN_PORT"
	envNodeID                = "TEAMUSERS_NODE_ID"
	envLogLevel              = "TEAMUSERS_LOG_LEVEL"
	envKeyDir                = "TEAMUSERS_KEY_DIR"
	envNATSURL               = "TEAMUSERS_NATS_URL"
	envNotificationEndpoints = "TEAMUSERS_NOTIFICATION_ENDPOINTS"
	envNotificationSecret    = "TEAMUSERS_NOTIFICATION_SECRET"
	envAuditRetentionDays   = "TEAMUSERS_AUDIT_RETENTION_DAYS"
	envAuditForwardEndpoints = "TEAMUSERS_AUDIT_FORWARD_ENDPOINTS"
	envAuditForwardSecret    = "TEAMUSERS_AUDIT_FORWARD_SECRET"
	envRegistrationMode      = "TEAMUSERS_REGISTRATION_MODE"
	envTokenAudience         = "TEAMUSERS_TOKEN_AUDIENCE"
	envLockoutThreshold      = "TEAMUSERS_LOCKOUT_THRESHOLD"
	envLockoutDuration       = "TEAMUSERS_LOCKOUT_DURATION"
	envAccessTokenTTL        = "TEAMUSERS_ACCESS_TOKEN_TTL"
	envRefreshTokenTTL       = "TEAMUSERS_REFRESH_TOKEN_TTL"
	envSessionFamilyTTL      = "TEAMUSERS_SESSION_FAMILY_TTL"
	envWebAuthnRPID          = "TEAMUSERS_WEBAUTHN_RP_ID"
	envWebAuthnOrigin        = "TEAMUSERS_WEBAUTHN_ORIGIN"
	envTrustedProxies        = "TEAMUSERS_TRUSTED_PROXIES"

	DefaultLockoutThreshold = 5
	DefaultLockoutDuration  = 15 * time.Minute
	DefaultAccessTokenTTL   = 10 * time.Minute
	DefaultRefreshTokenTTL  = 720 * time.Hour
	DefaultSessionFamilyTTL = 2160 * time.Hour
	DefaultTokenAudience    = "teamusers"
	DefaultWebAuthnRPID     = "localhost"
	DefaultWebAuthnOrigin   = "http://localhost"
)

// Config is the process configuration. Values are resolved in flag, env, and
// default order, respectively.
type Config struct {
	ConnectionString      string         `json:"connection_string,omitempty"`
	ListenAddress         string         `json:"listen_address"`
	ListenPort            int            `json:"listen_port"`
	NodeID                string         `json:"node_id,omitempty"`
	LogLevel              string         `json:"log_level"`
	KeyDir                string         `json:"key_dir"`
	NATSURL               string         `json:"nats_url,omitempty"`
	NotificationEndpoints   []string       `json:"notification_endpoints,omitempty"`
	NotificationSecret      string         `json:"notification_secret,omitempty"`
	AuditRetentionDays      int            `json:"audit_retention_days"`
	AuditForwardEndpoints   []string       `json:"audit_forward_endpoints,omitempty"`
	AuditForwardSecret      string         `json:"audit_forward_secret,omitempty"`
	RegistrationMode      string         `json:"registration_mode"`
	TokenAudience         string         `json:"token_audience"`
	AccessTokenTTL        time.Duration  `json:"access_token_ttl"`
	RefreshTokenTTL       time.Duration  `json:"refresh_token_ttl"`
	SessionFamilyTTL      time.Duration  `json:"session_family_ttl"`
	LockoutThreshold      int            `json:"lockout_threshold"`
	LockoutDuration       time.Duration  `json:"lockout_duration"`
	WebAuthnRPID          string         `json:"webauthn_rp_id"`
	WebAuthnOrigin        string         `json:"webauthn_origin"`
	TrustedProxies        []netip.Prefix `json:"trusted_proxies,omitempty"`
}

// Load reads configuration from the process environment and optional command
// line arguments. Passing no arguments loads the environment only. This
// variadic form keeps the CLI thin while allowing callers and tests to supply
// an explicit argument vector.
func Load(args ...string) (Config, error) {
	// Precedence: CLI flag > TEAMUSERS_* env > supervisor contract env (Nekostick
	// child processes always receive PORT and HOST) > built-in default.
	listenPort := envOrDefault(envListenPort, envOrDefault("PORT", "0"))

	fs := flag.NewFlagSet("teamusers", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	connectionString := envOrDefault(envConnectionString, "")
	listenAddress := envOrDefault(envListenAddress, envOrDefault("HOST", "127.0.0.1"))
	nodeID := envOrDefault(envNodeID, "")
	logLevel := envOrDefault(envLogLevel, "info")
	keyDir := envOrDefault(envKeyDir, "./data/keys")
	natsURL := envOrDefault(envNATSURL, "")
	notificationEndpoints := envOrDefault(envNotificationEndpoints, "")
	notificationSecret := envOrDefault(envNotificationSecret, "")
	auditRetentionDays := envOrDefault(envAuditRetentionDays, "0")
	auditForwardEndpoints := envOrDefault(envAuditForwardEndpoints, "")
	auditForwardSecret := envOrDefault(envAuditForwardSecret, "")
	registrationMode := envOrDefault(envRegistrationMode, "closed")
	tokenAudience := envOrDefault(envTokenAudience, DefaultTokenAudience)
	accessTokenTTL := envOrDefault(envAccessTokenTTL, DefaultAccessTokenTTL.String())
	refreshTokenTTL := envOrDefault(envRefreshTokenTTL, DefaultRefreshTokenTTL.String())
	sessionFamilyTTL := envOrDefault(envSessionFamilyTTL, DefaultSessionFamilyTTL.String())
	lockoutThreshold := envOrDefault(envLockoutThreshold, strconv.Itoa(DefaultLockoutThreshold))
	lockoutDuration := envOrDefault(envLockoutDuration, DefaultLockoutDuration.String())
	webauthnRPID := envOrDefault(envWebAuthnRPID, DefaultWebAuthnRPID)
	webauthnOrigin := envOrDefault(envWebAuthnOrigin, DefaultWebAuthnOrigin)
	trustedProxies := envOrDefault(envTrustedProxies, "")

	fs.StringVar(&connectionString, "connection-string", connectionString, "PostgreSQL connection string")
	fs.StringVar(&listenAddress, "listen-address", listenAddress, "HTTP listen address")
	fs.StringVar(&listenPort, "listen-port", listenPort, "HTTP listen port")
	fs.StringVar(&nodeID, "node-id", nodeID, "node identifier")
	fs.StringVar(&logLevel, "log-level", logLevel, "log level (debug, info, warn, error)")
	fs.StringVar(&keyDir, "key-dir", keyDir, "directory containing signing keys")
	fs.StringVar(&natsURL, "nats-url", natsURL, "NATS URL")
	fs.StringVar(&notificationEndpoints, "notification-endpoints", notificationEndpoints, "comma-separated notification service endpoint URLs")
	fs.StringVar(&notificationSecret, "notification-secret", notificationSecret, "notification service signing secret")
	fs.StringVar(&auditRetentionDays, "audit-retention-days", auditRetentionDays, "audit retention in whole days (0 keeps forever)")
	fs.StringVar(&registrationMode, "registration-mode", registrationMode, "registration mode (closed, approval, open)")
	fs.StringVar(&tokenAudience, "token-audience", tokenAudience, "JWT token audience")
	fs.StringVar(&accessTokenTTL, "access-token-ttl", accessTokenTTL, "access token lifetime")
	fs.StringVar(&refreshTokenTTL, "refresh-token-ttl", refreshTokenTTL, "refresh token lifetime")
	fs.StringVar(&sessionFamilyTTL, "session-family-ttl", sessionFamilyTTL, "session family lifetime")
	fs.StringVar(&lockoutThreshold, "lockout-threshold", lockoutThreshold, "failed login attempts before account lockout")
	fs.StringVar(&lockoutDuration, "lockout-duration", lockoutDuration, "account lockout duration")
	fs.StringVar(&webauthnRPID, "webauthn-rp-id", webauthnRPID, "WebAuthn relying-party ID")
	fs.StringVar(&webauthnOrigin, "webauthn-origin", webauthnOrigin, "WebAuthn relying-party origin")
	fs.StringVar(&trustedProxies, "trusted-proxies", trustedProxies, "comma-separated trusted proxy CIDRs or IPs")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	auditRetentionDaysValue, err := strconv.Atoi(strings.TrimSpace(auditRetentionDays))
	if err != nil {
		return Config{}, fmt.Errorf("invalid audit retention days %q: %w", auditRetentionDays, err)
	}
	port, err := strconv.Atoi(strings.TrimSpace(listenPort))
	if err != nil {
		return Config{}, fmt.Errorf("invalid listen port %q: %w", listenPort, err)
	}
	threshold, err := strconv.Atoi(strings.TrimSpace(lockoutThreshold))
	if err != nil {
		return Config{}, fmt.Errorf("invalid lockout threshold %q: %w", lockoutThreshold, err)
	}
	duration, err := time.ParseDuration(strings.TrimSpace(lockoutDuration))
	if err != nil {
		return Config{}, fmt.Errorf("invalid lockout duration %q: %w", lockoutDuration, err)
	}
	accessTTL, err := time.ParseDuration(strings.TrimSpace(accessTokenTTL))
	if err != nil {
		return Config{}, fmt.Errorf("invalid access token TTL %q: %w", accessTokenTTL, err)
	}
	refreshTTL, err := time.ParseDuration(strings.TrimSpace(refreshTokenTTL))
	if err != nil {
		return Config{}, fmt.Errorf("invalid refresh token TTL %q: %w", refreshTokenTTL, err)
	}
	familyTTL, err := time.ParseDuration(strings.TrimSpace(sessionFamilyTTL))
	if err != nil {
		return Config{}, fmt.Errorf("invalid session family TTL %q: %w", sessionFamilyTTL, err)
	}
	parsedTrustedProxies, err := parseTrustedProxies(trustedProxies)
	if err != nil {
		return Config{}, err
	}
	if threshold < 1 {
		return Config{}, fmt.Errorf("lockout threshold must be positive, got %d", threshold)
	}
	if duration <= 0 {
		return Config{}, fmt.Errorf("lockout duration must be positive, got %s", duration)
	}

	cfg := Config{
		ConnectionString:      connectionString,
		ListenAddress:         listenAddress,
		ListenPort:            port,
		NodeID:                nodeID,
		LogLevel:              strings.ToLower(strings.TrimSpace(logLevel)),
		KeyDir:                keyDir,
		NATSURL:               natsURL,
		NotificationEndpoints: parseNotificationEndpoints(notificationEndpoints),
		NotificationSecret:    notificationSecret,
		AuditRetentionDays:    auditRetentionDaysValue,
		AuditForwardEndpoints: parseNotificationEndpoints(auditForwardEndpoints),
		AuditForwardSecret:    auditForwardSecret,
		RegistrationMode:      strings.ToLower(strings.TrimSpace(registrationMode)),
		TokenAudience:         strings.TrimSpace(tokenAudience),
		AccessTokenTTL:        accessTTL,
		RefreshTokenTTL:       refreshTTL,
		SessionFamilyTTL:      familyTTL,
		LockoutThreshold:      threshold,
		LockoutDuration:       duration,
		WebAuthnRPID:          strings.TrimSpace(webauthnRPID),
		WebAuthnOrigin:        strings.TrimSpace(webauthnOrigin),
		TrustedProxies:        parsedTrustedProxies,
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// WithDefaults fills security settings omitted by programmatic Config literals.
// Config.Load already resolves all defaults from environment and flags.
func (c Config) WithDefaults() Config {
	if c.LockoutThreshold == 0 {
		c.LockoutThreshold = DefaultLockoutThreshold
	}
	if c.LockoutDuration == 0 {
		c.LockoutDuration = DefaultLockoutDuration
	}
	if c.AccessTokenTTL == 0 {
		c.AccessTokenTTL = DefaultAccessTokenTTL
	}
	if c.RefreshTokenTTL == 0 {
		c.RefreshTokenTTL = DefaultRefreshTokenTTL
	}
	if c.SessionFamilyTTL == 0 {
		c.SessionFamilyTTL = DefaultSessionFamilyTTL
	}
	if strings.TrimSpace(c.TokenAudience) == "" {
		c.TokenAudience = DefaultTokenAudience
	}
	if strings.TrimSpace(c.WebAuthnRPID) == "" {
		c.WebAuthnRPID = DefaultWebAuthnRPID
	}
	if strings.TrimSpace(c.WebAuthnOrigin) == "" {
		c.WebAuthnOrigin = DefaultWebAuthnOrigin
	}
	return c
}

// Validate checks settings that are meaningful for every command. Database
// connectivity is checked by run and doctor, where a live database is needed.
func (c Config) Validate() error {
	if strings.TrimSpace(c.ListenAddress) == "" {
		return errors.New("listen address must not be empty")
	}
	if c.ListenPort < 0 || c.ListenPort > 65535 {
		return fmt.Errorf("listen port must be between 0 and 65535, got %d", c.ListenPort)
	}
	switch strings.ToLower(strings.TrimSpace(c.LogLevel)) {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log level must be one of debug, info, warn, error, got %q", c.LogLevel)
	}
	if strings.TrimSpace(c.KeyDir) == "" {
		return errors.New("key directory must not be empty")
	}
	mode := strings.ToLower(strings.TrimSpace(c.RegistrationMode))
	if mode == "" {
		mode = "closed"
	}
	switch mode {
	case "closed", "approval", "open":
	default:
		return fmt.Errorf("registration mode must be one of closed, approval, open, got %q", c.RegistrationMode)
	}
	if c.LockoutThreshold < 0 {
		return fmt.Errorf("lockout threshold must not be negative, got %d", c.LockoutThreshold)
	}
	if c.AuditRetentionDays < 0 {
		return fmt.Errorf("audit retention days must not be negative, got %d", c.AuditRetentionDays)
	}
	if len(c.AuditForwardEndpoints) > 0 && strings.TrimSpace(c.AuditForwardSecret) == "" {
		return errors.New("audit forwarding secret is required when endpoints are configured")
	}
	if c.LockoutDuration < 0 {
		return fmt.Errorf("lockout duration must not be negative, got %s", c.LockoutDuration)
	}
	if c.AccessTokenTTL <= 0 {
		return fmt.Errorf("access token TTL must be positive, got %s", c.AccessTokenTTL)
	}
	if c.RefreshTokenTTL <= 0 {
		return fmt.Errorf("refresh token TTL must be positive, got %s", c.RefreshTokenTTL)
	}
	if c.SessionFamilyTTL <= 0 {
		return fmt.Errorf("session family TTL must be positive, got %s", c.SessionFamilyTTL)
	}
	if c.SessionFamilyTTL < c.RefreshTokenTTL {
		return fmt.Errorf("session family TTL must be at least refresh token TTL, got %s < %s", c.SessionFamilyTTL, c.RefreshTokenTTL)
	}
	return nil
}

// ValidateFor applies command-specific requirements after Validate.
func (c Config) ValidateFor(command string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(command)) {
	case "run", "doctor", "bootstrap-admin":
		if strings.TrimSpace(c.ConnectionString) == "" {
			return errors.New("connection string is required for " + strings.ToLower(strings.TrimSpace(command)))
		}
	case "status":
		// status is intentionally usable without database credentials.
	default:
		return fmt.Errorf("unknown command %q", command)
	}
	return nil
}

// Redacted returns a copy safe for diagnostic output. Credentials and
// endpoint URLs are not exposed, even when they are present in otherwise useful config.
func (c Config) Redacted() Config {
	redacted := c
	if redacted.ConnectionString != "" {
		redacted.ConnectionString = "[redacted]"
	}
	if redacted.NATSURL != "" {
		redacted.NATSURL = "[redacted]"
	}
	redacted.NotificationEndpoints = nil
	redacted.AuditForwardEndpoints = nil
	if redacted.AuditForwardSecret != "" {
		redacted.AuditForwardSecret = "[redacted]"
	}
	if redacted.NotificationSecret != "" {
		redacted.NotificationSecret = "[redacted]"
	}
	return redacted
}

// SlogLevel converts the validated textual level to slog's level type.
func (c Config) SlogLevel() slog.Level {
	switch strings.ToLower(strings.TrimSpace(c.LogLevel)) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func parseTrustedProxies(raw string) ([]netip.Prefix, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	proxies := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			return nil, fmt.Errorf("invalid trusted proxy %q: expected an IP address or CIDR", value)
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			address, addressErr := netip.ParseAddr(value)
			if addressErr != nil {
				return nil, fmt.Errorf("invalid trusted proxy %q: expected an IP address or CIDR", value)
			}
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		proxies = append(proxies, prefix.Masked())
	}
	return proxies, nil
}

func parseNotificationEndpoints(raw string) []string {
	parts := strings.Split(raw, ",")
	endpoints := make([]string, 0, len(parts))
	for _, part := range parts {
		if endpoint := strings.TrimSpace(part); endpoint != "" {
			endpoints = append(endpoints, endpoint)
		}
	}
	return endpoints
}

func envOrDefault(name, fallback string) string {
	if value, ok := os.LookupEnv(name); ok {
		return value
	}
	return fallback
}
