package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
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
	envRegistrationMode      = "TEAMUSERS_REGISTRATION_MODE"
)

// Config is the process configuration. Values are resolved in flag, env, and
// default order, respectively.
type Config struct {
	ConnectionString      string   `json:"connection_string,omitempty"`
	ListenAddress         string   `json:"listen_address"`
	ListenPort            int      `json:"listen_port"`
	NodeID                string   `json:"node_id,omitempty"`
	LogLevel              string   `json:"log_level"`
	KeyDir                string   `json:"key_dir"`
	NATSURL               string   `json:"nats_url,omitempty"`
	NotificationEndpoints []string `json:"notification_endpoints,omitempty"`
	NotificationSecret    string   `json:"notification_secret,omitempty"`
	RegistrationMode      string   `json:"registration_mode"`
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
	registrationMode := envOrDefault(envRegistrationMode, "closed")

	fs.StringVar(&connectionString, "connection-string", connectionString, "PostgreSQL connection string")
	fs.StringVar(&listenAddress, "listen-address", listenAddress, "HTTP listen address")
	fs.StringVar(&listenPort, "listen-port", listenPort, "HTTP listen port")
	fs.StringVar(&nodeID, "node-id", nodeID, "node identifier")
	fs.StringVar(&logLevel, "log-level", logLevel, "log level (debug, info, warn, error)")
	fs.StringVar(&keyDir, "key-dir", keyDir, "directory containing signing keys")
	fs.StringVar(&natsURL, "nats-url", natsURL, "NATS URL")
	fs.StringVar(&notificationEndpoints, "notification-endpoints", notificationEndpoints, "comma-separated notification service endpoint URLs")
	fs.StringVar(&notificationSecret, "notification-secret", notificationSecret, "notification service signing secret")
	fs.StringVar(&registrationMode, "registration-mode", registrationMode, "registration mode (closed, approval, open)")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	port, err := strconv.Atoi(strings.TrimSpace(listenPort))
	if err != nil {
		return Config{}, fmt.Errorf("invalid listen port %q: %w", listenPort, err)
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
		RegistrationMode:      strings.ToLower(strings.TrimSpace(registrationMode)),
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
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
	return nil
}

// ValidateFor applies command-specific requirements after Validate.
func (c Config) ValidateFor(command string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(command)) {
	case "run", "doctor":
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
