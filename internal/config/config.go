package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/keyurgolani/DeveloperTools/internal/constants"
)

// Config holds all configuration for the server.
type Config struct {
	Server    ServerConfig    `json:"server"`
	Auth      AuthConfig      `json:"auth"`
	RateLimit RateLimitConfig `json:"rateLimit"`
	Log       LogConfig       `json:"log"`
	Tracing   TracingConfig   `json:"tracing"`
	Crypto    CryptoConfig    `json:"crypto"`
	Secrets   SecretsConfig   `json:"secrets"`
}

// CryptoConfig holds cryptography-specific configuration.
type CryptoConfig struct {
	ArgonMemory      int `json:"argonMemory"`      // Memory in KB
	ArgonIterations  int `json:"argonIterations"`  // Number of iterations
	ArgonParallelism int `json:"argonParallelism"` // Number of threads
	ArgonSaltLength  int `json:"argonSaltLength"`  // Salt length in bytes
	ArgonKeyLength   int `json:"argonKeyLength"`   // Key length in bytes
}

// SecretsConfig holds secret management configuration.
type SecretsConfig struct {
	MountPath string `json:"mountPath"` // Path where secrets are mounted (e.g., /etc/secrets)
}

// ServerConfig holds server-specific configuration.
type ServerConfig struct {
	Port       int  `json:"port"`
	TLSEnabled bool `json:"tlsEnabled"`
}

// AuthConfig holds authentication configuration.
type AuthConfig struct {
	Method      string   `json:"method"`      // "api_key", "jwt", or "none"
	APIKeys     []string `json:"apiKeys"`     // Valid API keys for API key authentication
	JWTSecret   string   `json:"jwtSecret"`   // Secret for JWT validation
	JWTIssuer   string   `json:"jwtIssuer"`   // Expected JWT issuer
	JWTAudience string   `json:"jwtAudience"` // Expected JWT audience
}

// RateLimitConfig holds rate limiting configuration.
type RateLimitConfig struct {
	Store    string `json:"store"`    // "memory" or "redis"
	RedisURL string `json:"redisUrl"` // Redis connection URL
}

// LogConfig holds logging configuration.
type LogConfig struct {
	Level string `json:"level"`
}

// TracingConfig holds tracing configuration.
type TracingConfig struct {
	Enabled        bool              `json:"enabled"`
	ServiceName    string            `json:"serviceName"`
	Environment    string            `json:"environment"`
	Exporter       string            `json:"exporter"`       // "jaeger", "otlp", or "noop"
	JaegerEndpoint string            `json:"jaegerEndpoint"` // Jaeger collector endpoint
	OTLPEndpoint   string            `json:"otlpEndpoint"`   // OTLP endpoint
	OTLPHeaders    map[string]string `json:"otlpHeaders"`    // OTLP headers
	SampleRate     float64           `json:"sampleRate"`     // 0.0 to 1.0
}

// LoadOptions holds options for loading configuration.
type LoadOptions struct {
	ConfigFile string // Path to configuration file (optional)
}

// Load loads configuration with hierarchical precedence:
// 1. Default values
// 2. Configuration file (if provided)
// 3. Environment variables
// 4. Mounted secrets (if configured).
func Load(opts ...LoadOptions) (*Config, error) {
	var options LoadOptions
	if len(opts) > 0 {
		options = opts[0]
	}

	// Start with default configuration
	config := getDefaultConfig()

	// Load from configuration file if provided
	if options.ConfigFile != "" {
		if err := loadFromFile(config, options.ConfigFile); err != nil {
			return nil, fmt.Errorf("failed to load configuration file: %w", err)
		}
	}

	// Override with environment variables
	loadFromEnvironment(config)

	// Load secrets from mounted files
	if err := loadSecrets(config); err != nil {
		return nil, fmt.Errorf("failed to load secrets: %w", err)
	}

	// Validate final configuration
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return config, nil
}

// getDefaultConfig returns configuration with default values.
func getDefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Port:       constants.DefaultPort,
			TLSEnabled: false,
		},
		Auth: AuthConfig{
			Method:      "none",
			APIKeys:     []string{},
			JWTSecret:   "",
			JWTIssuer:   "",
			JWTAudience: "",
		},
		RateLimit: RateLimitConfig{
			Store:    "memory",
			RedisURL: "",
		},
		Log: LogConfig{
			Level: "info",
		},
		Tracing: TracingConfig{
			Enabled:        false,
			ServiceName:    "dev-utilities",
			Environment:    "development",
			Exporter:       "noop",
			JaegerEndpoint: "",
			OTLPEndpoint:   "",
			OTLPHeaders:    map[string]string{},
			SampleRate:     1.0,
		},
		Crypto: CryptoConfig{
			ArgonMemory:      constants.DefaultArgonMemory,
			ArgonIterations:  constants.DefaultArgonIterations,
			ArgonParallelism: constants.DefaultArgonParallelism,
			ArgonSaltLength:  constants.DefaultArgonSaltLength,
			ArgonKeyLength:   constants.DefaultArgonKeyLength,
		},
		Secrets: SecretsConfig{
			MountPath: "/etc/secrets",
		},
	}
}

// loadFromFile loads configuration from a JSON file.
func loadFromFile(config *Config, filePath string) error {
	// Validate file path to prevent directory traversal
	if strings.Contains(filePath, "..") {
		return fmt.Errorf("invalid file path: %s", filePath)
	}

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("configuration file does not exist: %s", filePath)
	}

	data, err := os.ReadFile(filePath) // #nosec G304 - path validated above
	if err != nil {
		return fmt.Errorf("failed to read configuration file: %w", err)
	}

	if err := json.Unmarshal(data, config); err != nil {
		return fmt.Errorf("failed to parse configuration file: %w", err)
	}

	return nil
}

// loadFromEnvironment loads configuration from environment variables.
func loadFromEnvironment(config *Config) {
	loadServerConfig(config)
	loadAuthConfig(config)
	loadRateLimitConfig(config)
	loadLogConfig(config)
	loadTracingConfig(config)
	loadCryptoConfig(config)
	loadSecretsConfig(config)
}

func loadServerConfig(config *Config) {
	if port := getEnvAsInt("SERVER_PORT", 0); port != 0 {
		config.Server.Port = port
	}
	if tlsEnabled := getEnvAsBool("SERVER_TLS_ENABLED", false); getEnv("SERVER_TLS_ENABLED", "") != "" {
		config.Server.TLSEnabled = tlsEnabled
	}
}

func loadAuthConfig(config *Config) {
	if method := getEnv("AUTH_METHOD", ""); method != "" {
		config.Auth.Method = method
	}
	if apiKeys := getEnvAsStringSlice("AUTH_API_KEYS", nil); apiKeys != nil {
		config.Auth.APIKeys = apiKeys
	}
	if jwtSecret := getEnv("AUTH_JWT_SECRET", ""); jwtSecret != "" {
		config.Auth.JWTSecret = jwtSecret
	}
	if jwtIssuer := getEnv("AUTH_JWT_ISSUER", ""); jwtIssuer != "" {
		config.Auth.JWTIssuer = jwtIssuer
	}
	if jwtAudience := getEnv("AUTH_JWT_AUDIENCE", ""); jwtAudience != "" {
		config.Auth.JWTAudience = jwtAudience
	}
}

func loadRateLimitConfig(config *Config) {
	if store := getEnv("RATE_LIMIT_STORE", ""); store != "" {
		config.RateLimit.Store = store
	}
	if redisURL := getEnv("RATE_LIMIT_REDIS_URL", ""); redisURL != "" {
		config.RateLimit.RedisURL = redisURL
	}
}

func loadLogConfig(config *Config) {
	if level := getEnv("LOG_LEVEL", ""); level != "" {
		config.Log.Level = level
	}
}

func loadTracingConfig(config *Config) {
	if enabled := getEnvAsBool("TRACING_ENABLED", false); getEnv("TRACING_ENABLED", "") != "" {
		config.Tracing.Enabled = enabled
	}
	if serviceName := getEnv("TRACING_SERVICE_NAME", ""); serviceName != "" {
		config.Tracing.ServiceName = serviceName
	}
	if environment := getEnv("TRACING_ENVIRONMENT", ""); environment != "" {
		config.Tracing.Environment = environment
	}
	if exporter := getEnv("TRACING_EXPORTER", ""); exporter != "" {
		config.Tracing.Exporter = exporter
	}
	if jaegerEndpoint := getEnv("TRACING_JAEGER_ENDPOINT", ""); jaegerEndpoint != "" {
		config.Tracing.JaegerEndpoint = jaegerEndpoint
	}
	if otlpEndpoint := getEnv("TRACING_OTLP_ENDPOINT", ""); otlpEndpoint != "" {
		config.Tracing.OTLPEndpoint = otlpEndpoint
	}
	if otlpHeaders := getEnvAsMap("TRACING_OTLP_HEADERS", nil); otlpHeaders != nil {
		config.Tracing.OTLPHeaders = otlpHeaders
	}
	if sampleRate := getEnvAsFloat("TRACING_SAMPLE_RATE", -1); sampleRate >= 0 {
		config.Tracing.SampleRate = sampleRate
	}
}

func loadCryptoConfig(config *Config) {
	if argonMemory, set := getEnvAsIntWithCheck("ARGON_MEMORY"); set {
		config.Crypto.ArgonMemory = argonMemory
	}
	if argonIterations, set := getEnvAsIntWithCheck("ARGON_ITERATIONS"); set {
		config.Crypto.ArgonIterations = argonIterations
	}
	if argonParallelism, set := getEnvAsIntWithCheck("ARGON_PARALLELISM"); set {
		config.Crypto.ArgonParallelism = argonParallelism
	}
	if argonSaltLength, set := getEnvAsIntWithCheck("ARGON_SALT_LENGTH"); set {
		config.Crypto.ArgonSaltLength = argonSaltLength
	}
	if argonKeyLength, set := getEnvAsIntWithCheck("ARGON_KEY_LENGTH"); set {
		config.Crypto.ArgonKeyLength = argonKeyLength
	}
}

func loadSecretsConfig(config *Config) {
	if mountPath := getEnv("SECRETS_MOUNT_PATH", ""); mountPath != "" {
		config.Secrets.MountPath = mountPath
	}
}

// loadSecrets loads secrets from mounted files
//
//nolint:unparam // error return is for future extensibility
func loadSecrets(config *Config) error {
	if config.Secrets.MountPath == "" {
		return nil // No secrets mount path configured
	}

	// Check if secrets directory exists
	if _, err := os.Stat(config.Secrets.MountPath); os.IsNotExist(err) {
		return nil // Secrets directory doesn't exist, skip loading
	}

	// Load JWT secret from file if not already set
	if config.Auth.JWTSecret == "" {
		if secret, err := readSecret(filepath.Join(config.Secrets.MountPath, "jwt-secret")); err == nil {
			config.Auth.JWTSecret = secret
		}
	}

	// Load API keys from file if not already set
	if len(config.Auth.APIKeys) == 0 {
		if apiKeysData, err := readSecret(filepath.Join(config.Secrets.MountPath, "api-keys")); err == nil {
			// Parse as comma-separated values
			apiKeys := strings.Split(apiKeysData, ",")
			for i, key := range apiKeys {
				apiKeys[i] = strings.TrimSpace(key)
			}
			config.Auth.APIKeys = apiKeys
		}
	}

	// Load Redis URL from file if not already set
	if config.RateLimit.RedisURL == "" {
		if redisURL, err := readSecret(filepath.Join(config.Secrets.MountPath, "redis-url")); err == nil {
			config.RateLimit.RedisURL = redisURL
		}
	}

	return nil
}

// readSecret reads a secret from a mounted file.
func readSecret(path string) (string, error) {
	// Validate path to prevent directory traversal
	if strings.Contains(path, "..") {
		return "", fmt.Errorf("invalid secret path: %s", path)
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return "", fmt.Errorf("secret file does not exist: %s", path)
	}

	data, err := os.ReadFile(path) // #nosec G304 - path validated above
	if err != nil {
		return "", fmt.Errorf("failed to read secret file: %w", err)
	}

	return strings.TrimSpace(string(data)), nil
}

// validate ensures the configuration is valid.
func (c *Config) validate() error {
	if err := c.validateServer(); err != nil {
		return err
	}
	if err := c.validateAuth(); err != nil {
		return err
	}
	if err := c.validateLog(); err != nil {
		return err
	}
	if err := c.validateRateLimit(); err != nil {
		return err
	}
	if err := c.validateTracing(); err != nil {
		return err
	}
	return c.validateCrypto()
}

// validateServer validates server configuration.
func (c *Config) validateServer() error {
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}
	return nil
}

// validateAuth validates authentication configuration.
func (c *Config) validateAuth() error {
	validAuthMethods := []string{"api_key", "jwt", "none"}
	if !contains(validAuthMethods, c.Auth.Method) {
		return fmt.Errorf("invalid auth method: %s, must be one of %v", c.Auth.Method, validAuthMethods)
	}

	if c.Auth.Method == "api_key" && len(c.Auth.APIKeys) == 0 {
		return fmt.Errorf("API keys are required when using API key authentication")
	}

	if c.Auth.Method == "jwt" && c.Auth.JWTSecret == "" {
		return fmt.Errorf("JWT secret is required when using JWT authentication")
	}

	return nil
}

// validateLog validates logging configuration.
func (c *Config) validateLog() error {
	validLogLevels := []string{"debug", "info", "warn", "error"}
	if !contains(validLogLevels, c.Log.Level) {
		return fmt.Errorf("invalid log level: %s, must be one of %v", c.Log.Level, validLogLevels)
	}
	return nil
}

// validateRateLimit validates rate limiting configuration.
func (c *Config) validateRateLimit() error {
	validStores := []string{"memory", "redis"}
	if !contains(validStores, c.RateLimit.Store) {
		return fmt.Errorf("invalid rate limit store: %s, must be one of %v", c.RateLimit.Store, validStores)
	}

	if c.RateLimit.Store == "redis" && c.RateLimit.RedisURL == "" {
		return fmt.Errorf("redis URL is required when using Redis rate limit store")
	}

	return nil
}

// validateTracing validates tracing configuration.
func (c *Config) validateTracing() error {
	if !c.Tracing.Enabled {
		return nil
	}

	// Check for deprecated Jaeger exporter first
	if c.Tracing.Exporter == "jaeger" {
		return fmt.Errorf("jaeger exporter is deprecated, please use OTLP exporter instead")
	}

	validExporters := []string{"otlp", "noop"}
	if !contains(validExporters, c.Tracing.Exporter) {
		return fmt.Errorf("invalid tracing exporter: %s, must be one of %v", c.Tracing.Exporter, validExporters)
	}

	if c.Tracing.SampleRate < 0.0 || c.Tracing.SampleRate > 1.0 {
		return fmt.Errorf("invalid tracing sample rate: %f, must be between 0.0 and 1.0", c.Tracing.SampleRate)
	}

	if c.Tracing.Exporter == "otlp" && c.Tracing.OTLPEndpoint == "" {
		return fmt.Errorf("OTLP endpoint is required when using OTLP exporter")
	}

	return nil
}

// validateCrypto validates cryptographic configuration.
func (c *Config) validateCrypto() error {
	if c.Crypto.ArgonMemory < constants.MinArgonMemory {
		return fmt.Errorf("Argon2 memory must be at least %d KB, got %d", constants.MinArgonMemory, c.Crypto.ArgonMemory)
	}

	if c.Crypto.ArgonIterations < 1 {
		return fmt.Errorf("Argon2 iterations must be at least 1, got %d", c.Crypto.ArgonIterations)
	}

	if c.Crypto.ArgonParallelism < 1 {
		return fmt.Errorf("Argon2 parallelism must be at least 1, got %d", c.Crypto.ArgonParallelism)
	}

	if c.Crypto.ArgonSaltLength < constants.MinArgonSaltLength {
		return fmt.Errorf("Argon2 salt length must be at least %d bytes, got %d",
			constants.MinArgonSaltLength, c.Crypto.ArgonSaltLength)
	}

	if c.Crypto.ArgonKeyLength < constants.MinArgonKeyLength {
		return fmt.Errorf("Argon2 key length must be at least %d bytes, got %d",
			constants.MinArgonKeyLength, c.Crypto.ArgonKeyLength)
	}

	return nil
}

// Helper functions for environment variable parsing
//
//nolint:unparam // defaultValue parameter is for consistency with other getEnv functions
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvAsIntWithCheck(key string) (int, bool) {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue, true
		}
	}
	return 0, false
}

func getEnvAsBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getEnvAsStringSlice(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		// Split by comma and trim whitespace
		parts := strings.Split(value, ",")
		result := make([]string, 0, len(parts))
		for _, part := range parts {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				result = append(result, trimmed)
			}
		}
		return result
	}
	return defaultValue
}

func getEnvAsFloat(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		if floatValue, err := strconv.ParseFloat(value, 64); err == nil {
			return floatValue
		}
	}
	return defaultValue
}

func getEnvAsMap(key string, defaultValue map[string]string) map[string]string {
	if value := os.Getenv(key); value != "" {
		// Parse as comma-separated key=value pairs
		result := make(map[string]string)
		pairs := strings.Split(value, ",")
		for _, pair := range pairs {
			kv := strings.SplitN(strings.TrimSpace(pair), "=", constants.KeyValuePairParts)
			if len(kv) == constants.KeyValuePairParts {
				result[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
		return result
	}
	return defaultValue
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
