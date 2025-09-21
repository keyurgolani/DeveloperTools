package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	tests := []struct {
		name     string
		envVars  map[string]string
		expected *Config
		wantErr  bool
	}{
		{
			name:    "Default configuration",
			envVars: map[string]string{},
			expected: &Config{
				Server: ServerConfig{
					Port:       8080,
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
					ArgonMemory:      65536,
					ArgonIterations:  3,
					ArgonParallelism: 4,
					ArgonSaltLength:  16,
					ArgonKeyLength:   32,
				},
				Secrets: SecretsConfig{
					MountPath: "/etc/secrets",
				},
			},
			wantErr: false,
		},
		{
			name: "Custom configuration",
			envVars: map[string]string{
				"SERVER_PORT":           "9090",
				"SERVER_TLS_ENABLED":    "true",
				"AUTH_METHOD":           "api_key",
				"AUTH_API_KEYS":         "key1,key2,key3",
				"AUTH_JWT_SECRET":       "secret123",
				"AUTH_JWT_ISSUER":       "test-issuer",
				"AUTH_JWT_AUDIENCE":     "test-audience",
				"RATE_LIMIT_STORE":      "redis",
				"RATE_LIMIT_REDIS_URL":  "redis://localhost:6379",
				"LOG_LEVEL":             "debug",
				"ARGON_MEMORY":          "32768",
				"ARGON_ITERATIONS":      "2",
				"ARGON_PARALLELISM":     "2",
				"ARGON_SALT_LENGTH":     "12",
				"ARGON_KEY_LENGTH":      "24",
				"SECRETS_MOUNT_PATH":    "/custom/secrets",
			},
			expected: &Config{
				Server: ServerConfig{
					Port:       9090,
					TLSEnabled: true,
				},
				Auth: AuthConfig{
					Method:      "api_key",
					APIKeys:     []string{"key1", "key2", "key3"},
					JWTSecret:   "secret123",
					JWTIssuer:   "test-issuer",
					JWTAudience: "test-audience",
				},
				RateLimit: RateLimitConfig{
					Store:    "redis",
					RedisURL: "redis://localhost:6379",
				},
				Log: LogConfig{
					Level: "debug",
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
					ArgonMemory:      32768,
					ArgonIterations:  2,
					ArgonParallelism: 2,
					ArgonSaltLength:  12,
					ArgonKeyLength:   24,
				},
				Secrets: SecretsConfig{
					MountPath: "/custom/secrets",
				},
			},
			wantErr: false,
		},
		{
			name: "Invalid port",
			envVars: map[string]string{
				"SERVER_PORT": "70000",
			},
			expected: nil,
			wantErr:  true,
		},
		{
			name: "Invalid auth method",
			envVars: map[string]string{
				"AUTH_METHOD": "invalid",
			},
			expected: nil,
			wantErr:  true,
		},
		{
			name: "Invalid log level",
			envVars: map[string]string{
				"LOG_LEVEL": "invalid",
			},
			expected: nil,
			wantErr:  true,
		},
		{
			name: "Invalid rate limit store",
			envVars: map[string]string{
				"RATE_LIMIT_STORE": "invalid",
			},
			expected: nil,
			wantErr:  true,
		},
		{
			name: "Redis store without URL",
			envVars: map[string]string{
				"RATE_LIMIT_STORE": "redis",
			},
			expected: nil,
			wantErr:  true,
		},
		{
			name: "API key auth without keys",
			envVars: map[string]string{
				"AUTH_METHOD": "api_key",
			},
			expected: nil,
			wantErr:  true,
		},
		{
			name: "JWT auth without secret",
			envVars: map[string]string{
				"AUTH_METHOD": "jwt",
			},
			expected: nil,
			wantErr:  true,
		},
		{
			name: "Invalid Argon2 memory",
			envVars: map[string]string{
				"ARGON_MEMORY": "512",
			},
			expected: nil,
			wantErr:  true,
		},
		{
			name: "Invalid Argon2 iterations",
			envVars: map[string]string{
				"ARGON_ITERATIONS": "0",
			},
			expected: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear environment
			clearEnv()

			// Set test environment variables
			for key, value := range tt.envVars {
				os.Setenv(key, value)
			}

			// Load configuration
			config, err := Load()

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, config)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, config)
			}

			// Clean up
			clearEnv()
		})
	}
}

func TestLoadFromFile(t *testing.T) {
	// Create temporary config file
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "config.json")

	configData := map[string]interface{}{
		"server": map[string]interface{}{
			"port":       9090,
			"tlsEnabled": true,
		},
		"auth": map[string]interface{}{
			"method":      "jwt",
			"jwtSecret":   "file-secret",
			"jwtIssuer":   "file-issuer",
			"jwtAudience": "file-audience",
		},
		"log": map[string]interface{}{
			"level": "debug",
		},
	}

	data, err := json.Marshal(configData)
	require.NoError(t, err)

	err = os.WriteFile(configFile, data, 0644)
	require.NoError(t, err)

	// Load configuration from file
	config, err := Load(LoadOptions{ConfigFile: configFile})
	require.NoError(t, err)

	assert.Equal(t, 9090, config.Server.Port)
	assert.True(t, config.Server.TLSEnabled)
	assert.Equal(t, "jwt", config.Auth.Method)
	assert.Equal(t, "file-secret", config.Auth.JWTSecret)
	assert.Equal(t, "file-issuer", config.Auth.JWTIssuer)
	assert.Equal(t, "file-audience", config.Auth.JWTAudience)
	assert.Equal(t, "debug", config.Log.Level)
}

func TestLoadFromFileWithEnvironmentOverride(t *testing.T) {
	// Create temporary config file
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "config.json")

	configData := map[string]interface{}{
		"server": map[string]interface{}{
			"port": 9090,
		},
		"auth": map[string]interface{}{
			"method":    "jwt",
			"jwtSecret": "file-secret",
		},
	}

	data, err := json.Marshal(configData)
	require.NoError(t, err)

	err = os.WriteFile(configFile, data, 0644)
	require.NoError(t, err)

	// Set environment variable to override file config
	os.Setenv("SERVER_PORT", "8888")
	os.Setenv("AUTH_JWT_SECRET", "env-secret")
	defer func() {
		os.Unsetenv("SERVER_PORT")
		os.Unsetenv("AUTH_JWT_SECRET")
	}()

	// Load configuration
	config, err := Load(LoadOptions{ConfigFile: configFile})
	require.NoError(t, err)

	// Environment should override file
	assert.Equal(t, 8888, config.Server.Port)
	assert.Equal(t, "env-secret", config.Auth.JWTSecret)
	assert.Equal(t, "jwt", config.Auth.Method) // From file, not overridden
}

func TestLoadSecrets(t *testing.T) {
	// Create temporary secrets directory
	tempDir := t.TempDir()
	secretsDir := filepath.Join(tempDir, "secrets")
	err := os.MkdirAll(secretsDir, 0755)
	require.NoError(t, err)

	// Create secret files
	err = os.WriteFile(filepath.Join(secretsDir, "jwt-secret"), []byte("mounted-jwt-secret"), 0644)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(secretsDir, "api-keys"), []byte("key1,key2,key3"), 0644)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(secretsDir, "redis-url"), []byte("redis://secret-redis:6379"), 0644)
	require.NoError(t, err)

	// Set secrets mount path
	os.Setenv("SECRETS_MOUNT_PATH", secretsDir)
	os.Setenv("AUTH_METHOD", "jwt")
	defer func() {
		os.Unsetenv("SECRETS_MOUNT_PATH")
		os.Unsetenv("AUTH_METHOD")
	}()

	// Load configuration
	config, err := Load()
	require.NoError(t, err)

	assert.Equal(t, "mounted-jwt-secret", config.Auth.JWTSecret)
	assert.Equal(t, []string{"key1", "key2", "key3"}, config.Auth.APIKeys)
	assert.Equal(t, "redis://secret-redis:6379", config.RateLimit.RedisURL)
}

func TestLoadSecretsWithEnvironmentPrecedence(t *testing.T) {
	// Create temporary secrets directory
	tempDir := t.TempDir()
	secretsDir := filepath.Join(tempDir, "secrets")
	err := os.MkdirAll(secretsDir, 0755)
	require.NoError(t, err)

	// Create secret file
	err = os.WriteFile(filepath.Join(secretsDir, "jwt-secret"), []byte("mounted-jwt-secret"), 0644)
	require.NoError(t, err)

	// Set environment variables (should take precedence over secrets)
	os.Setenv("SECRETS_MOUNT_PATH", secretsDir)
	os.Setenv("AUTH_METHOD", "jwt")
	os.Setenv("AUTH_JWT_SECRET", "env-jwt-secret")
	defer func() {
		os.Unsetenv("SECRETS_MOUNT_PATH")
		os.Unsetenv("AUTH_METHOD")
		os.Unsetenv("AUTH_JWT_SECRET")
	}()

	// Load configuration
	config, err := Load()
	require.NoError(t, err)

	// Environment should take precedence over mounted secret
	assert.Equal(t, "env-jwt-secret", config.Auth.JWTSecret)
}

func TestLoadNonExistentConfigFile(t *testing.T) {
	_, err := Load(LoadOptions{ConfigFile: "/nonexistent/config.json"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "configuration file does not exist")
}

func TestLoadInvalidConfigFile(t *testing.T) {
	// Create temporary invalid config file
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "config.json")

	err := os.WriteFile(configFile, []byte("invalid json"), 0644)
	require.NoError(t, err)

	_, err = Load(LoadOptions{ConfigFile: configFile})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse configuration file")
}

func TestValidation(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
		errMsg string
	}{
		{
			name: "Valid tracing with Jaeger",
			config: &Config{
				Server: ServerConfig{Port: 8080},
				Auth:   AuthConfig{Method: "none"},
				Log:    LogConfig{Level: "info"},
				RateLimit: RateLimitConfig{Store: "memory"},
				Tracing: TracingConfig{
					Enabled:        true,
					Exporter:       "jaeger",
					JaegerEndpoint: "http://jaeger:14268/api/traces",
					SampleRate:     0.5,
				},
				Crypto: CryptoConfig{
					ArgonMemory:      65536,
					ArgonIterations:  3,
					ArgonParallelism: 4,
					ArgonSaltLength:  16,
					ArgonKeyLength:   32,
				},
			},
			errMsg: "",
		},
		{
			name: "Invalid tracing - Jaeger without endpoint",
			config: &Config{
				Server: ServerConfig{Port: 8080},
				Auth:   AuthConfig{Method: "none"},
				Log:    LogConfig{Level: "info"},
				RateLimit: RateLimitConfig{Store: "memory"},
				Tracing: TracingConfig{
					Enabled:  true,
					Exporter: "jaeger",
				},
				Crypto: CryptoConfig{
					ArgonMemory:      65536,
					ArgonIterations:  3,
					ArgonParallelism: 4,
					ArgonSaltLength:  16,
					ArgonKeyLength:   32,
				},
			},
			errMsg: "Jaeger endpoint is required",
		},
		{
			name: "Invalid tracing - OTLP without endpoint",
			config: &Config{
				Server: ServerConfig{Port: 8080},
				Auth:   AuthConfig{Method: "none"},
				Log:    LogConfig{Level: "info"},
				RateLimit: RateLimitConfig{Store: "memory"},
				Tracing: TracingConfig{
					Enabled:  true,
					Exporter: "otlp",
				},
				Crypto: CryptoConfig{
					ArgonMemory:      65536,
					ArgonIterations:  3,
					ArgonParallelism: 4,
					ArgonSaltLength:  16,
					ArgonKeyLength:   32,
				},
			},
			errMsg: "OTLP endpoint is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.validate()
			if tt.errMsg == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			}
		})
	}
}

func clearEnv() {
	envVars := []string{
		"SERVER_PORT",
		"SERVER_TLS_ENABLED",
		"AUTH_METHOD",
		"AUTH_API_KEYS",
		"AUTH_JWT_SECRET",
		"AUTH_JWT_ISSUER",
		"AUTH_JWT_AUDIENCE",
		"RATE_LIMIT_STORE",
		"RATE_LIMIT_REDIS_URL",
		"LOG_LEVEL",
		"TRACING_ENABLED",
		"TRACING_SERVICE_NAME",
		"TRACING_ENVIRONMENT",
		"TRACING_EXPORTER",
		"TRACING_JAEGER_ENDPOINT",
		"TRACING_OTLP_ENDPOINT",
		"TRACING_OTLP_HEADERS",
		"TRACING_SAMPLE_RATE",
		"ARGON_MEMORY",
		"ARGON_ITERATIONS",
		"ARGON_PARALLELISM",
		"ARGON_SALT_LENGTH",
		"ARGON_KEY_LENGTH",
		"SECRETS_MOUNT_PATH",
	}

	for _, envVar := range envVars {
		os.Unsetenv(envVar)
	}
}