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
	tests := getConfigLoadTestCases()
	executeConfigLoadTests(t, tests)
}

type configLoadTestCase struct {
	name     string
	envVars  map[string]string
	expected *Config
	wantErr  bool
}

func getConfigLoadTestCases() []configLoadTestCase {
	return []configLoadTestCase{
		getDefaultConfigTestCase(),
		getCustomConfigTestCase(),
		getInvalidPortTestCase(),
		getInvalidAuthMethodTestCase(),
		getInvalidLogLevelTestCase(),
		getInvalidRateLimitStoreTestCase(),
		getRedisStoreWithoutURLTestCase(),
		getAPIKeyAuthWithoutKeysTestCase(),
		getJWTAuthWithoutSecretTestCase(),
		getInvalidArgonMemoryTestCase(),
		getInvalidArgonIterationsTestCase(),
	}
}

func getDefaultConfigTestCase() configLoadTestCase {
	return configLoadTestCase{
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
	}
}

func getCustomConfigTestCase() configLoadTestCase {
	return configLoadTestCase{
		name:     "Custom configuration",
		envVars:  getCustomConfigEnvVars(),
		expected: getCustomConfigExpected(),
		wantErr:  false,
	}
}

func getCustomConfigEnvVars() map[string]string {
	return map[string]string{
		"SERVER_PORT":          "9090",
		"SERVER_TLS_ENABLED":   "true",
		"AUTH_METHOD":          "api_key",
		"AUTH_API_KEYS":        "key1,key2,key3",
		"AUTH_JWT_SECRET":      "secret123",
		"AUTH_JWT_ISSUER":      "test-issuer",
		"AUTH_JWT_AUDIENCE":    "test-audience",
		"RATE_LIMIT_STORE":     "redis",
		"RATE_LIMIT_REDIS_URL": "redis://localhost:6379",
		"LOG_LEVEL":            "debug",
		"ARGON_MEMORY":         "32768",
		"ARGON_ITERATIONS":     "2",
		"ARGON_PARALLELISM":    "2",
		"ARGON_SALT_LENGTH":    "12",
		"ARGON_KEY_LENGTH":     "24",
		"SECRETS_MOUNT_PATH":   "/custom/secrets",
	}
}

func getCustomConfigExpected() *Config {
	return &Config{
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
	}
}

func getInvalidPortTestCase() configLoadTestCase {
	return configLoadTestCase{
		name: "Invalid port",
		envVars: map[string]string{
			"SERVER_PORT": "70000",
		},
		expected: nil,
		wantErr:  true,
	}
}

func getInvalidAuthMethodTestCase() configLoadTestCase {
	return configLoadTestCase{
		name: "Invalid auth method",
		envVars: map[string]string{
			"AUTH_METHOD": "invalid",
		},
		expected: nil,
		wantErr:  true,
	}
}

func getInvalidLogLevelTestCase() configLoadTestCase {
	return configLoadTestCase{
		name: "Invalid log level",
		envVars: map[string]string{
			"LOG_LEVEL": "invalid",
		},
		expected: nil,
		wantErr:  true,
	}
}

func getInvalidRateLimitStoreTestCase() configLoadTestCase {
	return configLoadTestCase{
		name: "Invalid rate limit store",
		envVars: map[string]string{
			"RATE_LIMIT_STORE": "invalid",
		},
		expected: nil,
		wantErr:  true,
	}
}

func getRedisStoreWithoutURLTestCase() configLoadTestCase {
	return configLoadTestCase{
		name: "Redis store without URL",
		envVars: map[string]string{
			"RATE_LIMIT_STORE": "redis",
		},
		expected: nil,
		wantErr:  true,
	}
}

func getAPIKeyAuthWithoutKeysTestCase() configLoadTestCase {
	return configLoadTestCase{
		name: "API key auth without keys",
		envVars: map[string]string{
			"AUTH_METHOD": "api_key",
		},
		expected: nil,
		wantErr:  true,
	}
}

func getJWTAuthWithoutSecretTestCase() configLoadTestCase {
	return configLoadTestCase{
		name: "JWT auth without secret",
		envVars: map[string]string{
			"AUTH_METHOD": "jwt",
		},
		expected: nil,
		wantErr:  true,
	}
}

func getInvalidArgonMemoryTestCase() configLoadTestCase {
	return configLoadTestCase{
		name: "Invalid Argon2 memory",
		envVars: map[string]string{
			"ARGON_MEMORY": "512",
		},
		expected: nil,
		wantErr:  true,
	}
}

func getInvalidArgonIterationsTestCase() configLoadTestCase {
	return configLoadTestCase{
		name: "Invalid Argon2 iterations",
		envVars: map[string]string{
			"ARGON_ITERATIONS": "0",
		},
		expected: nil,
		wantErr:  true,
	}
}

func executeConfigLoadTests(t *testing.T, tests []configLoadTestCase) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearEnv()

			for key, value := range tt.envVars {
				_ = os.Setenv(key, value)
			}

			config, err := Load()

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, config)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, config)
			}

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

	err = os.WriteFile(configFile, data, 0600)
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

	err = os.WriteFile(configFile, data, 0600)
	require.NoError(t, err)

	// Set environment variable to override file config
	_ = os.Setenv("SERVER_PORT", "8888")
	_ = os.Setenv("AUTH_JWT_SECRET", "env-secret")
	defer func() {
		_ = os.Unsetenv("SERVER_PORT")
		_ = os.Unsetenv("AUTH_JWT_SECRET")
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
	err := os.MkdirAll(secretsDir, 0750)
	require.NoError(t, err)

	// Create secret files
	err = os.WriteFile(filepath.Join(secretsDir, "jwt-secret"), []byte("mounted-jwt-secret"), 0600)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(secretsDir, "api-keys"), []byte("key1,key2,key3"), 0600)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(secretsDir, "redis-url"), []byte("redis://secret-redis:6379"), 0600)
	require.NoError(t, err)

	// Set secrets mount path
	_ = os.Setenv("SECRETS_MOUNT_PATH", secretsDir)
	_ = os.Setenv("AUTH_METHOD", "jwt")
	defer func() {
		_ = os.Unsetenv("SECRETS_MOUNT_PATH")
		_ = os.Unsetenv("AUTH_METHOD")
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
	err := os.MkdirAll(secretsDir, 0750)
	require.NoError(t, err)

	// Create secret file
	err = os.WriteFile(filepath.Join(secretsDir, "jwt-secret"), []byte("mounted-jwt-secret"), 0600)
	require.NoError(t, err)

	// Set environment variables (should take precedence over secrets)
	_ = os.Setenv("SECRETS_MOUNT_PATH", secretsDir)
	_ = os.Setenv("AUTH_METHOD", "jwt")
	_ = os.Setenv("AUTH_JWT_SECRET", "env-jwt-secret")
	defer func() {
		_ = os.Unsetenv("SECRETS_MOUNT_PATH")
		_ = os.Unsetenv("AUTH_METHOD")
		_ = os.Unsetenv("AUTH_JWT_SECRET")
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

	err := os.WriteFile(configFile, []byte("invalid json"), 0600)
	require.NoError(t, err)

	_, err = Load(LoadOptions{ConfigFile: configFile})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse configuration file")
}

func TestValidation(t *testing.T) {
	tests := getValidationTestCases()
	executeValidationTests(t, tests)
}

type validationTestCase struct {
	name   string
	config *Config
	errMsg string
}

func getValidationTestCases() []validationTestCase {
	return []validationTestCase{
		getValidJaegerTracingTestCase(),
		getInvalidJaegerTracingTestCase(),
		getInvalidOTLPTracingTestCase(),
	}
}

func getValidJaegerTracingTestCase() validationTestCase {
	return validationTestCase{
		name:   "Deprecated Jaeger exporter",
		config: createValidJaegerConfig(),
		errMsg: "jaeger exporter is deprecated",
	}
}

func getInvalidJaegerTracingTestCase() validationTestCase {
	return validationTestCase{
		name:   "Invalid tracing - Jaeger without endpoint",
		config: createInvalidJaegerConfig(),
		errMsg: "jaeger exporter is deprecated",
	}
}

func getInvalidOTLPTracingTestCase() validationTestCase {
	return validationTestCase{
		name:   "Invalid tracing - OTLP without endpoint",
		config: createInvalidOTLPConfig(),
		errMsg: "OTLP endpoint is required",
	}
}

func createValidJaegerConfig() *Config {
	return &Config{
		Server:    ServerConfig{Port: 8080},
		Auth:      AuthConfig{Method: "none"},
		Log:       LogConfig{Level: "info"},
		RateLimit: RateLimitConfig{Store: "memory"},
		Tracing: TracingConfig{
			Enabled:        true,
			Exporter:       "jaeger",
			JaegerEndpoint: "http://jaeger:14268/api/traces",
			SampleRate:     0.5,
		},
		Crypto: getDefaultCryptoConfig(),
	}
}

func createInvalidJaegerConfig() *Config {
	return &Config{
		Server:    ServerConfig{Port: 8080},
		Auth:      AuthConfig{Method: "none"},
		Log:       LogConfig{Level: "info"},
		RateLimit: RateLimitConfig{Store: "memory"},
		Tracing: TracingConfig{
			Enabled:  true,
			Exporter: "jaeger",
		},
		Crypto: getDefaultCryptoConfig(),
	}
}

func createInvalidOTLPConfig() *Config {
	return &Config{
		Server:    ServerConfig{Port: 8080},
		Auth:      AuthConfig{Method: "none"},
		Log:       LogConfig{Level: "info"},
		RateLimit: RateLimitConfig{Store: "memory"},
		Tracing: TracingConfig{
			Enabled:  true,
			Exporter: "otlp",
		},
		Crypto: getDefaultCryptoConfig(),
	}
}

func getDefaultCryptoConfig() CryptoConfig {
	return CryptoConfig{
		ArgonMemory:      65536,
		ArgonIterations:  3,
		ArgonParallelism: 4,
		ArgonSaltLength:  16,
		ArgonKeyLength:   32,
	}
}

func executeValidationTests(t *testing.T, tests []validationTestCase) {
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
		_ = os.Unsetenv(envVar)
	}
}
