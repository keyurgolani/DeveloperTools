package middleware

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	// Set Gin to test mode
	gin.SetMode(gin.TestMode)
	os.Exit(m.Run())
}

func createTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError, // Suppress logs during tests
	}))
}

func TestNoAuthMiddleware(t *testing.T) {
	logger := createTestLogger()
	middleware := NewNoAuthMiddleware(logger)

	router := gin.New()
	router.Use(middleware.Authenticate())
	router.GET("/test", func(c *gin.Context) {
		authMethod, _ := c.Get("auth_method")
		userID, _ := c.Get("user_id")
		c.JSON(http.StatusOK, gin.H{
			"auth_method": authMethod,
			"user_id":     userID,
		})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"auth_method":"none"`)
	assert.Contains(t, w.Body.String(), `"user_id":"anonymous"`)
}

func TestAPIKeyMiddleware_ValidKey(t *testing.T) {
	logger := createTestLogger()
	apiKeys := []string{"valid-key-1", "valid-key-2"}
	middleware := NewAPIKeyMiddleware(apiKeys, logger)

	router := gin.New()
	router.Use(middleware.Authenticate())
	router.GET("/test", func(c *gin.Context) {
		authMethod, _ := c.Get("auth_method")
		userID, _ := c.Get("user_id")
		c.JSON(http.StatusOK, gin.H{
			"auth_method": authMethod,
			"user_id":     userID,
		})
	})

	tests := []struct {
		name   string
		header string
		value  string
	}{
		{
			name:   "X-API-Key header",
			header: "X-API-Key",
			value:  "valid-key-1",
		},
		{
			name:   "Authorization Bearer header",
			header: "Authorization",
			value:  "Bearer valid-key-2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set(tt.header, tt.value)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
			assert.Contains(t, w.Body.String(), `"auth_method":"api_key"`)
			assert.Contains(t, w.Body.String(), `"user_id":"api_key_user"`)
		})
	}
}

func TestAPIKeyMiddleware_InvalidKey(t *testing.T) {
	logger := createTestLogger()
	apiKeys := []string{"valid-key"}
	middleware := NewAPIKeyMiddleware(apiKeys, logger)

	router := gin.New()
	router.Use(middleware.Authenticate())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	tests := []struct {
		name           string
		header         string
		value          string
		expectedCode   int
		expectedError  string
	}{
		{
			name:          "Missing API key",
			expectedCode:  http.StatusUnauthorized,
			expectedError: "MISSING_API_KEY",
		},
		{
			name:          "Invalid API key",
			header:        "X-API-Key",
			value:         "invalid-key",
			expectedCode:  http.StatusUnauthorized,
			expectedError: "INVALID_API_KEY",
		},
		{
			name:          "Empty API key",
			header:        "X-API-Key",
			value:         "",
			expectedCode:  http.StatusUnauthorized,
			expectedError: "MISSING_API_KEY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.header != "" {
				req.Header.Set(tt.header, tt.value)
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedCode, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectedError)
		})
	}
}

func TestJWTMiddleware_ValidToken(t *testing.T) {
	logger := createTestLogger()
	secret := "test-secret"
	issuer := "test-issuer"
	audience := "test-audience"
	middleware := NewJWTMiddleware(secret, issuer, audience, logger)

	router := gin.New()
	router.Use(middleware.Authenticate())
	router.GET("/test", func(c *gin.Context) {
		authMethod, _ := c.Get("auth_method")
		userID, _ := c.Get("user_id")
		claims, _ := c.Get("jwt_claims")
		c.JSON(http.StatusOK, gin.H{
			"auth_method": authMethod,
			"user_id":     userID,
			"claims":      claims,
		})
	})

	// Create a valid JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "test-user",
		"iss": issuer,
		"aud": audience,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	tokenString, err := token.SignedString([]byte(secret))
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"auth_method":"jwt"`)
	assert.Contains(t, w.Body.String(), `"user_id":"test-user"`)
}

func TestJWTMiddleware_InvalidToken(t *testing.T) {
	logger := createTestLogger()
	secret := "test-secret"
	middleware := NewJWTMiddleware(secret, "", "", logger)

	router := gin.New()
	router.Use(middleware.Authenticate())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	tests := []struct {
		name          string
		token         string
		expectedCode  int
		expectedError string
	}{
		{
			name:          "Missing token",
			expectedCode:  http.StatusUnauthorized,
			expectedError: "MISSING_TOKEN",
		},
		{
			name:          "Invalid token format",
			token:         "invalid-token",
			expectedCode:  http.StatusUnauthorized,
			expectedError: "INVALID_TOKEN",
		},
		{
			name:          "Expired token",
			token:         createExpiredToken(secret),
			expectedCode:  http.StatusUnauthorized,
			expectedError: "TOKEN_EXPIRED",
		},
		{
			name:          "Wrong signing method",
			token:         createTokenWithWrongMethod(),
			expectedCode:  http.StatusUnauthorized,
			expectedError: "INVALID_TOKEN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedCode, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectedError)
		})
	}
}

func TestJWTMiddleware_IssuerValidation(t *testing.T) {
	logger := createTestLogger()
	secret := "test-secret"
	expectedIssuer := "expected-issuer"
	middleware := NewJWTMiddleware(secret, expectedIssuer, "", logger)

	router := gin.New()
	router.Use(middleware.Authenticate())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Create token with wrong issuer
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "test-user",
		"iss": "wrong-issuer",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	tokenString, err := token.SignedString([]byte(secret))
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_ISSUER")
}

func TestJWTMiddleware_AudienceValidation(t *testing.T) {
	logger := createTestLogger()
	secret := "test-secret"
	expectedAudience := "expected-audience"
	middleware := NewJWTMiddleware(secret, "", expectedAudience, logger)

	router := gin.New()
	router.Use(middleware.Authenticate())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Create token with wrong audience
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "test-user",
		"aud": "wrong-audience",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	tokenString, err := token.SignedString([]byte(secret))
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_AUDIENCE")
}

func TestNewAuthMiddleware(t *testing.T) {
	logger := createTestLogger()

	tests := []struct {
		name        string
		config      *AuthConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "None auth",
			config: &AuthConfig{
				Method: AuthMethodNone,
			},
			expectError: false,
		},
		{
			name: "API key auth with keys",
			config: &AuthConfig{
				Method:  AuthMethodAPIKey,
				APIKeys: []string{"key1", "key2"},
			},
			expectError: false,
		},
		{
			name: "API key auth without keys",
			config: &AuthConfig{
				Method: AuthMethodAPIKey,
			},
			expectError: true,
			errorMsg:    "API keys must be provided",
		},
		{
			name: "JWT auth with secret",
			config: &AuthConfig{
				Method:    AuthMethodJWT,
				JWTSecret: "secret",
			},
			expectError: false,
		},
		{
			name: "JWT auth without secret",
			config: &AuthConfig{
				Method: AuthMethodJWT,
			},
			expectError: true,
			errorMsg:    "JWT secret must be provided",
		},
		{
			name: "Unsupported method",
			config: &AuthConfig{
				Method: "unsupported",
			},
			expectError: true,
			errorMsg:    "unsupported authentication method",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware, err := NewAuthMiddleware(tt.config, logger)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, middleware)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, middleware)
			}
		})
	}
}

// Helper functions for creating test tokens

func createExpiredToken(secret string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(-time.Hour).Unix(), // Expired 1 hour ago
	})

	tokenString, _ := token.SignedString([]byte(secret))
	return tokenString
}

func createTokenWithWrongMethod() string {
	// Create a token with HS256 but we'll manually construct it to have wrong method in header
	// This creates a properly formatted JWT but with wrong signing method
	header := `{"alg":"RS256","typ":"JWT"}`
	payload := `{"sub":"test-user","exp":` + fmt.Sprintf("%d", time.Now().Add(time.Hour).Unix()) + `}`
	
	// Base64 encode header and payload
	encodedHeader := base64.RawURLEncoding.EncodeToString([]byte(header))
	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(payload))
	
	// Create a fake signature (this will be invalid but properly formatted)
	fakeSignature := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))
	
	return encodedHeader + "." + encodedPayload + "." + fakeSignature
}