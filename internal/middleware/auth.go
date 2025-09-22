package middleware

import (
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// AuthMethod represents the authentication method type.
type AuthMethod string

const (
	AuthMethodNone   AuthMethod = "none"
	AuthMethodAPIKey AuthMethod = "api_key"
	AuthMethodJWT    AuthMethod = "jwt"
)

// AuthConfig holds authentication configuration.
type AuthConfig struct {
	Method      AuthMethod
	APIKeys     []string // Valid API keys for API key authentication
	JWTSecret   string   // Secret for JWT validation
	JWTIssuer   string   // Expected JWT issuer
	JWTAudience string   // Expected JWT audience
}

// AuthMiddleware interface defines the authentication middleware contract.
type AuthMiddleware interface {
	Authenticate() gin.HandlerFunc
}

// NoAuthMiddleware implements no authentication.
type NoAuthMiddleware struct {
	logger *slog.Logger
}

// NewNoAuthMiddleware creates a new no-auth middleware.
func NewNoAuthMiddleware(logger *slog.Logger) *NoAuthMiddleware {
	return &NoAuthMiddleware{
		logger: logger,
	}
}

// Authenticate returns a middleware that allows all requests.
func (m *NoAuthMiddleware) Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Set anonymous user context
		c.Set("auth_method", "none")
		c.Set("user_id", "anonymous")
		c.Next()
	}
}

// APIKeyMiddleware implements API key authentication.
type APIKeyMiddleware struct {
	validKeys map[string]bool
	logger    *slog.Logger
}

// NewAPIKeyMiddleware creates a new API key middleware.
func NewAPIKeyMiddleware(apiKeys []string, logger *slog.Logger) *APIKeyMiddleware {
	validKeys := make(map[string]bool)
	for _, key := range apiKeys {
		if key != "" {
			validKeys[key] = true
		}
	}

	return &APIKeyMiddleware{
		validKeys: validKeys,
		logger:    logger,
	}
}

// Authenticate returns a middleware that validates API keys.
func (m *APIKeyMiddleware) Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check for API key in header
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			// Also check Authorization header with Bearer prefix
			authHeader := c.GetHeader("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				apiKey = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if apiKey == "" {
			m.logger.Warn("Missing API key", "path", c.Request.URL.Path, "ip", c.ClientIP())
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": gin.H{
					"code":    "MISSING_API_KEY",
					"message": "API key is required",
				},
			})
			c.Abort()
			return
		}

		// Validate API key using constant-time comparison
		valid := false
		for validKey := range m.validKeys {
			if subtle.ConstantTimeCompare([]byte(apiKey), []byte(validKey)) == 1 {
				valid = true
				break
			}
		}

		if !valid {
			m.logger.Warn("Invalid API key", "path", c.Request.URL.Path, "ip", c.ClientIP())
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": gin.H{
					"code":    "INVALID_API_KEY",
					"message": "Invalid API key",
				},
			})
			c.Abort()
			return
		}

		// Set authenticated user context
		c.Set("auth_method", "api_key")
		c.Set("user_id", "api_key_user")
		c.Next()
	}
}

// JWTMiddleware implements JWT authentication.
type JWTMiddleware struct {
	secret   []byte
	issuer   string
	audience string
	logger   *slog.Logger
}

// NewJWTMiddleware creates a new JWT middleware.
func NewJWTMiddleware(secret, issuer, audience string, logger *slog.Logger) *JWTMiddleware {
	return &JWTMiddleware{
		secret:   []byte(secret),
		issuer:   issuer,
		audience: audience,
		logger:   logger,
	}
}

// Authenticate returns a middleware that validates JWT tokens.
func (m *JWTMiddleware) Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := m.extractToken(c)
		if err != nil {
			m.handleAuthError(c, "MISSING_TOKEN", "Bearer token is required")
			return
		}

		token, err := m.parseToken(tokenString)
		if err != nil {
			m.handleTokenParseError(c, err)
			return
		}

		claims, err := m.validateToken(token, c)
		if err != nil {
			return // Error already handled in validateToken
		}

		err = m.validateClaims(claims, c)
		if err != nil {
			return // Error already handled in validateClaims
		}

		m.setUserContext(c, claims)
		c.Next()
	}
}

// extractToken extracts the JWT token from the Authorization header.
func (m *JWTMiddleware) extractToken(c *gin.Context) (string, error) {
	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		m.logger.Warn("Missing or invalid Authorization header", "path", c.Request.URL.Path, "ip", c.ClientIP())
		return "", fmt.Errorf("missing bearer token")
	}
	return strings.TrimPrefix(authHeader, "Bearer "), nil
}

// parseToken parses and validates the JWT token structure.
func (m *JWTMiddleware) parseToken(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.secret, nil
	})
}

// validateToken validates the token and extracts claims.
func (m *JWTMiddleware) validateToken(token *jwt.Token, c *gin.Context) (jwt.MapClaims, error) {
	if !token.Valid {
		m.logger.Warn("Invalid JWT token", "path", c.Request.URL.Path, "ip", c.ClientIP())
		m.handleAuthError(c, "INVALID_TOKEN", "Invalid token")
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		m.logger.Warn("Invalid JWT claims", "path", c.Request.URL.Path, "ip", c.ClientIP())
		m.handleAuthError(c, "INVALID_CLAIMS", "Invalid token claims")
		return nil, fmt.Errorf("invalid claims")
	}

	return claims, nil
}

// validateClaims validates JWT claims (issuer, audience, expiration).
func (m *JWTMiddleware) validateClaims(claims jwt.MapClaims, c *gin.Context) error {
	if err := m.validateIssuer(claims, c); err != nil {
		return err
	}
	if err := m.validateAudience(claims, c); err != nil {
		return err
	}
	return m.validateExpiration(claims, c)
}

// validateIssuer validates the JWT issuer claim.
func (m *JWTMiddleware) validateIssuer(claims jwt.MapClaims, c *gin.Context) error {
	if m.issuer == "" {
		return nil
	}

	iss, ok := claims["iss"].(string)
	if !ok || iss != m.issuer {
		m.logger.Warn("Invalid JWT issuer", "expected", m.issuer, "got", claims["iss"], "path", c.Request.URL.Path)
		m.handleAuthError(c, "INVALID_ISSUER", "Invalid token issuer")
		return fmt.Errorf("invalid issuer")
	}
	return nil
}

// validateAudience validates the JWT audience claim.
func (m *JWTMiddleware) validateAudience(claims jwt.MapClaims, c *gin.Context) error {
	if m.audience == "" {
		return nil
	}

	aud, ok := claims["aud"].(string)
	if !ok || aud != m.audience {
		m.logger.Warn("Invalid JWT audience", "expected", m.audience, "got", claims["aud"], "path", c.Request.URL.Path)
		m.handleAuthError(c, "INVALID_AUDIENCE", "Invalid token audience")
		return fmt.Errorf("invalid audience")
	}
	return nil
}

// validateExpiration validates the JWT expiration claim.
func (m *JWTMiddleware) validateExpiration(claims jwt.MapClaims, c *gin.Context) error {
	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil
	}

	if time.Now().Unix() > int64(exp) {
		m.logger.Warn("Expired JWT token", "path", c.Request.URL.Path, "ip", c.ClientIP())
		m.handleAuthError(c, "TOKEN_EXPIRED", "Token has expired")
		return fmt.Errorf("token expired")
	}
	return nil
}

// setUserContext sets the authenticated user context.
func (m *JWTMiddleware) setUserContext(c *gin.Context, claims jwt.MapClaims) {
	c.Set("auth_method", "jwt")
	if sub, ok := claims["sub"].(string); ok {
		c.Set("user_id", sub)
	} else {
		c.Set("user_id", "jwt_user")
	}
	c.Set("jwt_claims", claims)
}

// handleTokenParseError handles JWT token parsing errors.
func (m *JWTMiddleware) handleTokenParseError(c *gin.Context, err error) {
	m.logger.Warn("JWT parsing error", "error", err.Error(), "path", c.Request.URL.Path, "ip", c.ClientIP())

	if strings.Contains(err.Error(), "token is expired") {
		m.handleAuthError(c, "TOKEN_EXPIRED", "Token has expired")
	} else {
		m.handleAuthError(c, "INVALID_TOKEN", "Invalid or expired token")
	}
}

// handleAuthError handles authentication errors with consistent response format.
func (m *JWTMiddleware) handleAuthError(c *gin.Context, code, message string) {
	c.JSON(http.StatusUnauthorized, gin.H{
		"error": gin.H{
			"code":    code,
			"message": message,
		},
	})
	c.Abort()
}

// NewAuthMiddleware creates the appropriate authentication middleware based on config.
func NewAuthMiddleware(config *AuthConfig, logger *slog.Logger) (AuthMiddleware, error) {
	switch config.Method {
	case AuthMethodNone:
		return NewNoAuthMiddleware(logger), nil
	case AuthMethodAPIKey:
		if len(config.APIKeys) == 0 {
			return nil, fmt.Errorf("API keys must be provided for API key authentication")
		}
		return NewAPIKeyMiddleware(config.APIKeys, logger), nil
	case AuthMethodJWT:
		if config.JWTSecret == "" {
			return nil, fmt.Errorf("JWT secret must be provided for JWT authentication")
		}
		return NewJWTMiddleware(config.JWTSecret, config.JWTIssuer, config.JWTAudience, logger), nil
	default:
		return nil, fmt.Errorf("unsupported authentication method: %s", config.Method)
	}
}
