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

// AuthMethod represents the authentication method type
type AuthMethod string

const (
	AuthMethodNone   AuthMethod = "none"
	AuthMethodAPIKey AuthMethod = "api_key"
	AuthMethodJWT    AuthMethod = "jwt"
)

// AuthConfig holds authentication configuration
type AuthConfig struct {
	Method     AuthMethod
	APIKeys    []string // Valid API keys for API key authentication
	JWTSecret  string   // Secret for JWT validation
	JWTIssuer  string   // Expected JWT issuer
	JWTAudience string  // Expected JWT audience
}

// AuthMiddleware interface defines the authentication middleware contract
type AuthMiddleware interface {
	Authenticate() gin.HandlerFunc
}

// NoAuthMiddleware implements no authentication
type NoAuthMiddleware struct {
	logger *slog.Logger
}

// NewNoAuthMiddleware creates a new no-auth middleware
func NewNoAuthMiddleware(logger *slog.Logger) *NoAuthMiddleware {
	return &NoAuthMiddleware{
		logger: logger,
	}
}

// Authenticate returns a middleware that allows all requests
func (m *NoAuthMiddleware) Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Set anonymous user context
		c.Set("auth_method", "none")
		c.Set("user_id", "anonymous")
		c.Next()
	}
}

// APIKeyMiddleware implements API key authentication
type APIKeyMiddleware struct {
	validKeys map[string]bool
	logger    *slog.Logger
}

// NewAPIKeyMiddleware creates a new API key middleware
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

// Authenticate returns a middleware that validates API keys
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

// JWTMiddleware implements JWT authentication
type JWTMiddleware struct {
	secret   []byte
	issuer   string
	audience string
	logger   *slog.Logger
}

// NewJWTMiddleware creates a new JWT middleware
func NewJWTMiddleware(secret, issuer, audience string, logger *slog.Logger) *JWTMiddleware {
	return &JWTMiddleware{
		secret:   []byte(secret),
		issuer:   issuer,
		audience: audience,
		logger:   logger,
	}
}

// Authenticate returns a middleware that validates JWT tokens
func (m *JWTMiddleware) Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			m.logger.Warn("Missing or invalid Authorization header", "path", c.Request.URL.Path, "ip", c.ClientIP())
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": gin.H{
					"code":    "MISSING_TOKEN",
					"message": "Bearer token is required",
				},
			})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// Parse and validate JWT token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Validate signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return m.secret, nil
		})

		if err != nil {
			m.logger.Warn("JWT parsing error", "error", err.Error(), "path", c.Request.URL.Path, "ip", c.ClientIP())
			
			// Check if the error is specifically about token expiration
			if strings.Contains(err.Error(), "token is expired") {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error": gin.H{
						"code":    "TOKEN_EXPIRED",
						"message": "Token has expired",
					},
				})
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error": gin.H{
						"code":    "INVALID_TOKEN",
						"message": "Invalid or expired token",
					},
				})
			}
			c.Abort()
			return
		}

		// Validate token and claims
		if !token.Valid {
			m.logger.Warn("Invalid JWT token", "path", c.Request.URL.Path, "ip", c.ClientIP())
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": gin.H{
					"code":    "INVALID_TOKEN",
					"message": "Invalid token",
				},
			})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			m.logger.Warn("Invalid JWT claims", "path", c.Request.URL.Path, "ip", c.ClientIP())
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": gin.H{
					"code":    "INVALID_CLAIMS",
					"message": "Invalid token claims",
				},
			})
			c.Abort()
			return
		}

		// Validate issuer if configured
		if m.issuer != "" {
			if iss, ok := claims["iss"].(string); !ok || iss != m.issuer {
				m.logger.Warn("Invalid JWT issuer", "expected", m.issuer, "got", claims["iss"], "path", c.Request.URL.Path)
				c.JSON(http.StatusUnauthorized, gin.H{
					"error": gin.H{
						"code":    "INVALID_ISSUER",
						"message": "Invalid token issuer",
					},
				})
				c.Abort()
				return
			}
		}

		// Validate audience if configured
		if m.audience != "" {
			if aud, ok := claims["aud"].(string); !ok || aud != m.audience {
				m.logger.Warn("Invalid JWT audience", "expected", m.audience, "got", claims["aud"], "path", c.Request.URL.Path)
				c.JSON(http.StatusUnauthorized, gin.H{
					"error": gin.H{
						"code":    "INVALID_AUDIENCE",
						"message": "Invalid token audience",
					},
				})
				c.Abort()
				return
			}
		}

		// Validate expiration
		if exp, ok := claims["exp"].(float64); ok {
			if time.Now().Unix() > int64(exp) {
				m.logger.Warn("Expired JWT token", "path", c.Request.URL.Path, "ip", c.ClientIP())
				c.JSON(http.StatusUnauthorized, gin.H{
					"error": gin.H{
						"code":    "TOKEN_EXPIRED",
						"message": "Token has expired",
					},
				})
				c.Abort()
				return
			}
		}

		// Set authenticated user context
		c.Set("auth_method", "jwt")
		if sub, ok := claims["sub"].(string); ok {
			c.Set("user_id", sub)
		} else {
			c.Set("user_id", "jwt_user")
		}
		c.Set("jwt_claims", claims)
		c.Next()
	}
}

// NewAuthMiddleware creates the appropriate authentication middleware based on config
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