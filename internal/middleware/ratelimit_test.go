package middleware_test

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/keyurgolani/DeveloperTools/internal/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenBucket(t *testing.T) {
	t.Run("Initial capacity", func(t *testing.T) {
		bucket := middleware.NewTokenBucket(5, 60) // 5 tokens, 60 per minute

		// Should allow 5 requests initially
		for i := 0; i < 5; i++ {
			assert.True(t, bucket.Allow(), "Request %d should be allowed", i+1)
		}

		// 6th request should be denied
		assert.False(t, bucket.Allow(), "6th request should be denied")
	})

	t.Run("Token refill", func(t *testing.T) {
		bucket := middleware.NewTokenBucket(2, 120) // 2 tokens, 120 per minute (2 per second)

		// Consume all tokens
		assert.True(t, bucket.Allow())
		assert.True(t, bucket.Allow())
		assert.False(t, bucket.Allow())

		// Wait for refill (simulate 1 second = 2 tokens)
		bucket.SetLastRefillForTesting(time.Now().Add(-time.Second))

		// Should allow 2 more requests
		assert.True(t, bucket.Allow())
		assert.True(t, bucket.Allow())
		assert.False(t, bucket.Allow())
	})

	t.Run("Capacity limit", func(t *testing.T) {
		bucket := middleware.NewTokenBucket(3, 60)

		// Consume one token
		assert.True(t, bucket.Allow())

		// Simulate long wait (should refill to capacity, not beyond)
		bucket.SetLastRefillForTesting(time.Now().Add(-10 * time.Minute))

		// Should allow exactly 3 requests (capacity limit)
		assert.True(t, bucket.Allow())
		assert.True(t, bucket.Allow())
		assert.True(t, bucket.Allow())
		assert.False(t, bucket.Allow())
	})
}

func TestMemoryRateLimitStore(t *testing.T) {
	logger := createTestLogger()
	store := middleware.NewMemoryRateLimitStore(logger)
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	limit := createTestRateLimit()

	testAllowRequestsWithinLimit(t, store, ctx, limit)
	testDifferentKeysHaveSeparateLimits(t, store, ctx, limit)
	testResetFunctionality(t, store, ctx, limit)
}

func createTestRateLimit() middleware.RateLimit {
	return middleware.RateLimit{
		RequestsPerMinute: 60,
		BurstSize:         5,
		WindowSize:        time.Minute,
	}
}

func testAllowRequestsWithinLimit(
	t *testing.T, store middleware.RateLimitStore, ctx context.Context, limit middleware.RateLimit) {
	t.Run("Allow requests within limit", func(t *testing.T) {
		key := "test-key-1"

		// Should allow burst size requests
		for i := 0; i < limit.BurstSize; i++ {
			allowed, err := store.Allow(ctx, key, limit)
			require.NoError(t, err)
			assert.True(t, allowed, "Request %d should be allowed", i+1)
		}

		// Next request should be denied
		allowed, err := store.Allow(ctx, key, limit)
		require.NoError(t, err)
		assert.False(t, allowed, "Request beyond burst should be denied")
	})
}

func testDifferentKeysHaveSeparateLimits(
	t *testing.T, store middleware.RateLimitStore, ctx context.Context, limit middleware.RateLimit) {
	t.Run("Different keys have separate limits", func(t *testing.T) {
		key1 := "test-key-2"
		key2 := "test-key-3"

		// Exhaust limit for key1
		for i := 0; i < limit.BurstSize; i++ {
			allowed, err := store.Allow(ctx, key1, limit)
			require.NoError(t, err)
			assert.True(t, allowed)
		}

		// key1 should be denied
		allowed, err := store.Allow(ctx, key1, limit)
		require.NoError(t, err)
		assert.False(t, allowed)

		// key2 should still be allowed
		allowed, err = store.Allow(ctx, key2, limit)
		require.NoError(t, err)
		assert.True(t, allowed)
	})
}

func testResetFunctionality(
	t *testing.T, store middleware.RateLimitStore, ctx context.Context, limit middleware.RateLimit) {
	t.Run("Reset functionality", func(t *testing.T) {
		key := "test-key-4"

		// Exhaust limit
		for i := 0; i < limit.BurstSize; i++ {
			allowed, err := store.Allow(ctx, key, limit)
			require.NoError(t, err)
			assert.True(t, allowed)
		}

		// Should be denied
		allowed, err := store.Allow(ctx, key, limit)
		require.NoError(t, err)
		assert.False(t, allowed)

		// Reset the key
		err = store.Reset(ctx, key)
		require.NoError(t, err)

		// Should be allowed again
		allowed, err = store.Allow(ctx, key, limit)
		require.NoError(t, err)
		assert.True(t, allowed)
	})
}

func TestRateLimitMiddleware_Memory(t *testing.T) {
	logger := createTestLogger()
	config := createRateLimitTestConfig()
	middleware, router := setupRateLimitTest(t, config, logger)
	defer func() { _ = middleware.Close() }()

	testAPIEndpointRateLimit(t, router)
	testCryptoEndpointRateLimit(t, router)
	testDifferentIPsHaveSeparateLimits(t, router)
	testAuthenticatedUsersUseUserID(t, middleware)
}

func createRateLimitTestConfig() *middleware.RateLimitConfig {
	return &middleware.RateLimitConfig{
		Store: "memory",
		Limits: map[string]middleware.RateLimit{
			"api": {
				RequestsPerMinute: 60,
				BurstSize:         5,
				WindowSize:        time.Minute,
			},
			"crypto": {
				RequestsPerMinute: 30,
				BurstSize:         3,
				WindowSize:        time.Minute,
			},
		},
		Default: middleware.RateLimit{
			RequestsPerMinute: 100,
			BurstSize:         10,
			WindowSize:        time.Minute,
		},
	}
}

func setupRateLimitTest(
	t *testing.T, config *middleware.RateLimitConfig, logger *slog.Logger,
) (*middleware.RateLimitMiddleware, *gin.Engine) {
	middlewareInstance, err := middleware.NewRateLimitMiddleware(config, logger)
	require.NoError(t, err)

	router := gin.New()
	router.Use(middlewareInstance.Limit())
	router.GET("/api/v1/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})
	router.GET("/api/v1/crypto/hash", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	return middlewareInstance, router
}

func testAPIEndpointRateLimit(t *testing.T, router *gin.Engine) {
	t.Run("API endpoint rate limiting", func(t *testing.T) {
		// Should allow burst size requests
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest("GET", "/api/v1/test", nil)
			req.Header.Set("X-Forwarded-For", "192.168.1.100")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code, "Request %d should be allowed", i+1)
			assert.Equal(t, "60", w.Header().Get("X-RateLimit-Limit"))
		}

		// Next request should be rate limited
		req := httptest.NewRequest("GET", "/api/v1/test", nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.100")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusTooManyRequests, w.Code)
		assert.Contains(t, w.Body.String(), "RATE_LIMIT_EXCEEDED")
		assert.Equal(t, "60", w.Header().Get("X-RateLimit-Limit"))
		assert.Equal(t, "0", w.Header().Get("X-RateLimit-Remaining"))
	})
}

func testCryptoEndpointRateLimit(t *testing.T, router *gin.Engine) {
	t.Run("Crypto endpoint stricter rate limiting", func(t *testing.T) {
		// Should allow only 3 requests for crypto endpoints
		for i := 0; i < 3; i++ {
			req := httptest.NewRequest("GET", "/api/v1/crypto/hash", nil)
			req.Header.Set("X-Forwarded-For", "192.168.1.101")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code, "Request %d should be allowed", i+1)
			assert.Equal(t, "30", w.Header().Get("X-RateLimit-Limit"))
		}

		// 4th request should be rate limited
		req := httptest.NewRequest("GET", "/api/v1/crypto/hash", nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.101")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusTooManyRequests, w.Code)
		assert.Contains(t, w.Body.String(), "30 requests per minute")
	})
}

func testDifferentIPsHaveSeparateLimits(t *testing.T, router *gin.Engine) {
	t.Run("Different IPs have separate limits", func(t *testing.T) {
		// Exhaust limit for first IP
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest("GET", "/api/v1/test", nil)
			req.Header.Set("X-Forwarded-For", "192.168.1.102")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		}

		// First IP should be rate limited
		req := httptest.NewRequest("GET", "/api/v1/test", nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.102")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code)

		// Second IP should still be allowed
		req = httptest.NewRequest("GET", "/api/v1/test", nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.103")
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func testAuthenticatedUsersUseUserID(t *testing.T, middlewareInstance *middleware.RateLimitMiddleware) {
	t.Run("Authenticated users use user ID", func(t *testing.T) {
		authRouter := setupAuthenticatedRouter(middlewareInstance)

		// Should use user ID instead of IP for rate limiting
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest("GET", "/api/v1/test", nil)
			req.Header.Set("X-Forwarded-For", fmt.Sprintf("192.168.1.%d", 104+i))
			w := httptest.NewRecorder()
			authRouter.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code, "Request %d should be allowed", i+1)
		}

		// Should be rate limited despite different IP
		req := httptest.NewRequest("GET", "/api/v1/test", nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.200")
		w := httptest.NewRecorder()
		authRouter.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code)
	})
}

func setupAuthenticatedRouter(middlewareInstance *middleware.RateLimitMiddleware) *gin.Engine {
	authRouter := gin.New()
	authRouter.Use(func(c *gin.Context) {
		c.Set("user_id", "test-user-123")
		c.Next()
	})
	authRouter.Use(middlewareInstance.Limit())
	authRouter.GET("/api/v1/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})
	return authRouter
}

func TestRateLimitMiddleware_Configuration(t *testing.T) {
	logger := createTestLogger()

	t.Run("Valid memory configuration", func(t *testing.T) {
		config := &middleware.RateLimitConfig{
			Store: "memory",
			Default: middleware.RateLimit{
				RequestsPerMinute: 100,
				BurstSize:         10,
				WindowSize:        time.Minute,
			},
		}

		middlewareInstance, err := middleware.NewRateLimitMiddleware(config, logger)
		assert.NoError(t, err)
		assert.NotNil(t, middlewareInstance)
		_ = middlewareInstance.Close()
	})

	t.Run("Invalid store type", func(t *testing.T) {
		config := &middleware.RateLimitConfig{
			Store: "invalid",
		}

		middlewareInstance, err := middleware.NewRateLimitMiddleware(config, logger)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported rate limit store")
		assert.Nil(t, middlewareInstance)
	})

	t.Run("Redis without URL", func(t *testing.T) {
		config := &middleware.RateLimitConfig{
			Store: "redis",
		}

		middlewareInstance, err := middleware.NewRateLimitMiddleware(config, logger)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "redis URL is required")
		assert.Nil(t, middlewareInstance)
	})
}
