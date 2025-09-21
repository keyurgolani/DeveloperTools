package middleware

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// RateLimit defines rate limiting configuration
type RateLimit struct {
	RequestsPerMinute int           `json:"requestsPerMinute"`
	BurstSize         int           `json:"burstSize"`
	WindowSize        time.Duration `json:"windowSize"`
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	Store     string                `json:"store"`     // "memory" or "redis"
	RedisURL  string                `json:"redisUrl"`  // Redis connection URL
	Limits    map[string]RateLimit  `json:"limits"`    // Rate limits by operation type
	Default   RateLimit             `json:"default"`   // Default rate limit
}

// RateLimitStore interface defines the storage backend for rate limiting
type RateLimitStore interface {
	Allow(ctx context.Context, key string, limit RateLimit) (bool, error)
	Reset(ctx context.Context, key string) error
	Close() error
}

// TokenBucket represents a token bucket for rate limiting
type TokenBucket struct {
	tokens     int
	capacity   int
	refillRate int // tokens per minute
	lastRefill time.Time
	mutex      sync.Mutex
}

// NewTokenBucket creates a new token bucket
func NewTokenBucket(capacity, refillRate int) *TokenBucket {
	return &TokenBucket{
		tokens:     capacity,
		capacity:   capacity,
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

// Allow checks if a request is allowed and consumes a token if so
func (tb *TokenBucket) Allow() bool {
	tb.mutex.Lock()
	defer tb.mutex.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastRefill)

	// Refill tokens based on elapsed time
	tokensToAdd := int(elapsed.Minutes() * float64(tb.refillRate))
	if tokensToAdd > 0 {
		tb.tokens = min(tb.capacity, tb.tokens+tokensToAdd)
		tb.lastRefill = now
	}

	// Check if we have tokens available
	if tb.tokens > 0 {
		tb.tokens--
		return true
	}

	return false
}

// MemoryRateLimitStore implements in-memory rate limiting storage
type MemoryRateLimitStore struct {
	buckets map[string]*TokenBucket
	mutex   sync.RWMutex
	logger  *slog.Logger
}

// NewMemoryRateLimitStore creates a new in-memory rate limit store
func NewMemoryRateLimitStore(logger *slog.Logger) *MemoryRateLimitStore {
	store := &MemoryRateLimitStore{
		buckets: make(map[string]*TokenBucket),
		logger:  logger,
	}

	// Start cleanup goroutine to remove old buckets
	go store.cleanup()

	return store
}

// Allow checks if a request is allowed for the given key and limit
func (m *MemoryRateLimitStore) Allow(ctx context.Context, key string, limit RateLimit) (bool, error) {
	m.mutex.Lock()
	bucket, exists := m.buckets[key]
	if !exists {
		bucket = NewTokenBucket(limit.BurstSize, limit.RequestsPerMinute)
		m.buckets[key] = bucket
	}
	m.mutex.Unlock()

	return bucket.Allow(), nil
}

// Reset resets the rate limit for the given key
func (m *MemoryRateLimitStore) Reset(ctx context.Context, key string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	delete(m.buckets, key)
	return nil
}

// Close closes the store (no-op for memory store)
func (m *MemoryRateLimitStore) Close() error {
	return nil
}

// cleanup removes old unused buckets
func (m *MemoryRateLimitStore) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		m.mutex.Lock()
		// In a real implementation, we'd track last access time
		// For now, we'll keep all buckets
		m.mutex.Unlock()
	}
}

// RedisRateLimitStore implements Redis-backed rate limiting storage
type RedisRateLimitStore struct {
	client *redis.Client
	logger *slog.Logger
}

// NewRedisRateLimitStore creates a new Redis rate limit store
func NewRedisRateLimitStore(redisURL string, logger *slog.Logger) (*RedisRateLimitStore, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	client := redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisRateLimitStore{
		client: client,
		logger: logger,
	}, nil
}

// Allow checks if a request is allowed using Redis-based token bucket
func (r *RedisRateLimitStore) Allow(ctx context.Context, key string, limit RateLimit) (bool, error) {
	// Use Lua script for atomic token bucket operations
	script := `
		local key = KEYS[1]
		local capacity = tonumber(ARGV[1])
		local refill_rate = tonumber(ARGV[2])
		local now = tonumber(ARGV[3])
		
		local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
		local tokens = tonumber(bucket[1]) or capacity
		local last_refill = tonumber(bucket[2]) or now
		
		-- Calculate tokens to add based on elapsed time
		local elapsed_minutes = (now - last_refill) / 60
		local tokens_to_add = math.floor(elapsed_minutes * refill_rate)
		
		if tokens_to_add > 0 then
			tokens = math.min(capacity, tokens + tokens_to_add)
			last_refill = now
		end
		
		-- Check if we can consume a token
		if tokens > 0 then
			tokens = tokens - 1
			redis.call('HMSET', key, 'tokens', tokens, 'last_refill', last_refill)
			redis.call('EXPIRE', key, 3600) -- Expire after 1 hour of inactivity
			return 1
		else
			redis.call('HMSET', key, 'tokens', tokens, 'last_refill', last_refill)
			redis.call('EXPIRE', key, 3600)
			return 0
		end
	`

	result, err := r.client.Eval(ctx, script, []string{key}, 
		limit.BurstSize, limit.RequestsPerMinute, time.Now().Unix()).Result()
	if err != nil {
		return false, fmt.Errorf("Redis rate limit check failed: %w", err)
	}

	allowed, ok := result.(int64)
	if !ok {
		return false, fmt.Errorf("unexpected Redis response type: %T", result)
	}

	return allowed == 1, nil
}

// Reset resets the rate limit for the given key
func (r *RedisRateLimitStore) Reset(ctx context.Context, key string) error {
	return r.client.Del(ctx, key).Err()
}

// Close closes the Redis connection
func (r *RedisRateLimitStore) Close() error {
	return r.client.Close()
}

// RateLimitMiddleware implements rate limiting middleware
type RateLimitMiddleware struct {
	store  RateLimitStore
	config *RateLimitConfig
	logger *slog.Logger
}

// NewRateLimitMiddleware creates a new rate limiting middleware
func NewRateLimitMiddleware(config *RateLimitConfig, logger *slog.Logger) (*RateLimitMiddleware, error) {
	var store RateLimitStore
	var err error

	switch strings.ToLower(config.Store) {
	case "memory":
		store = NewMemoryRateLimitStore(logger)
	case "redis":
		if config.RedisURL == "" {
			return nil, fmt.Errorf("Redis URL is required for Redis store")
		}
		store, err = NewRedisRateLimitStore(config.RedisURL, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create Redis store: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported rate limit store: %s", config.Store)
	}

	return &RateLimitMiddleware{
		store:  store,
		config: config,
		logger: logger,
	}, nil
}

// Limit returns a middleware that enforces rate limiting
func (m *RateLimitMiddleware) Limit() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Determine client identifier
		clientID := m.getClientID(c)
		
		// Determine operation type for rate limiting
		operationType := m.getOperationType(c)
		
		// Get rate limit for this operation
		limit := m.getRateLimit(operationType)
		
		// Create rate limit key
		key := fmt.Sprintf("rate_limit:%s:%s", clientID, operationType)
		
		// Check rate limit
		ctx := c.Request.Context()
		allowed, err := m.store.Allow(ctx, key, limit)
		if err != nil {
			m.logger.Error("Rate limit check failed", "error", err, "key", key)
			// On error, allow the request but log the issue
			c.Next()
			return
		}
		
		if !allowed {
			m.logger.Warn("Rate limit exceeded", 
				"client_id", clientID, 
				"operation", operationType,
				"limit", limit.RequestsPerMinute,
				"path", c.Request.URL.Path,
			)
			
			// Add rate limit headers
			c.Header("X-RateLimit-Limit", strconv.Itoa(limit.RequestsPerMinute))
			c.Header("X-RateLimit-Remaining", "0")
			c.Header("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10))
			
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": gin.H{
					"code":    "RATE_LIMIT_EXCEEDED",
					"message": "Rate limit exceeded. Please try again later.",
					"details": fmt.Sprintf("Limit: %d requests per minute", limit.RequestsPerMinute),
				},
			})
			c.Abort()
			return
		}
		
		// Add rate limit headers for successful requests
		c.Header("X-RateLimit-Limit", strconv.Itoa(limit.RequestsPerMinute))
		// Note: Getting remaining count would require additional Redis call
		// For now, we'll omit it to avoid performance impact
		
		c.Next()
	}
}

// getClientID determines the client identifier for rate limiting
func (m *RateLimitMiddleware) getClientID(c *gin.Context) string {
	// Try to get authenticated user ID first
	if userID, exists := c.Get("user_id"); exists {
		if uid, ok := userID.(string); ok && uid != "anonymous" {
			return uid
		}
	}
	
	// Fall back to IP address for anonymous users
	return c.ClientIP()
}

// getOperationType determines the operation type for rate limiting
func (m *RateLimitMiddleware) getOperationType(c *gin.Context) string {
	path := c.Request.URL.Path
	
	// Define operation types based on path patterns
	switch {
	case strings.HasPrefix(path, "/api/v1/crypto/"):
		return "crypto"
	case strings.HasPrefix(path, "/api/v1/network/"):
		return "network"
	case strings.HasPrefix(path, "/api/v1/"):
		return "api"
	case strings.HasPrefix(path, "/health"):
		return "health"
	default:
		return "default"
	}
}

// getRateLimit gets the rate limit for the given operation type
func (m *RateLimitMiddleware) getRateLimit(operationType string) RateLimit {
	if limit, exists := m.config.Limits[operationType]; exists {
		return limit
	}
	return m.config.Default
}

// Close closes the rate limit store
func (m *RateLimitMiddleware) Close() error {
	return m.store.Close()
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}