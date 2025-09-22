//go:build performance

package performance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keyurgolani/DeveloperTools/internal/config"
	"github.com/keyurgolani/DeveloperTools/internal/logging"
	"github.com/keyurgolani/DeveloperTools/internal/metrics"
	"github.com/keyurgolani/DeveloperTools/internal/server"
	"github.com/keyurgolani/DeveloperTools/pkg/apierror"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// PerformanceTestSuite contains all performance-related tests
type PerformanceTestSuite struct {
	suite.Suite
	server *server.Server
	router *gin.Engine
}

// SetupSuite runs once before all tests
func (suite *PerformanceTestSuite) SetupSuite() {
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:       8080,
			TLSEnabled: false,
		},
		Log: config.LogConfig{
			Level: "error", // Reduce log noise during performance tests
		},
		Auth: config.AuthConfig{
			Method: "none",
		},
		RateLimit: config.RateLimitConfig{
			Store: "memory", // Use memory store for performance testing
		},
		Tracing: config.TracingConfig{
			Enabled: false, // Disable for performance testing
		},
	}

	logger := logging.New(cfg.Log.Level)
	suite.server = server.New(cfg, logger)
	suite.router = suite.server.GetRouter()
}

// TestCryptoPerformance tests performance of cryptographic operations
func (suite *PerformanceTestSuite) TestCryptoPerformance() {
	suite.Run("Hash performance", func() {
		algorithms := []string{"md5", "sha1", "sha256", "sha512"}
		contentSizes := []int{100, 1024, 10240, 102400} // 100B, 1KB, 10KB, 100KB

		for _, algorithm := range algorithms {
			for _, size := range contentSizes {
				suite.Run(fmt.Sprintf("%s_%dB", algorithm, size), func() {
					content := strings.Repeat("a", size)
					payload := map[string]interface{}{
						"content":   content,
						"algorithm": algorithm,
					}

					body, _ := json.Marshal(payload)

					// Measure performance
					start := time.Now()
					w := httptest.NewRecorder()
					req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/crypto/hash", bytes.NewBuffer(body))
					req.Header.Set("Content-Type", "application/json")
					suite.router.ServeHTTP(w, req)
					duration := time.Since(start)

					assert.Equal(suite.T(), http.StatusOK, w.Code)

					var response apierror.SuccessResponse
					err := json.Unmarshal(w.Body.Bytes(), &response)
					require.NoError(suite.T(), err)
					assert.True(suite.T(), response.Success)

					// Performance assertions
					maxDuration := 100 * time.Millisecond // Should complete within 100ms
					if size > 10240 {                     // For larger payloads, allow more time
						maxDuration = 500 * time.Millisecond
					}

					assert.True(suite.T(), duration < maxDuration,
						"Hash operation took too long: %v (max: %v) for %s with %dB",
						duration, maxDuration, algorithm, size)

					suite.T().Logf("%s hash of %dB took %v", algorithm, size, duration)
				})
			}
		}
	})

	suite.Run("Password hashing performance", func() {
		passwords := []string{
			"short",
			"medium_length_password",
			"very_long_password_with_many_characters_to_test_performance_impact",
		}

		for _, password := range passwords {
			suite.Run(fmt.Sprintf("password_len_%d", len(password)), func() {
				payload := map[string]interface{}{
					"password": password,
				}

				body, _ := json.Marshal(payload)

				start := time.Now()
				w := httptest.NewRecorder()
				req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/crypto/password/hash", bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")
				suite.router.ServeHTTP(w, req)
				duration := time.Since(start)

				assert.Equal(suite.T(), http.StatusOK, w.Code)

				var response apierror.SuccessResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(suite.T(), err)
				assert.True(suite.T(), response.Success)

				// Argon2id should take reasonable time (not too fast, not too slow)
				minDuration := 10 * time.Millisecond // Should take at least 10ms (security)
				maxDuration := 2 * time.Second       // Should complete within 2s (usability)

				assert.True(suite.T(), duration >= minDuration,
					"Password hashing too fast (potential security issue): %v", duration)
				assert.True(suite.T(), duration <= maxDuration,
					"Password hashing too slow: %v", duration)

				suite.T().Logf("Password hashing (len=%d) took %v", len(password), duration)
			})
		}
	})

	suite.Run("HMAC performance", func() {
		contentSizes := []int{100, 1024, 10240, 102400}
		algorithms := []string{"sha256", "sha512"}

		for _, algorithm := range algorithms {
			for _, size := range contentSizes {
				suite.Run(fmt.Sprintf("%s_%dB", algorithm, size), func() {
					content := strings.Repeat("a", size)
					payload := map[string]interface{}{
						"content":   content,
						"key":       "test_key",
						"algorithm": algorithm,
					}

					body, _ := json.Marshal(payload)

					start := time.Now()
					w := httptest.NewRecorder()
					req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/crypto/hmac", bytes.NewBuffer(body))
					req.Header.Set("Content-Type", "application/json")
					suite.router.ServeHTTP(w, req)
					duration := time.Since(start)

					assert.Equal(suite.T(), http.StatusOK, w.Code)

					maxDuration := 100 * time.Millisecond
					if size > 10240 {
						maxDuration = 500 * time.Millisecond
					}

					assert.True(suite.T(), duration < maxDuration,
						"HMAC operation took too long: %v for %s with %dB",
						duration, algorithm, size)
				})
			}
		}
	})
}

// TestTextProcessingPerformance tests performance of text operations
func (suite *PerformanceTestSuite) TestTextProcessingPerformance() {
	suite.Run("Case conversion performance", func() {
		textSizes := []int{100, 1024, 10240, 102400} // 100B to 100KB
		caseTypes := []string{"UPPERCASE", "lowercase", "camelCase", "snake_case"}

		for _, caseType := range caseTypes {
			for _, size := range textSizes {
				suite.Run(fmt.Sprintf("%s_%dB", caseType, size), func() {
					content := strings.Repeat("hello world test ", size/17) // Approximate size
					payload := map[string]interface{}{
						"content":  content,
						"caseType": caseType,
					}

					body, _ := json.Marshal(payload)

					start := time.Now()
					w := httptest.NewRecorder()
					req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/text/case", bytes.NewBuffer(body))
					req.Header.Set("Content-Type", "application/json")
					suite.router.ServeHTTP(w, req)
					duration := time.Since(start)

					assert.Equal(suite.T(), http.StatusOK, w.Code)

					maxDuration := 50 * time.Millisecond
					if size > 10240 {
						maxDuration = 200 * time.Millisecond
					}

					assert.True(suite.T(), duration < maxDuration,
						"Case conversion took too long: %v for %s with ~%dB",
						duration, caseType, size)
				})
			}
		}
	})

	suite.Run("Text analysis performance", func() {
		textSizes := []int{1024, 10240, 102400, 1024000} // 1KB to 1MB

		for _, size := range textSizes {
			suite.Run(fmt.Sprintf("analysis_%dB", size), func() {
				// Create text with varied content (words, lines, sentences)
				content := strings.Repeat("Hello world! This is a test sentence.\nNew line here. ", size/55)
				payload := map[string]interface{}{
					"content": content,
				}

				body, _ := json.Marshal(payload)

				start := time.Now()
				w := httptest.NewRecorder()
				req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/text/info", bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")
				suite.router.ServeHTTP(w, req)
				duration := time.Since(start)

				assert.Equal(suite.T(), http.StatusOK, w.Code)

				var response apierror.SuccessResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(suite.T(), err)
				assert.True(suite.T(), response.Success)

				maxDuration := 100 * time.Millisecond
				if size > 102400 {
					maxDuration = 1 * time.Second
				}

				assert.True(suite.T(), duration < maxDuration,
					"Text analysis took too long: %v for ~%dB", duration, size)

				suite.T().Logf("Text analysis of ~%dB took %v", size, duration)
			})
		}
	})

	suite.Run("Regex performance", func() {
		patterns := []struct {
			name    string
			pattern string
			content string
		}{
			{
				name:    "simple_word_match",
				pattern: "\\btest\\b",
				content: strings.Repeat("This is a test sentence with test words. ", 1000),
			},
			{
				name:    "email_pattern",
				pattern: "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
				content: strings.Repeat("Contact us at test@example.com or admin@test.org. ", 1000),
			},
			{
				name:    "number_extraction",
				pattern: "\\d+",
				content: strings.Repeat("The year 2023 has 365 days and 12 months. ", 1000),
			},
		}

		for _, tt := range patterns {
			suite.Run(tt.name, func() {
				payload := map[string]interface{}{
					"content": tt.content,
					"pattern": tt.pattern,
				}

				body, _ := json.Marshal(payload)

				start := time.Now()
				w := httptest.NewRecorder()
				req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/text/regex", bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")
				suite.router.ServeHTTP(w, req)
				duration := time.Since(start)

				assert.Equal(suite.T(), http.StatusOK, w.Code)

				maxDuration := 100 * time.Millisecond
				assert.True(suite.T(), duration < maxDuration,
					"Regex operation took too long: %v for pattern %s", duration, tt.pattern)
			})
		}
	})
}

// TestConcurrentLoad tests performance under concurrent load
func (suite *PerformanceTestSuite) TestConcurrentLoad() {
	suite.Run("Concurrent hash operations", func() {
		const numGoroutines = 50
		const requestsPerGoroutine = 10

		var wg sync.WaitGroup
		results := make(chan time.Duration, numGoroutines*requestsPerGoroutine)
		errors := make(chan error, numGoroutines*requestsPerGoroutine)

		payload := map[string]interface{}{
			"content":   "test content for concurrent hashing",
			"algorithm": "sha256",
		}
		body, _ := json.Marshal(payload)

		start := time.Now()

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				for j := 0; j < requestsPerGoroutine; j++ {
					reqStart := time.Now()

					w := httptest.NewRecorder()
					req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/crypto/hash", bytes.NewBuffer(body))
					req.Header.Set("Content-Type", "application/json")
					suite.router.ServeHTTP(w, req)

					reqDuration := time.Since(reqStart)
					results <- reqDuration

					if w.Code != http.StatusOK {
						errors <- fmt.Errorf("request failed with status %d", w.Code)
					}
				}
			}()
		}

		wg.Wait()
		totalDuration := time.Since(start)
		close(results)
		close(errors)

		// Collect results
		var durations []time.Duration
		for duration := range results {
			durations = append(durations, duration)
		}

		// Check for errors
		errorCount := 0
		for range errors {
			errorCount++
		}

		assert.Equal(suite.T(), 0, errorCount, "No requests should fail under concurrent load")
		assert.Equal(suite.T(), numGoroutines*requestsPerGoroutine, len(durations),
			"All requests should complete")

		// Calculate statistics
		var totalReqDuration time.Duration
		maxDuration := time.Duration(0)
		minDuration := time.Hour

		for _, d := range durations {
			totalReqDuration += d
			if d > maxDuration {
				maxDuration = d
			}
			if d < minDuration {
				minDuration = d
			}
		}

		avgDuration := totalReqDuration / time.Duration(len(durations))
		throughput := float64(len(durations)) / totalDuration.Seconds()

		suite.T().Logf("Concurrent load test results:")
		suite.T().Logf("  Total requests: %d", len(durations))
		suite.T().Logf("  Total time: %v", totalDuration)
		suite.T().Logf("  Throughput: %.2f req/sec", throughput)
		suite.T().Logf("  Avg response time: %v", avgDuration)
		suite.T().Logf("  Min response time: %v", minDuration)
		suite.T().Logf("  Max response time: %v", maxDuration)

		// Performance assertions
		assert.True(suite.T(), throughput > 100, "Throughput should be > 100 req/sec, got %.2f", throughput)
		assert.True(suite.T(), avgDuration < 100*time.Millisecond,
			"Average response time should be < 100ms, got %v", avgDuration)
		assert.True(suite.T(), maxDuration < 1*time.Second,
			"Max response time should be < 1s, got %v", maxDuration)
	})

	suite.Run("Mixed operation load", func() {
		const numGoroutines = 20
		const requestsPerGoroutine = 5

		endpoints := []struct {
			path    string
			payload map[string]interface{}
		}{
			{
				path: "/api/v1/crypto/hash",
				payload: map[string]interface{}{
					"content":   "test",
					"algorithm": "sha256",
				},
			},
			{
				path: "/api/v1/text/case",
				payload: map[string]interface{}{
					"content":  "hello world",
					"caseType": "UPPERCASE",
				},
			},
			{
				path: "/api/v1/transform/base64",
				payload: map[string]interface{}{
					"content": "hello world",
					"action":  "encode",
				},
			},
			{
				path: "/api/v1/id/uuid",
				payload: map[string]interface{}{
					"version": 4,
					"count":   1,
				},
			},
		}

		var wg sync.WaitGroup
		results := make(chan time.Duration, numGoroutines*requestsPerGoroutine)
		errors := make(chan error, numGoroutines*requestsPerGoroutine)

		start := time.Now()

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(goroutineID int) {
				defer wg.Done()

				for j := 0; j < requestsPerGoroutine; j++ {
					endpoint := endpoints[(goroutineID+j)%len(endpoints)]

					body, _ := json.Marshal(endpoint.payload)
					reqStart := time.Now()

					w := httptest.NewRecorder()
					req, _ := http.NewRequestWithContext(context.Background(), "POST", endpoint.path, bytes.NewBuffer(body))
					req.Header.Set("Content-Type", "application/json")
					suite.router.ServeHTTP(w, req)

					reqDuration := time.Since(reqStart)
					results <- reqDuration

					if w.Code != http.StatusOK {
						errors <- fmt.Errorf("request to %s failed with status %d", endpoint.path, w.Code)
					}
				}
			}(i)
		}

		wg.Wait()
		totalDuration := time.Since(start)
		close(results)
		close(errors)

		// Check results
		var durations []time.Duration
		for duration := range results {
			durations = append(durations, duration)
		}

		errorCount := 0
		for range errors {
			errorCount++
		}

		assert.Equal(suite.T(), 0, errorCount, "No requests should fail under mixed load")

		throughput := float64(len(durations)) / totalDuration.Seconds()
		suite.T().Logf("Mixed load throughput: %.2f req/sec", throughput)

		assert.True(suite.T(), throughput > 50, "Mixed load throughput should be > 50 req/sec")
	})
}

// TestMemoryUsage tests memory usage patterns
func (suite *PerformanceTestSuite) TestMemoryUsage() {
	suite.Run("Memory usage under load", func() {
		runtime.GC() // Clean up before test

		var m1 runtime.MemStats
		runtime.ReadMemStats(&m1)

		// Perform many operations
		for i := 0; i < 1000; i++ {
			payload := map[string]interface{}{
				"content":   fmt.Sprintf("test content %d", i),
				"algorithm": "sha256",
			}

			body, _ := json.Marshal(payload)
			w := httptest.NewRecorder()
			req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/crypto/hash", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			suite.router.ServeHTTP(w, req)

			assert.Equal(suite.T(), http.StatusOK, w.Code)
		}

		runtime.GC() // Force garbage collection

		var m2 runtime.MemStats
		runtime.ReadMemStats(&m2)

		var memoryIncrease uint64
		if m2.Alloc > m1.Alloc {
			memoryIncrease = m2.Alloc - m1.Alloc
		} else {
			memoryIncrease = 0 // Memory usage decreased or stayed same
		}
		suite.T().Logf("Memory usage increase: %d bytes", memoryIncrease)

		// Memory increase should be reasonable (less than 10MB for 1000 operations)
		maxMemoryIncrease := uint64(10 * 1024 * 1024) // 10MB
		assert.True(suite.T(), memoryIncrease < maxMemoryIncrease,
			"Memory usage increased too much: %d bytes", memoryIncrease)
	})
}

// TestRateLimitPerformance tests rate limiting performance impact
func (suite *PerformanceTestSuite) TestRateLimitPerformance() {
	suite.Run("Rate limit overhead", func() {
		// This test would require enabling rate limiting
		// For now, we'll test without rate limiting and document the expected behavior

		const numRequests = 100
		durations := make([]time.Duration, numRequests)

		payload := map[string]interface{}{
			"content":   "test",
			"algorithm": "sha256",
		}
		body, _ := json.Marshal(payload)

		for i := 0; i < numRequests; i++ {
			start := time.Now()

			w := httptest.NewRecorder()
			req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/crypto/hash", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			suite.router.ServeHTTP(w, req)

			durations[i] = time.Since(start)
			assert.Equal(suite.T(), http.StatusOK, w.Code)
		}

		// Calculate average duration
		var total time.Duration
		for _, d := range durations {
			total += d
		}
		avgDuration := total / time.Duration(numRequests)

		suite.T().Logf("Average request duration (no rate limiting): %v", avgDuration)

		// Without rate limiting, requests should be fast
		assert.True(suite.T(), avgDuration < 50*time.Millisecond,
			"Requests should be fast without rate limiting")
	})
}

// Benchmark functions for detailed performance analysis
func BenchmarkCryptoOperations(b *testing.B) {
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		Server:    config.ServerConfig{Port: 8080, TLSEnabled: false},
		Log:       config.LogConfig{Level: "error"},
		Auth:      config.AuthConfig{Method: "none"},
		RateLimit: config.RateLimitConfig{Store: "memory"},
		Tracing:   config.TracingConfig{Enabled: false},
	}

	logger := logging.New(cfg.Log.Level)
	// Create a separate metrics registry for benchmarks to avoid conflicts
	benchmarkRegistry := prometheus.NewRegistry()
	benchmarkMetrics := metrics.NewWithRegistry(benchmarkRegistry)
	srv := server.NewWithMetrics(cfg, logger, benchmarkMetrics)
	router := srv.GetRouter()

	b.Run("SHA256Hash", func(b *testing.B) {
		payload := map[string]interface{}{
			"content":   "hello world",
			"algorithm": "sha256",
		}
		body, _ := json.Marshal(payload)

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				w := httptest.NewRecorder()
				req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/crypto/hash", bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")
				router.ServeHTTP(w, req)

				if w.Code != http.StatusOK {
					b.Errorf("Expected status 200, got %d", w.Code)
				}
			}
		})
	})

	b.Run("PasswordHash", func(b *testing.B) {
		payload := map[string]interface{}{
			"password": "testpassword123",
		}
		body, _ := json.Marshal(payload)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/crypto/password/hash", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				b.Errorf("Expected status 200, got %d", w.Code)
			}
		}
	})
}

func BenchmarkTextOperations(b *testing.B) {
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		Server:    config.ServerConfig{Port: 8080, TLSEnabled: false},
		Log:       config.LogConfig{Level: "error"},
		Auth:      config.AuthConfig{Method: "none"},
		RateLimit: config.RateLimitConfig{Store: "memory"},
		Tracing:   config.TracingConfig{Enabled: false},
	}

	logger := logging.New(cfg.Log.Level)
	// Create a separate metrics registry for benchmarks to avoid conflicts
	benchmarkRegistry := prometheus.NewRegistry()
	benchmarkMetrics := metrics.NewWithRegistry(benchmarkRegistry)
	srv := server.NewWithMetrics(cfg, logger, benchmarkMetrics)
	router := srv.GetRouter()

	b.Run("CaseConversion", func(b *testing.B) {
		payload := map[string]interface{}{
			"content":  "hello world test case conversion",
			"caseType": "UPPERCASE",
		}
		body, _ := json.Marshal(payload)

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				w := httptest.NewRecorder()
				req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/text/case", bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")
				router.ServeHTTP(w, req)

				if w.Code != http.StatusOK {
					b.Errorf("Expected status 200, got %d", w.Code)
				}
			}
		})
	})

	b.Run("TextAnalysis", func(b *testing.B) {
		payload := map[string]interface{}{
			"content": "Hello world! This is a test sentence.\nAnother line here. More text for analysis.",
		}
		body, _ := json.Marshal(payload)

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				w := httptest.NewRecorder()
				req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/text/info", bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")
				router.ServeHTTP(w, req)

				if w.Code != http.StatusOK {
					b.Errorf("Expected status 200, got %d", w.Code)
				}
			}
		})
	})
}

// Run the performance test suite
func TestPerformanceSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance tests in short mode")
	}

	suite.Run(t, new(PerformanceTestSuite))
}
