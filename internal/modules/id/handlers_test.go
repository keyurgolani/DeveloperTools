package id

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	
	service := NewService()
	handler := NewHandler(service, nil) // Pass nil for metrics in tests
	
	v1 := router.Group("/api/v1")
	handler.RegisterRoutes(v1)
	
	return router
}

func TestHandler_GenerateUUID(t *testing.T) {
	router := setupTestRouter()

	tests := []struct {
		name           string
		requestBody    interface{}
		expectedStatus int
		expectSuccess  bool
		expectError    string
	}{
		{
			name: "Valid UUID v4 request",
			requestBody: UUIDRequest{
				Version: 4,
				Count:   1,
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
		},
		{
			name: "Valid UUID v1 request",
			requestBody: UUIDRequest{
				Version: 1,
				Count:   1,
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
		},
		{
			name: "Multiple UUIDs",
			requestBody: UUIDRequest{
				Version: 4,
				Count:   5,
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
		},
		{
			name: "Default count (zero)",
			requestBody: UUIDRequest{
				Version: 4,
				Count:   0,
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
		},
		{
			name: "Invalid version",
			requestBody: UUIDRequest{
				Version: 3,
				Count:   1,
			},
			expectedStatus: http.StatusBadRequest,
			expectSuccess:  false,
			expectError:    "INVALID_REQUEST",
		},
		{
			name: "Count exceeds limit",
			requestBody: UUIDRequest{
				Version: 4,
				Count:   MaxUUIDCount + 1,
			},
			expectedStatus: http.StatusBadRequest,
			expectSuccess:  false,
			expectError:    "UUID_GENERATION_FAILED",
		},
		{
			name: "Invalid version in binding",
			requestBody: UUIDRequest{
				Version: 2,
				Count:   1,
			},
			expectedStatus: http.StatusBadRequest,
			expectSuccess:  false,
			expectError:    "INVALID_REQUEST",
		},
		{
			name:           "Invalid JSON",
			requestBody:    "invalid json",
			expectedStatus: http.StatusBadRequest,
			expectSuccess:  false,
			expectError:    "INVALID_REQUEST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body bytes.Buffer
			if str, ok := tt.requestBody.(string); ok {
				body.WriteString(str)
			} else {
				err := json.NewEncoder(&body).Encode(tt.requestBody)
				require.NoError(t, err)
			}

			req, err := http.NewRequest("POST", "/api/v1/id/uuid", &body)
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)

			if tt.expectSuccess {
				assert.True(t, response["success"].(bool))
				assert.Contains(t, response, "data")
				
				data := response["data"].(map[string]interface{})
				uuids := data["uuids"].([]interface{})
				
				expectedCount := tt.requestBody.(UUIDRequest).Count
				if expectedCount <= 0 {
					expectedCount = DefaultCount
				}
				
				assert.Len(t, uuids, expectedCount)
				
				// Validate UUID format
				for _, uuidInterface := range uuids {
					uuidStr := uuidInterface.(string)
					assert.Regexp(t, `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`, uuidStr)
				}
			} else {
				assert.Contains(t, response, "error")
				errorObj := response["error"].(map[string]interface{})
				assert.Equal(t, tt.expectError, errorObj["code"])
			}
		})
	}
}

func TestHandler_GenerateNanoID(t *testing.T) {
	router := setupTestRouter()

	tests := []struct {
		name           string
		requestBody    interface{}
		expectedStatus int
		expectSuccess  bool
		expectError    string
	}{
		{
			name: "Valid Nano ID request",
			requestBody: NanoIDRequest{
				Size:  21,
				Count: 1,
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
		},
		{
			name: "Custom size",
			requestBody: NanoIDRequest{
				Size:  10,
				Count: 1,
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
		},
		{
			name: "Multiple Nano IDs",
			requestBody: NanoIDRequest{
				Size:  21,
				Count: 5,
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
		},
		{
			name: "Default values (zero)",
			requestBody: NanoIDRequest{
				Size:  0,
				Count: 0,
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
		},
		{
			name: "Max size",
			requestBody: NanoIDRequest{
				Size:  MaxNanoIDSize,
				Count: 1,
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
		},
		{
			name: "Size exceeds limit",
			requestBody: NanoIDRequest{
				Size:  MaxNanoIDSize + 1,
				Count: 1,
			},
			expectedStatus: http.StatusBadRequest,
			expectSuccess:  false,
			expectError:    "NANOID_GENERATION_FAILED",
		},
		{
			name: "Count exceeds limit",
			requestBody: NanoIDRequest{
				Size:  21,
				Count: MaxNanoIDCount + 1,
			},
			expectedStatus: http.StatusBadRequest,
			expectSuccess:  false,
			expectError:    "NANOID_GENERATION_FAILED",
		},
		{
			name:           "Invalid JSON",
			requestBody:    "invalid json",
			expectedStatus: http.StatusBadRequest,
			expectSuccess:  false,
			expectError:    "INVALID_REQUEST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body bytes.Buffer
			if str, ok := tt.requestBody.(string); ok {
				body.WriteString(str)
			} else {
				err := json.NewEncoder(&body).Encode(tt.requestBody)
				require.NoError(t, err)
			}

			req, err := http.NewRequest("POST", "/api/v1/id/nanoid", &body)
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)

			if tt.expectSuccess {
				assert.True(t, response["success"].(bool))
				assert.Contains(t, response, "data")
				
				data := response["data"].(map[string]interface{})
				ids := data["ids"].([]interface{})
				
				expectedCount := tt.requestBody.(NanoIDRequest).Count
				if expectedCount <= 0 {
					expectedCount = DefaultCount
				}
				
				expectedSize := tt.requestBody.(NanoIDRequest).Size
				if expectedSize <= 0 {
					expectedSize = DefaultNanoIDSize
				}
				
				assert.Len(t, ids, expectedCount)
				
				// Validate Nano ID format and size
				for _, idInterface := range ids {
					idStr := idInterface.(string)
					assert.Len(t, idStr, expectedSize)
					
					// Check URL-safe characters
					for _, char := range idStr {
						assert.True(t, isURLSafeChar(char), "Nano ID should contain only URL-safe characters: %s", idStr)
					}
				}
			} else {
				assert.Contains(t, response, "error")
				errorObj := response["error"].(map[string]interface{})
				assert.Equal(t, tt.expectError, errorObj["code"])
			}
		})
	}
}

func TestHandler_EmptyRequest(t *testing.T) {
	router := setupTestRouter()

	// Test empty request body for UUID
	req, err := http.NewRequest("POST", "/api/v1/id/uuid", bytes.NewBuffer([]byte("{}")))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Test empty request body for Nano ID (should work with defaults)
	req, err = http.NewRequest("POST", "/api/v1/id/nanoid", bytes.NewBuffer([]byte("{}")))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}