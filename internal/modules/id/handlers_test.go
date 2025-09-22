package id_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/keyurgolani/DeveloperTools/internal/modules/id"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	service := id.NewService()
	handler := id.NewHandler(service, nil) // Pass nil for metrics in tests

	v1 := router.Group("/api/v1")
	handler.RegisterRoutes(v1)

	return router
}

func TestHandler_GenerateUUID(t *testing.T) {
	router := setupTestRouter()
	tests := getUUIDGenerationTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executeUUIDGenerationTest(t, router, tt)
		})
	}
}

func getValidUUIDTestCases() []struct {
	name           string
	requestBody    interface{}
	expectedStatus int
	expectSuccess  bool
	expectError    string
} {
	return []struct {
		name           string
		requestBody    interface{}
		expectedStatus int
		expectSuccess  bool
		expectError    string
	}{
		{
			name: "Valid UUID v4 request",
			requestBody: id.UUIDRequest{
				Version: 4,
				Count:   1,
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
		},
		{
			name: "Valid UUID v1 request",
			requestBody: id.UUIDRequest{
				Version: 1,
				Count:   1,
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
		},
		{
			name: "Multiple UUIDs",
			requestBody: id.UUIDRequest{
				Version: 4,
				Count:   5,
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
		},
		{
			name: "Default count (zero)",
			requestBody: id.UUIDRequest{
				Version: 4,
				Count:   0,
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
		},
	}
}

func getInvalidUUIDTestCases() []struct {
	name           string
	requestBody    interface{}
	expectedStatus int
	expectSuccess  bool
	expectError    string
} {
	return []struct {
		name           string
		requestBody    interface{}
		expectedStatus int
		expectSuccess  bool
		expectError    string
	}{
		{
			name: "Invalid version",
			requestBody: id.UUIDRequest{
				Version: 3,
				Count:   1,
			},
			expectedStatus: http.StatusBadRequest,
			expectSuccess:  false,
			expectError:    "INVALID_REQUEST",
		},
		{
			name: "Count exceeds limit",
			requestBody: id.UUIDRequest{
				Version: 4,
				Count:   id.MaxUUIDCount + 1,
			},
			expectedStatus: http.StatusBadRequest,
			expectSuccess:  false,
			expectError:    "UUID_GENERATION_FAILED",
		},
		{
			name: "Invalid version in binding",
			requestBody: id.UUIDRequest{
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
}

func getUUIDGenerationTestCases() []struct {
	name           string
	requestBody    interface{}
	expectedStatus int
	expectSuccess  bool
	expectError    string
} {
	var testCases []struct {
		name           string
		requestBody    interface{}
		expectedStatus int
		expectSuccess  bool
		expectError    string
	}

	testCases = append(testCases, getValidUUIDTestCases()...)
	testCases = append(testCases, getInvalidUUIDTestCases()...)

	return testCases
}

func executeUUIDGenerationTest(t *testing.T, router *gin.Engine, tt struct {
	name           string
	requestBody    interface{}
	expectedStatus int
	expectSuccess  bool
	expectError    string
}) {
	body := prepareRequestBody(t, tt.requestBody)
	req := createUUIDRequest(t, body)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, tt.expectedStatus, w.Code)
	verifyUUIDResponse(t, w, tt)
}

func prepareRequestBody(t *testing.T, requestBody interface{}) *bytes.Buffer {
	var body bytes.Buffer
	if str, ok := requestBody.(string); ok {
		body.WriteString(str)
	} else {
		err := json.NewEncoder(&body).Encode(requestBody)
		require.NoError(t, err)
	}
	return &body
}

func createUUIDRequest(t *testing.T, body *bytes.Buffer) *http.Request {
	req, err := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/id/uuid", body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	return req
}

func verifyUUIDResponse(t *testing.T, w *httptest.ResponseRecorder, tt struct {
	name           string
	requestBody    interface{}
	expectedStatus int
	expectSuccess  bool
	expectError    string
}) {
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	if tt.expectSuccess {
		verifySuccessfulUUIDResponse(t, response, tt.requestBody)
	} else {
		verifyErrorUUIDResponse(t, response, tt.expectError)
	}
}

func verifySuccessfulUUIDResponse(t *testing.T, response map[string]interface{}, requestBody interface{}) {
	assert.True(t, response["success"].(bool))
	assert.Contains(t, response, "data")

	data := response["data"].(map[string]interface{})
	uuids := data["uuids"].([]interface{})

	expectedCount := requestBody.(id.UUIDRequest).Count
	if expectedCount <= 0 {
		expectedCount = id.DefaultCount
	}

	assert.Len(t, uuids, expectedCount)

	// Validate UUID format
	for _, uuidInterface := range uuids {
		uuidStr := uuidInterface.(string)
		assert.Regexp(t, `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`, uuidStr)
	}
}

func verifyErrorUUIDResponse(t *testing.T, response map[string]interface{}, expectError string) {
	assert.Contains(t, response, "error")
	errorObj := response["error"].(map[string]interface{})
	assert.Equal(t, expectError, errorObj["code"])
}

func getValidNanoIDTestCases() []struct {
	name           string
	requestBody    interface{}
	expectedStatus int
	expectSuccess  bool
	expectError    string
} {
	return []struct {
		name           string
		requestBody    interface{}
		expectedStatus int
		expectSuccess  bool
		expectError    string
	}{
		{
			name: "Valid Nano ID request",
			requestBody: id.NanoIDRequest{
				Size:  21,
				Count: 1,
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
		},
		{
			name: "Custom size",
			requestBody: id.NanoIDRequest{
				Size:  10,
				Count: 1,
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
		},
		{
			name: "Multiple Nano IDs",
			requestBody: id.NanoIDRequest{
				Size:  21,
				Count: 5,
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
		},
		{
			name: "Default values (zero)",
			requestBody: id.NanoIDRequest{
				Size:  0,
				Count: 0,
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
		},
		{
			name: "Max size",
			requestBody: id.NanoIDRequest{
				Size:  id.MaxNanoIDSize,
				Count: 1,
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
		},
	}
}

func getInvalidNanoIDTestCases() []struct {
	name           string
	requestBody    interface{}
	expectedStatus int
	expectSuccess  bool
	expectError    string
} {
	return []struct {
		name           string
		requestBody    interface{}
		expectedStatus int
		expectSuccess  bool
		expectError    string
	}{
		{
			name: "Size exceeds limit",
			requestBody: id.NanoIDRequest{
				Size:  id.MaxNanoIDSize + 1,
				Count: 1,
			},
			expectedStatus: http.StatusBadRequest,
			expectSuccess:  false,
			expectError:    "NANOID_GENERATION_FAILED",
		},
		{
			name: "Count exceeds limit",
			requestBody: id.NanoIDRequest{
				Size:  21,
				Count: id.MaxNanoIDCount + 1,
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
}

func getNanoIDTestCases() []struct {
	name           string
	requestBody    interface{}
	expectedStatus int
	expectSuccess  bool
	expectError    string
} {
	var testCases []struct {
		name           string
		requestBody    interface{}
		expectedStatus int
		expectSuccess  bool
		expectError    string
	}

	testCases = append(testCases, getValidNanoIDTestCases()...)
	testCases = append(testCases, getInvalidNanoIDTestCases()...)

	return testCases
}

func executeNanoIDTest(t *testing.T, router *gin.Engine, tt struct {
	name           string
	requestBody    interface{}
	expectedStatus int
	expectSuccess  bool
	expectError    string
}) {
	var body bytes.Buffer
	if str, ok := tt.requestBody.(string); ok {
		body.WriteString(str)
	} else {
		err := json.NewEncoder(&body).Encode(tt.requestBody)
		require.NoError(t, err)
	}

	req, err := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/id/nanoid", &body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, tt.expectedStatus, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	if tt.expectSuccess {
		verifySuccessfulNanoIDResponse(t, response, tt.requestBody)
	} else {
		verifyErrorNanoIDResponse(t, response, tt.expectError)
	}
}

func verifySuccessfulNanoIDResponse(t *testing.T, response map[string]interface{}, requestBody interface{}) {
	assert.True(t, response["success"].(bool))
	assert.Contains(t, response, "data")

	data := response["data"].(map[string]interface{})
	ids := data["ids"].([]interface{})

	expectedCount := requestBody.(id.NanoIDRequest).Count
	if expectedCount <= 0 {
		expectedCount = id.DefaultCount
	}

	expectedSize := requestBody.(id.NanoIDRequest).Size
	if expectedSize <= 0 {
		expectedSize = id.DefaultNanoIDSize
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
}

func verifyErrorNanoIDResponse(t *testing.T, response map[string]interface{}, expectError string) {
	assert.Contains(t, response, "error")
	errorObj := response["error"].(map[string]interface{})
	assert.Equal(t, expectError, errorObj["code"])
}

func TestHandler_GenerateNanoID(t *testing.T) {
	router := setupTestRouter()
	tests := getNanoIDTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executeNanoIDTest(t, router, tt)
		})
	}
}

func TestHandler_EmptyRequest(t *testing.T) {
	router := setupTestRouter()

	// Test empty request body for UUID
	req, err := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/id/uuid", bytes.NewBuffer([]byte("{}")))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Test empty request body for Nano ID (should work with defaults)
	req, err = http.NewRequestWithContext(context.Background(), "POST", "/api/v1/id/nanoid", bytes.NewBuffer([]byte("{}")))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
