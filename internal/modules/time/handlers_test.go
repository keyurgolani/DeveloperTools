package time_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/keyurgolani/DeveloperTools/internal/modules/time"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	service := time.NewService()
	handler := time.NewHandler(service, nil) // Pass nil for metrics in tests

	v1 := router.Group("/api/v1")
	handler.RegisterRoutes(v1)

	return router
}

func TestHandler_ConvertTime(t *testing.T) {
	router := setupTestRouter()

	req, err := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/time/convert", bytes.NewBuffer([]byte(`{
		"input": "1703518245",
		"inputFormat": "unix",
		"outputFormat": "iso8601"
	}`)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.True(t, response["success"].(bool))
	data := response["data"].(map[string]interface{})
	assert.Equal(t, "2023-12-25T15:30:45Z", data["result"])
}

func TestHandler_GetCurrentTime(t *testing.T) {
	router := setupTestRouter()

	req, err := http.NewRequestWithContext(context.Background(), "GET", "/api/v1/time/now", nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.True(t, response["success"].(bool))
	data := response["data"].(map[string]interface{})

	// Verify all required fields are present
	assert.Contains(t, data, "unixSeconds")
	assert.Contains(t, data, "unixMilliseconds")
	assert.Contains(t, data, "iso8601")
	assert.Contains(t, data, "rfc3339")
	assert.Contains(t, data, "humanReadable")
}
