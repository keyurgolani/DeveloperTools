package network

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockNetworkService is a mock implementation of NetworkService
type MockNetworkService struct {
	mock.Mock
}

func (m *MockNetworkService) ParseURL(urlStr string) (*URLParts, error) {
	args := m.Called(urlStr)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*URLParts), args.Error(1)
}

func (m *MockNetworkService) BuildURL(parts *URLParts) (string, error) {
	args := m.Called(parts)
	return args.String(0), args.Error(1)
}

func (m *MockNetworkService) GetHeaders(urlStr string) (*HeadersResponse, error) {
	args := m.Called(urlStr)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*HeadersResponse), args.Error(1)
}

func (m *MockNetworkService) DNSLookup(domain, recordType string) (*DNSLookupResponse, error) {
	args := m.Called(domain, recordType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*DNSLookupResponse), args.Error(1)
}

func (m *MockNetworkService) AnalyzeIP(ip string) (*IPInfo, error) {
	args := m.Called(ip)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*IPInfo), args.Error(1)
}

func setupTestRouter() (*gin.Engine, *MockNetworkService) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	
	mockService := &MockNetworkService{}
	handler := NewHandler(mockService, nil) // Pass nil for metrics in tests
	
	api := router.Group("/api")
	handler.RegisterRoutes(api)
	
	return router, mockService
}

func TestHandler_URLOperation_Parse(t *testing.T) {
	router, mockService := setupTestRouter()

	t.Run("successful URL parsing", func(t *testing.T) {
		expectedParts := &URLParts{
			Scheme: "https",
			Host:   "example.com",
			Path:   "/path",
			Query:  map[string]string{"q": "test"},
		}

		mockService.On("ParseURL", "https://example.com/path?q=test").Return(expectedParts, nil)

		reqBody := URLOperationRequest{
			Action: "parse",
			URL:    "https://example.com/path?q=test",
		}
		jsonBody, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/web/url", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.True(t, response["success"].(bool))
		
		data := response["data"].(map[string]interface{})
		assert.Equal(t, "https", data["scheme"])
		assert.Equal(t, "example.com", data["host"])
		assert.Equal(t, "/path", data["path"])

		mockService.AssertExpectations(t)
	})

	t.Run("missing URL for parse", func(t *testing.T) {
		reqBody := URLOperationRequest{
			Action: "parse",
		}
		jsonBody, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/web/url", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("invalid URL", func(t *testing.T) {
		mockService.On("ParseURL", "invalid-url").Return(nil, assert.AnError)

		reqBody := URLOperationRequest{
			Action: "parse",
			URL:    "invalid-url",
		}
		jsonBody, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/web/url", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
	})
}

func TestHandler_URLOperation_Build(t *testing.T) {
	router, mockService := setupTestRouter()

	t.Run("successful URL building", func(t *testing.T) {
		parts := &URLParts{
			Scheme: "https",
			Host:   "example.com",
			Path:   "/api",
		}

		mockService.On("BuildURL", parts).Return("https://example.com/api", nil)

		reqBody := URLOperationRequest{
			Action: "build",
			Scheme: "https",
			Host:   "example.com",
			Path:   "/api",
		}
		jsonBody, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/web/url", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.True(t, response["success"].(bool))
		
		data := response["data"].(map[string]interface{})
		assert.Equal(t, "https://example.com/api", data["url"])

		mockService.AssertExpectations(t)
	})

	t.Run("missing scheme for build", func(t *testing.T) {
		reqBody := URLOperationRequest{
			Action: "build",
			Host:   "example.com",
		}
		jsonBody, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/web/url", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("missing host for build", func(t *testing.T) {
		reqBody := URLOperationRequest{
			Action: "build",
			Scheme: "https",
		}
		jsonBody, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/web/url", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestHandler_URLOperation_InvalidAction(t *testing.T) {
	router, _ := setupTestRouter()

	reqBody := URLOperationRequest{
		Action: "invalid",
	}
	jsonBody, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/web/url", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandler_GetHeaders(t *testing.T) {
	router, mockService := setupTestRouter()

	t.Run("successful header inspection", func(t *testing.T) {
		expectedResponse := &HeadersResponse{
			URL:        "https://example.com",
			StatusCode: 200,
			Headers: map[string]string{
				"Content-Type": "application/json",
				"Server":       "nginx",
			},
		}

		mockService.On("GetHeaders", "https://example.com").Return(expectedResponse, nil)

		reqBody := HeadersRequest{
			URL: "https://example.com",
		}
		jsonBody, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/network/headers", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.True(t, response["success"].(bool))

		mockService.AssertExpectations(t)
	})

	t.Run("invalid request", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/network/headers", bytes.NewBuffer([]byte("{}")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("service error", func(t *testing.T) {
		mockService.On("GetHeaders", "https://invalid.com").Return(nil, assert.AnError)

		reqBody := HeadersRequest{
			URL: "https://invalid.com",
		}
		jsonBody, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/network/headers", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
	})
}

func TestHandler_DNSLookup(t *testing.T) {
	router, mockService := setupTestRouter()

	t.Run("successful DNS lookup", func(t *testing.T) {
		expectedResponse := &DNSLookupResponse{
			Domain:     "example.com",
			RecordType: "A",
			Records:    []string{"93.184.216.34"},
		}

		mockService.On("DNSLookup", "example.com", "A").Return(expectedResponse, nil)

		reqBody := DNSLookupRequest{
			Domain:     "example.com",
			RecordType: "A",
		}
		jsonBody, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/network/dns", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.True(t, response["success"].(bool))

		mockService.AssertExpectations(t)
	})

	t.Run("invalid record type", func(t *testing.T) {
		reqBody := DNSLookupRequest{
			Domain:     "example.com",
			RecordType: "INVALID",
		}
		jsonBody, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/network/dns", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("service error", func(t *testing.T) {
		mockService.On("DNSLookup", "invalid.domain", "A").Return(nil, assert.AnError)

		reqBody := DNSLookupRequest{
			Domain:     "invalid.domain",
			RecordType: "A",
		}
		jsonBody, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/network/dns", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
	})
}

func TestHandler_AnalyzeIP(t *testing.T) {
	router, mockService := setupTestRouter()

	t.Run("successful IP analysis", func(t *testing.T) {
		expectedInfo := &IPInfo{
			IP:         "8.8.8.8",
			Version:    4,
			IsPrivate:  false,
			IsPublic:   true,
			IsLoopback: false,
		}

		mockService.On("AnalyzeIP", "8.8.8.8").Return(expectedInfo, nil)

		reqBody := IPAnalysisRequest{
			IP: "8.8.8.8",
		}
		jsonBody, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/network/ip", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.True(t, response["success"].(bool))

		mockService.AssertExpectations(t)
	})

	t.Run("invalid request", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/network/ip", bytes.NewBuffer([]byte("{}")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("invalid IP", func(t *testing.T) {
		mockService.On("AnalyzeIP", "invalid-ip").Return(nil, assert.AnError)

		reqBody := IPAnalysisRequest{
			IP: "invalid-ip",
		}
		jsonBody, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/network/ip", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
	})
}