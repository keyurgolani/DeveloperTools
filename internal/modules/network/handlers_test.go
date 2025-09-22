package network_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/keyurgolani/DeveloperTools/internal/modules/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockNetworkService is a mock implementation of NetworkService.
type MockNetworkService struct {
	mock.Mock
}

func (m *MockNetworkService) ParseURL(urlStr string) (*network.URLParts, error) {
	args := m.Called(urlStr)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*network.URLParts), args.Error(1)
}

func (m *MockNetworkService) BuildURL(parts *network.URLParts) (string, error) {
	args := m.Called(parts)
	return args.String(0), args.Error(1)
}

func (m *MockNetworkService) GetHeaders(urlStr string) (*network.HeadersResponse, error) {
	args := m.Called(urlStr)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*network.HeadersResponse), args.Error(1)
}

func (m *MockNetworkService) DNSLookup(domain, recordType string) (*network.DNSLookupResponse, error) {
	args := m.Called(domain, recordType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*network.DNSLookupResponse), args.Error(1)
}

func (m *MockNetworkService) AnalyzeIP(ip string) (*network.IPInfo, error) {
	args := m.Called(ip)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*network.IPInfo), args.Error(1)
}

func setupTestRouter() (*gin.Engine, *MockNetworkService) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	mockService := &MockNetworkService{}
	handler := network.NewHandler(mockService, nil) // Pass nil for metrics in tests

	api := router.Group("/api")
	handler.RegisterRoutes(api)

	return router, mockService
}

func TestHandler_URLOperation_Parse(t *testing.T) {
	router, mockService := setupTestRouter()

	t.Run("successful URL parsing", func(t *testing.T) {
		executeSuccessfulURLParseTest(t, router, mockService)
	})

	t.Run("missing URL for parse", func(t *testing.T) {
		executeMissingURLParseTest(t, router)
	})

	t.Run("invalid URL", func(t *testing.T) {
		executeInvalidURLParseTest(t, router, mockService)
	})
}

func executeSuccessfulURLParseTest(t *testing.T, router *gin.Engine, mockService *MockNetworkService) {
	expectedParts := &network.URLParts{
		Scheme: "https",
		Host:   "example.com",
		Path:   "/path",
		Query:  map[string]string{"q": "test"},
	}

	mockService.On("ParseURL", "https://example.com/path?q=test").Return(expectedParts, nil)

	reqBody := network.URLOperationRequest{
		Action: "parse",
		URL:    "https://example.com/path?q=test",
	}

	w := executeURLOperationRequest(t, router, reqBody)
	assert.Equal(t, http.StatusOK, w.Code)
	verifySuccessfulParseResponse(t, w)
	mockService.AssertExpectations(t)
}

func executeMissingURLParseTest(t *testing.T, router *gin.Engine) {
	reqBody := network.URLOperationRequest{
		Action: "parse",
	}

	w := executeURLOperationRequest(t, router, reqBody)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func executeInvalidURLParseTest(t *testing.T, router *gin.Engine, mockService *MockNetworkService) {
	mockService.On("ParseURL", "invalid-url").Return(nil, assert.AnError)

	reqBody := network.URLOperationRequest{
		Action: "parse",
		URL:    "invalid-url",
	}

	w := executeURLOperationRequest(t, router, reqBody)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	mockService.AssertExpectations(t)
}

func executeURLOperationRequest(t *testing.T, router *gin.Engine, reqBody network.URLOperationRequest) *httptest.ResponseRecorder {
	jsonBody, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/web/url", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func verifySuccessfulParseResponse(t *testing.T, w *httptest.ResponseRecorder) {
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response["success"].(bool))

	data := response["data"].(map[string]interface{})
	assert.Equal(t, "https", data["scheme"])
	assert.Equal(t, "example.com", data["host"])
	assert.Equal(t, "/path", data["path"])
}

func testSuccessfulURLBuild(t *testing.T, router *gin.Engine, mockService *MockNetworkService) {
	parts := &network.URLParts{
		Scheme: "https",
		Host:   "example.com",
		Path:   "/api",
	}

	mockService.On("BuildURL", parts).Return("https://example.com/api", nil)

	reqBody := network.URLOperationRequest{
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
}

func testMissingSchemeForBuild(t *testing.T, router *gin.Engine) {
	reqBody := network.URLOperationRequest{
		Action: "build",
		Host:   "example.com",
	}
	jsonBody, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/web/url", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func testMissingHostForBuild(t *testing.T, router *gin.Engine) {
	reqBody := network.URLOperationRequest{
		Action: "build",
		Scheme: "https",
	}
	jsonBody, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/web/url", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandler_URLOperation_Build(t *testing.T) {
	router, mockService := setupTestRouter()

	t.Run("successful URL building", func(t *testing.T) {
		testSuccessfulURLBuild(t, router, mockService)
	})

	t.Run("missing scheme for build", func(t *testing.T) {
		testMissingSchemeForBuild(t, router)
	})

	t.Run("missing host for build", func(t *testing.T) {
		testMissingHostForBuild(t, router)
	})
}

func TestHandler_URLOperation_InvalidAction(t *testing.T) {
	router, _ := setupTestRouter()

	reqBody := network.URLOperationRequest{
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
		testSuccessfulHeaderInspection(t, router, mockService)
	})

	t.Run("invalid request", func(t *testing.T) {
		testInvalidHeaderRequest(t, router)
	})

	t.Run("service error", func(t *testing.T) {
		testHeaderServiceError(t, router, mockService)
	})
}

func testSuccessfulHeaderInspection(t *testing.T, router *gin.Engine, mockService *MockNetworkService) {
	expectedResponse := &network.HeadersResponse{
		URL:        "https://example.com",
		StatusCode: 200,
		Headers: map[string]string{
			"Content-Type": "application/json",
			"Server":       "nginx",
		},
	}

	mockService.On("GetHeaders", "https://example.com").Return(expectedResponse, nil)

	reqBody := network.HeadersRequest{URL: "https://example.com"}
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
}

func testInvalidHeaderRequest(t *testing.T, router *gin.Engine) {
	req := httptest.NewRequest("POST", "/api/network/headers", bytes.NewBuffer([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func testHeaderServiceError(t *testing.T, router *gin.Engine, mockService *MockNetworkService) {
	mockService.On("GetHeaders", "https://invalid.com").Return(nil, assert.AnError)

	reqBody := network.HeadersRequest{URL: "https://invalid.com"}
	jsonBody, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/network/headers", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	mockService.AssertExpectations(t)
}

func testSuccessfulDNSLookup(t *testing.T, router *gin.Engine, mockService *MockNetworkService) {
	expectedResponse := &network.DNSLookupResponse{
		Domain:     "example.com",
		RecordType: "A",
		Records:    []string{"93.184.216.34"},
	}

	mockService.On("DNSLookup", "example.com", "A").Return(expectedResponse, nil)

	reqBody := network.DNSLookupRequest{
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
}

func testInvalidRecordType(t *testing.T, router *gin.Engine) {
	reqBody := network.DNSLookupRequest{
		Domain:     "example.com",
		RecordType: "INVALID",
	}
	jsonBody, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/network/dns", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func testDNSServiceError(t *testing.T, router *gin.Engine, mockService *MockNetworkService) {
	mockService.On("DNSLookup", "invalid.domain", "A").Return(nil, assert.AnError)

	reqBody := network.DNSLookupRequest{
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
}

func TestHandler_DNSLookup(t *testing.T) {
	router, mockService := setupTestRouter()

	t.Run("successful DNS lookup", func(t *testing.T) {
		testSuccessfulDNSLookup(t, router, mockService)
	})

	t.Run("invalid record type", func(t *testing.T) {
		testInvalidRecordType(t, router)
	})

	t.Run("service error", func(t *testing.T) {
		testDNSServiceError(t, router, mockService)
	})
}

func TestHandler_AnalyzeIP(t *testing.T) {
	router, mockService := setupTestRouter()

	t.Run("successful IP analysis", func(t *testing.T) {
		testSuccessfulIPAnalysis(t, router, mockService)
	})

	t.Run("invalid request", func(t *testing.T) {
		testInvalidIPRequest(t, router)
	})

	t.Run("invalid IP", func(t *testing.T) {
		testInvalidIPAnalysis(t, router, mockService)
	})
}

func testSuccessfulIPAnalysis(t *testing.T, router *gin.Engine, mockService *MockNetworkService) {
	expectedInfo := &network.IPInfo{
		IP:         "8.8.8.8",
		Version:    4,
		IsPrivate:  false,
		IsPublic:   true,
		IsLoopback: false,
	}

	mockService.On("AnalyzeIP", "8.8.8.8").Return(expectedInfo, nil)

	reqBody := network.IPAnalysisRequest{IP: "8.8.8.8"}
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
}

func testInvalidIPRequest(t *testing.T, router *gin.Engine) {
	req := httptest.NewRequest("POST", "/api/network/ip", bytes.NewBuffer([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func testInvalidIPAnalysis(t *testing.T, router *gin.Engine, mockService *MockNetworkService) {
	mockService.On("AnalyzeIP", "invalid-ip").Return(nil, assert.AnError)

	reqBody := network.IPAnalysisRequest{IP: "invalid-ip"}
	jsonBody, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/network/ip", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	mockService.AssertExpectations(t)
}
