package crypto_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/keyurgolani/DeveloperTools/internal/metrics"
	"github.com/keyurgolani/DeveloperTools/internal/modules/crypto"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupMetricsTestRouter() *gin.Engine {
	// Clear any existing metrics to avoid duplicate registration
	prometheus.DefaultRegisterer = prometheus.NewRegistry()

	gin.SetMode(gin.TestMode)
	router := gin.New()

	service := crypto.NewCryptoService()
	metricsInstance := metrics.New()
	handler := crypto.NewMetricsAwareHandler(service, metricsInstance)

	v1 := router.Group("/api/v1")
	handler.RegisterRoutes(v1)

	return router
}

func TestMetricsAwareHandler_Hash(t *testing.T) {
	router := setupMetricsTestRouter()

	tests := []struct {
		name           string
		request        crypto.HashRequest
		expectedStatus int
		expectSuccess  bool
	}{
		{
			name: "Valid SHA256 hash request with metrics",
			request: crypto.HashRequest{
				Content:   "hello world",
				Algorithm: "sha256",
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
		},
		{
			name: "Invalid algorithm with metrics",
			request: crypto.HashRequest{
				Content:   "hello world",
				Algorithm: "invalid",
			},
			expectedStatus: http.StatusBadRequest,
			expectSuccess:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqBody, err := json.Marshal(tt.request)
			require.NoError(t, err)

			req, err := http.NewRequest("POST", "/api/v1/crypto/hash", bytes.NewBuffer(reqBody))
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
				assert.NotNil(t, response["data"])
			} else {
				assert.NotNil(t, response["error"])
			}
		})
	}
}

func TestMetricsAwareHandler_HMAC(t *testing.T) {
	router := setupMetricsTestRouter()

	tests := []struct {
		name           string
		request        crypto.HMACRequest
		expectedStatus int
		expectSuccess  bool
	}{
		{
			name: "Valid HMAC request with metrics",
			request: crypto.HMACRequest{
				Content:   "hello world",
				Key:       "secret-key",
				Algorithm: "sha256",
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
		},
		{
			name: "Invalid algorithm with metrics",
			request: crypto.HMACRequest{
				Content:   "hello world",
				Key:       "secret-key",
				Algorithm: "invalid",
			},
			expectedStatus: http.StatusBadRequest,
			expectSuccess:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqBody, err := json.Marshal(tt.request)
			require.NoError(t, err)

			req, err := http.NewRequest("POST", "/api/v1/crypto/hmac", bytes.NewBuffer(reqBody))
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
				assert.NotNil(t, response["data"])
			} else {
				assert.NotNil(t, response["error"])
			}
		})
	}
}

func TestMetricsAwareHandler_HashPassword(t *testing.T) {
	router := setupMetricsTestRouter()

	request := crypto.PasswordHashRequest{
		Password: "test-password-123",
	}

	reqBody, err := json.Marshal(request)
	require.NoError(t, err)

	req, err := http.NewRequest("POST", "/api/v1/crypto/password/hash", bytes.NewBuffer(reqBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.True(t, response["success"].(bool))
	assert.NotNil(t, response["data"])
}

func TestMetricsAwareHandler_VerifyPassword(t *testing.T) {
	router := setupMetricsTestRouter()

	// First hash a password
	hashRequest := crypto.PasswordHashRequest{
		Password: "test-password-123",
	}

	reqBody, err := json.Marshal(hashRequest)
	require.NoError(t, err)

	req, err := http.NewRequest("POST", "/api/v1/crypto/password/hash", bytes.NewBuffer(reqBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var hashResponse map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &hashResponse)
	require.NoError(t, err)

	data := hashResponse["data"].(map[string]interface{})
	hash := data["hash"].(string)

	// Now verify the password
	verifyRequest := crypto.PasswordVerifyRequest{
		Password: "test-password-123",
		Hash:     hash,
	}

	reqBody, err = json.Marshal(verifyRequest)
	require.NoError(t, err)

	req, err = http.NewRequest("POST", "/api/v1/crypto/password/verify", bytes.NewBuffer(reqBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.True(t, response["success"].(bool))
	data = response["data"].(map[string]interface{})
	assert.True(t, data["valid"].(bool))
}

func TestMetricsAwareHandler_DecodeCertificate(t *testing.T) {
	router := setupMetricsTestRouter()

	// Sample certificate for testing
	certPEM := `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKoK/heBjcOuMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTcwODI3MjM1NzU5WhcNMTgwODI3MjM1NzU5WjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAuuExKvY1xzHFw4A9J3QnsdTtjqjHtdI5nkvFQrP4O+Tc5aysIUmhRWZ/
FTADHlr6Mc8EqJOOOWxlhyqTraHwSmx2+oNmsxd/AoAmTisSKNRcK56IMiVscQEm
TQ5OMjthpFAh6rUr9/sHqFp6BcO2T2c1ZdaJDmla5xZqjQhfYSJXh2yVKC3kx5w6
3+CIMGqGqsU3+1hlCXt+fP8h4XvpbdHwmNzuAll9DiVlTGMdcks/Fpn7rhSiEcHo
t+3hlKHGwaMFJ3z1Vb8NsecwYzAe4OBQd+RwHBDyCCXmCSuMWFJo5c1SjE5+4rln
BaO+RaPABvSxD/BH7XrJjbyMRoGQXwIDAQABo1AwTjAdBgNVHQ4EFgQUhO4LbL+O
lAqgm6+ZhO+DzFyLlBUwHwYDVR0jBBgwFoAUhO4LbL+OlAqgm6+ZhO+DzFyLlBUw
DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEABjDKAvmYcQsurIS6jWmT
hADDzqLGHRgPiB6xsm4f1+FQbVyrEKpDmw8cnAHFUv/NOdKXw9Ev1hTd4hIeC42l
8YuArzjHiuJdFd5cf7/YFdT2ON4fInKqQs4nuMiUnInvgL2Zu2wQ3MfKuMaK+Xbx
hQbHlnPrHuJegtYMUg3r3+hSqXJoQKOdOvRLnXNhNQqw++anCpL9+40gmdGt/HFZ
eaAjLQR9txAuoRhteQrwQqejh+rGFsm3+ccQZcw4eMW1IrqESBWATiN/q0vasuBb
MrpbqBmVmfvdWk4i+cLdDpO+ycgzTQIHmz1IuiUZKTARyQA5pD79y6b0kOHWw1aU
5A==
-----END CERTIFICATE-----`

	request := crypto.CertificateDecodeRequest{
		Certificate: certPEM,
	}

	reqBody, err := json.Marshal(request)
	require.NoError(t, err)

	req, err := http.NewRequest("POST", "/api/v1/crypto/cert/decode", bytes.NewBuffer(reqBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.True(t, response["success"].(bool))
	assert.NotNil(t, response["data"])
}

func TestMetricsAwareHandler_InvalidJSON(t *testing.T) {
	router := setupMetricsTestRouter()

	req, err := http.NewRequest("POST", "/api/v1/crypto/hash", bytes.NewBuffer([]byte("invalid json")))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.NotNil(t, response["error"])
}
