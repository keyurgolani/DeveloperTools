package crypto_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/keyurgolani/DeveloperTools/internal/metrics"
	"github.com/keyurgolani/DeveloperTools/internal/modules/crypto"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestRouter() *gin.Engine {
	// Clear any existing metrics to avoid duplicate registration
	prometheus.DefaultRegisterer = prometheus.NewRegistry()

	gin.SetMode(gin.TestMode)
	router := gin.New()

	service := crypto.NewCryptoService()
	metricsInstance := metrics.New()
	handler := crypto.NewHandler(service, metricsInstance)

	v1 := router.Group("/api/v1")
	handler.RegisterRoutes(v1)

	return router
}

func TestHandler_Hash(t *testing.T) {
	router := setupTestRouter()

	tests := []struct {
		name           string
		request        crypto.HashRequest
		expectedStatus int
		expectSuccess  bool
		expectedHash   string
	}{
		{
			name: "Valid SHA256 hash request",
			request: crypto.HashRequest{
				Content:   "hello world",
				Algorithm: "sha256",
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
			expectedHash:   "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
		},
		{
			name: "Valid MD5 hash request",
			request: crypto.HashRequest{
				Content:   "test",
				Algorithm: "md5",
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
			expectedHash:   "098f6bcd4621d373cade4e832627b4f6",
		},
		{
			name: "Invalid algorithm",
			request: crypto.HashRequest{
				Content:   "test",
				Algorithm: "invalid",
			},
			expectedStatus: http.StatusBadRequest,
			expectSuccess:  false,
		},
		{
			name: "Empty content",
			request: crypto.HashRequest{
				Content:   "",
				Algorithm: "sha256",
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
			expectedHash:   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
	}

	executeHashTests(t, router, tests)
}

func TestHandler_Hash_ValidationErrors(t *testing.T) {
	router := setupTestRouter()

	tests := []struct {
		name        string
		requestBody string
		expectedMsg string
	}{

		{
			name:        "Missing algorithm field",
			requestBody: `{"content": "test"}`,
			expectedMsg: "validation error",
		},
		{
			name:        "Invalid JSON",
			requestBody: `{"content": "test", "algorithm":}`,
			expectedMsg: "validation error",
		},
		{
			name:        "Unsupported algorithm in validation",
			requestBody: `{"content": "test", "algorithm": "unsupported"}`,
			expectedMsg: "validation error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(
				context.Background(),
				"POST",
				"/api/v1/crypto/hash",
				bytes.NewBufferString(tt.requestBody),
			)
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)

			var response map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)

			assert.Contains(t, response, "error")
		})
	}
}

func TestHandler_HMAC(t *testing.T) {
	router := setupTestRouter()

	tests := []struct {
		name           string
		request        crypto.HMACRequest
		expectedStatus int
		expectSuccess  bool
		expectedHMAC   string
	}{
		{
			name: "Valid HMAC-SHA256 request",
			request: crypto.HMACRequest{
				Content:   "what do ya want for nothing?",
				Key:       "Jefe",
				Algorithm: "sha256",
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
			expectedHMAC:   "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
		},
		{
			name: "Valid HMAC-SHA512 request",
			request: crypto.HMACRequest{
				Content:   "Hi There",
				Key:       "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
				Algorithm: "sha512",
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
			expectedHMAC: "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cded" +
				"aa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
		},
		{
			name: "Invalid algorithm",
			request: crypto.HMACRequest{
				Content:   "test",
				Key:       "key",
				Algorithm: "md5",
			},
			expectedStatus: http.StatusBadRequest,
			expectSuccess:  false,
		},
		{
			name: "Empty content",
			request: crypto.HMACRequest{
				Content:   "",
				Key:       "key",
				Algorithm: "sha256",
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
			expectedHMAC:   "5d5d139563c95b5967b9bd9a8c9b233a9dedb45072794cd232dc1b74832607d0",
		},
	}

	executeHMACTests(t, router, tests)
}

func TestHandler_HMAC_ValidationErrors(t *testing.T) {
	router := setupTestRouter()

	tests := []struct {
		name        string
		requestBody string
	}{

		{
			name:        "Missing key field",
			requestBody: `{"content": "test", "algorithm": "sha256"}`,
		},
		{
			name:        "Missing algorithm field",
			requestBody: `{"content": "test", "key": "secret"}`,
		},
		{
			name:        "Invalid algorithm in validation",
			requestBody: `{"content": "test", "key": "secret", "algorithm": "md5"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(
				context.Background(),
				"POST",
				"/api/v1/crypto/hmac",
				bytes.NewBufferString(tt.requestBody),
			)
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)

			var response map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)

			assert.Contains(t, response, "error")
		})
	}
}

func TestHandler_PasswordHash(t *testing.T) {
	router := setupTestRouter()
	tests := getPasswordHashTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executePasswordHashTest(t, router, tt)
		})
	}
}

func getPasswordHashTestCases() []struct {
	name           string
	request        crypto.PasswordHashRequest
	expectedStatus int
	expectSuccess  bool
} {
	return []struct {
		name           string
		request        crypto.PasswordHashRequest
		expectedStatus int
		expectSuccess  bool
	}{
		{
			name: "Valid password hash request",
			request: crypto.PasswordHashRequest{
				Password: "testpassword123",
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
		},
		{
			name: "Empty password",
			request: crypto.PasswordHashRequest{
				Password: "",
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
		},
		{
			name: "Unicode password",
			request: crypto.PasswordHashRequest{
				Password: "пароль123🔒",
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
		},
		{
			name: "Long password",
			request: crypto.PasswordHashRequest{
				Password: strings.Repeat("a", 1000),
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
		},
	}
}

func executePasswordHashTest(t *testing.T, router *gin.Engine, tt struct {
	name           string
	request        crypto.PasswordHashRequest
	expectedStatus int
	expectSuccess  bool
}) {
	jsonBody, err := json.Marshal(tt.request)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(
		context.Background(), "POST", "/api/v1/crypto/password/hash", bytes.NewBuffer(jsonBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, tt.expectedStatus, w.Code)
	verifyPasswordHashResponse(t, w, tt.expectSuccess)
}

func verifyPasswordHashResponse(t *testing.T, w *httptest.ResponseRecorder, expectSuccess bool) {
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	if expectSuccess {
		assert.True(t, response["success"].(bool))
		data := response["data"].(map[string]interface{})
		hash := data["hash"].(string)
		assert.NotEmpty(t, hash)
		assert.True(t, strings.HasPrefix(hash, "$argon2id$v=19$"))
	} else {
		assert.Contains(t, response, "error")
	}
}

func TestHandler_PasswordVerify(t *testing.T) {
	router := setupTestRouter()
	validHash := generateValidHashForTesting(t, router)
	tests := getPasswordVerifyTestCases(validHash)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executePasswordVerifyTest(t, router, tt)
		})
	}
}

func generateValidHashForTesting(t *testing.T, router *gin.Engine) string {
	hashRequest := crypto.PasswordHashRequest{
		Password: "testpassword123",
	}

	jsonBody, err := json.Marshal(hashRequest)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(
		context.Background(), "POST", "/api/v1/crypto/password/hash", bytes.NewBuffer(jsonBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var hashResponse map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &hashResponse)
	require.NoError(t, err)

	data := hashResponse["data"].(map[string]interface{})
	return data["hash"].(string)
}

func getPasswordVerifyTestCases(validHash string) []struct {
	name           string
	request        crypto.PasswordVerifyRequest
	expectedStatus int
	expectSuccess  bool
	expectedValid  bool
} {
	return []struct {
		name           string
		request        crypto.PasswordVerifyRequest
		expectedStatus int
		expectSuccess  bool
		expectedValid  bool
	}{
		{
			name: "Valid password verification",
			request: crypto.PasswordVerifyRequest{
				Password: "testpassword123",
				Hash:     validHash,
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
			expectedValid:  true,
		},
		{
			name: "Invalid password verification",
			request: crypto.PasswordVerifyRequest{
				Password: "wrongpassword",
				Hash:     validHash,
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
			expectedValid:  false,
		},
		{
			name: "Invalid hash format",
			request: crypto.PasswordVerifyRequest{
				Password: "testpassword123",
				Hash:     "invalid_hash",
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
			expectedValid:  false,
		},
		{
			name: "Empty password with valid hash",
			request: crypto.PasswordVerifyRequest{
				Password: "",
				Hash:     validHash,
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
			expectedValid:  false,
		},
	}
}

func executePasswordVerifyTest(t *testing.T, router *gin.Engine, tt struct {
	name           string
	request        crypto.PasswordVerifyRequest
	expectedStatus int
	expectSuccess  bool
	expectedValid  bool
}) {
	jsonBody, err := json.Marshal(tt.request)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(
		context.Background(), "POST", "/api/v1/crypto/password/verify", bytes.NewBuffer(jsonBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, tt.expectedStatus, w.Code)
	verifyPasswordVerifyResponse(t, w, tt.expectSuccess, tt.expectedValid)
}

func verifyPasswordVerifyResponse(t *testing.T, w *httptest.ResponseRecorder, expectSuccess bool, expectedValid bool) {
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	if expectSuccess {
		assert.True(t, response["success"].(bool))
		data := response["data"].(map[string]interface{})
		assert.Equal(t, expectedValid, data["valid"].(bool))
	} else {
		assert.Contains(t, response, "error")
	}
}

func TestHandler_Password_ValidationErrors(t *testing.T) {
	router := setupTestRouter()

	tests := []struct {
		name        string
		endpoint    string
		requestBody string
	}{

		{
			name:        "Hash - invalid JSON",
			endpoint:    "/api/v1/crypto/password/hash",
			requestBody: `{"password":}`,
		},

		{
			name:        "Verify - missing hash field",
			endpoint:    "/api/v1/crypto/password/verify",
			requestBody: `{"password": "somepassword"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(
				context.Background(), "POST", tt.endpoint, bytes.NewBufferString(tt.requestBody))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)

			var response map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)

			assert.Contains(t, response, "error")
		})
	}
}

func TestHandler_DecodeCertificate(t *testing.T) {
	router := setupTestRouter()
	tests := getDecodeCertificateTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executeDecodeCertificateTest(t, router, tt)
		})
	}
}

func getValidTestCertificate() string {
	return `-----BEGIN CERTIFICATE-----
MIIDJjCCAg4CCQD+EO1siPH5GTANBgkqhkiG9w0BAQsFADBVMQswCQYDVQQGEwJV
UzENMAsGA1UECAwEVGVzdDENMAsGA1UEBwwEVGVzdDENMAsGA1UECgwEVGVzdDEZ
MBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTAeFw0yNTA5MjAxOTMxNTNaFw0yNjA5
MjAxOTMxNTNaMFUxCzAJBgNVBAYTAlVTMQ0wCwYDVQQIDARUZXN0MQ0wCwYDVQQH
DARUZXN0MQ0wCwYDVQQKDARUZXN0MRkwFwYDVQQDDBB0ZXN0LmV4YW1wbGUuY29t
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw0anQHt/88gvbutvzcdT
cSKOXPkx9mrMhETXWpqcGjHliavZn51Qavvy7sLrzduUTt7Y/m4Y/jOjhoJGOaaa
Bk4FQbAYIQsKtizp5Ydkn94WgQ50aTv+OrH5hHsw25pMiJYRv6lptTi+CIAfKrJD
T6Xrtytrph+cUmvI3LkmvZCY+7S8694VHpArmz4TTo29GAVcEjv8JlODKH049lfR
NvU21eEOajQozlXJ/vPeugwwuRlZFRjrmWtbmWEhyhsNOXOl6oo6EFBU2/eipbVT
V8SG0QogwAynlMyXVWkjSw5o9fErSb2TxJti+SjB4Ys2BRitr8WN0jxYXTWBUvl1
KwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAuKxZ0CNbxhh97CjQ5XgThVE3X0Yv9
YNJ9QTtF4p4mBvn8L5DSj8OhEYsKMfNU2Tc+hJgPBQMA3zPKQzg3IJfOldM4cCWU
UdVm4QRSOpcTGcjCWriu6IBKXaYoJkbyts2C6TSAAdnz/LoNAIxl+j0r93OQS4Su
6E/wQH38RwSlAfY8l/JofiAbjn3u1gMLb9iMI+MooBj5/AQ2NlvYZBLqoURFA4cz
bm1nEqtJZCN/WZA4K2YIi0xboI1oMRbUIIYgmqhR5+qGRpO32Roa/8XuXw5o1ftn
nU4ZU3j43ohhFR96ZjnvIZ/5eYr/L0ZlexDZ8gpGXsaV+RLF5DxGTOFp
-----END CERTIFICATE-----`
}

func getValidCertificateTestCases() []struct {
	name           string
	request        crypto.CertificateDecodeRequest
	expectedStatus int
	expectSuccess  bool
	checkResponse  func(*testing.T, map[string]interface{})
} {
	validCert := getValidTestCertificate()

	return []struct {
		name           string
		request        crypto.CertificateDecodeRequest
		expectedStatus int
		expectSuccess  bool
		checkResponse  func(*testing.T, map[string]interface{})
	}{
		{
			name: "Valid certificate",
			request: crypto.CertificateDecodeRequest{
				Certificate: validCert,
			},
			expectedStatus: http.StatusOK,
			expectSuccess:  true,
			checkResponse:  validateCertificateResponse,
		},
	}
}

func getInvalidCertificateTestCases() []struct {
	name           string
	request        crypto.CertificateDecodeRequest
	expectedStatus int
	expectSuccess  bool
	checkResponse  func(*testing.T, map[string]interface{})
} {
	return []struct {
		name           string
		request        crypto.CertificateDecodeRequest
		expectedStatus int
		expectSuccess  bool
		checkResponse  func(*testing.T, map[string]interface{})
	}{
		{
			name: "Invalid PEM format",
			request: crypto.CertificateDecodeRequest{
				Certificate: "not a certificate",
			},
			expectedStatus: http.StatusBadRequest,
			expectSuccess:  false,
		},
		{
			name: "Empty certificate",
			request: crypto.CertificateDecodeRequest{
				Certificate: "",
			},
			expectedStatus: http.StatusBadRequest,
			expectSuccess:  false,
		},
		{
			name: "Wrong PEM type",
			request: crypto.CertificateDecodeRequest{
				Certificate: `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC64TFWKUZxYiNl
-----END PRIVATE KEY-----`,
			},
			expectedStatus: http.StatusBadRequest,
			expectSuccess:  false,
		},
		{
			name: "Malformed certificate data",
			request: crypto.CertificateDecodeRequest{
				Certificate: `-----BEGIN CERTIFICATE-----
invalid base64 data!
-----END CERTIFICATE-----`,
			},
			expectedStatus: http.StatusBadRequest,
			expectSuccess:  false,
		},
	}
}

func getDecodeCertificateTestCases() []struct {
	name           string
	request        crypto.CertificateDecodeRequest
	expectedStatus int
	expectSuccess  bool
	checkResponse  func(*testing.T, map[string]interface{})
} {
	var testCases []struct {
		name           string
		request        crypto.CertificateDecodeRequest
		expectedStatus int
		expectSuccess  bool
		checkResponse  func(*testing.T, map[string]interface{})
	}

	testCases = append(testCases, getValidCertificateTestCases()...)
	testCases = append(testCases, getInvalidCertificateTestCases()...)

	return testCases
}

func validateCertificateResponse(t *testing.T, response map[string]interface{}) {
	data := response["data"].(map[string]interface{})
	cert := data["certificate"].(map[string]interface{})

	assert.NotEmpty(t, cert["subject"])
	assert.NotEmpty(t, cert["issuer"])
	assert.NotEmpty(t, cert["serialNumber"])
	assert.NotEmpty(t, cert["notBefore"])
	assert.NotEmpty(t, cert["notAfter"])
	assert.Equal(t, float64(1), cert["version"]) // JSON numbers are float64
	assert.Contains(t, cert, "keyUsage")
	// dnsNames may be omitted if empty due to omitempty tag
}

func executeDecodeCertificateTest(t *testing.T, router *gin.Engine, tt struct {
	name           string
	request        crypto.CertificateDecodeRequest
	expectedStatus int
	expectSuccess  bool
	checkResponse  func(*testing.T, map[string]interface{})
}) {
	jsonBody, err := json.Marshal(tt.request)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(
		context.Background(), "POST", "/api/v1/crypto/cert/decode", bytes.NewBuffer(jsonBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, tt.expectedStatus, w.Code)
	verifyDecodeCertificateResponse(t, w, tt.expectSuccess, tt.checkResponse)
}

func verifyDecodeCertificateResponse(
	t *testing.T, w *httptest.ResponseRecorder, expectSuccess bool,
	checkResponse func(*testing.T, map[string]interface{}),
) {
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	if expectSuccess {
		assert.True(t, response["success"].(bool))
		if checkResponse != nil {
			checkResponse(t, response)
		}
	} else {
		assert.Contains(t, response, "error")
	}
}

func TestHandler_DecodeCertificate_ValidationErrors(t *testing.T) {
	router := setupTestRouter()

	tests := []struct {
		name        string
		requestBody string
	}{
		{
			name:        "Missing certificate field",
			requestBody: `{}`,
		},
		{
			name:        "Invalid JSON",
			requestBody: `{"certificate":}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(
				context.Background(), "POST", "/api/v1/crypto/cert/decode", bytes.NewBufferString(tt.requestBody))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)

			var response map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)

			assert.Contains(t, response, "error")
		})
	}
}

// Generic helper function to execute crypto test cases.
func executeCryptoTests(t *testing.T, router *gin.Engine, endpoint string, tests []struct {
	name           string
	request        interface{}
	expectedStatus int
	expectSuccess  bool
	expectedValue  string
	valueKey       string
	algorithm      string
}) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonBody, err := json.Marshal(tt.request)
			require.NoError(t, err)

			req, err := http.NewRequestWithContext(
				context.Background(),
				"POST",
				endpoint,
				bytes.NewBuffer(jsonBody),
			)
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
				data := response["data"].(map[string]interface{})
				assert.Equal(t, tt.expectedValue, data[tt.valueKey])
				assert.Equal(t, tt.algorithm, data["algorithm"])
			} else {
				assert.Contains(t, response, "error")
			}
		})
	}
}

// Helper function to execute hash test cases.
func executeHashTests(t *testing.T, router *gin.Engine, tests []struct {
	name           string
	request        crypto.HashRequest
	expectedStatus int
	expectSuccess  bool
	expectedHash   string
}) {
	var genericTests []struct {
		name           string
		request        interface{}
		expectedStatus int
		expectSuccess  bool
		expectedValue  string
		valueKey       string
		algorithm      string
	}

	for _, test := range tests {
		genericTests = append(genericTests, struct {
			name           string
			request        interface{}
			expectedStatus int
			expectSuccess  bool
			expectedValue  string
			valueKey       string
			algorithm      string
		}{
			name:           test.name,
			request:        test.request,
			expectedStatus: test.expectedStatus,
			expectSuccess:  test.expectSuccess,
			expectedValue:  test.expectedHash,
			valueKey:       "hash",
			algorithm:      test.request.Algorithm,
		})
	}

	executeCryptoTests(t, router, "/api/v1/crypto/hash", genericTests)
}

// Helper function to execute HMAC test cases.
func executeHMACTests(t *testing.T, router *gin.Engine, tests []struct {
	name           string
	request        crypto.HMACRequest
	expectedStatus int
	expectSuccess  bool
	expectedHMAC   string
}) {
	var genericTests []struct {
		name           string
		request        interface{}
		expectedStatus int
		expectSuccess  bool
		expectedValue  string
		valueKey       string
		algorithm      string
	}

	for _, test := range tests {
		genericTests = append(genericTests, struct {
			name           string
			request        interface{}
			expectedStatus int
			expectSuccess  bool
			expectedValue  string
			valueKey       string
			algorithm      string
		}{
			name:           test.name,
			request:        test.request,
			expectedStatus: test.expectedStatus,
			expectSuccess:  test.expectSuccess,
			expectedValue:  test.expectedHMAC,
			valueKey:       "hmac",
			algorithm:      test.request.Algorithm,
		})
	}

	executeCryptoTests(t, router, "/api/v1/crypto/hmac", genericTests)
}
