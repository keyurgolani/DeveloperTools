package network_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyurgolani/DeveloperTools/internal/modules/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getBasicURLParseTestCases() []struct {
	name     string
	url      string
	expected *network.URLParts
	wantErr  bool
} {
	return []struct {
		name     string
		url      string
		expected *network.URLParts
		wantErr  bool
	}{
		{
			name: "simple HTTP URL",
			url:  "http://example.com",
			expected: &network.URLParts{
				Scheme:   "http",
				Host:     "example.com",
				Path:     "",
				Query:    map[string]string{},
				Fragment: "",
			},
			wantErr: false,
		},
		{
			name: "HTTPS URL with path",
			url:  "https://example.com/path/to/resource",
			expected: &network.URLParts{
				Scheme:   "https",
				Host:     "example.com",
				Path:     "/path/to/resource",
				Query:    map[string]string{},
				Fragment: "",
			},
			wantErr: false,
		},
		{
			name: "URL with port",
			url:  "http://example.com:8080/api",
			expected: &network.URLParts{
				Scheme:   "http",
				Host:     "example.com:8080",
				Path:     "/api",
				Query:    map[string]string{},
				Fragment: "",
			},
			wantErr: false,
		},
	}
}

func getComplexURLParseTestCases() []struct {
	name     string
	url      string
	expected *network.URLParts
	wantErr  bool
} {
	return []struct {
		name     string
		url      string
		expected *network.URLParts
		wantErr  bool
	}{
		{
			name: "URL with query parameters",
			url:  "https://example.com/search?q=test&limit=10",
			expected: &network.URLParts{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/search",
				Query: map[string]string{
					"q":     "test",
					"limit": "10",
				},
				Fragment: "",
			},
			wantErr: false,
		},
		{
			name: "URL with fragment",
			url:  "https://example.com/page#section1",
			expected: &network.URLParts{
				Scheme:   "https",
				Host:     "example.com",
				Path:     "/page",
				Query:    map[string]string{},
				Fragment: "section1",
			},
			wantErr: false,
		},
		{
			name: "complex URL",
			url:  "https://user:pass@example.com:443/path?param1=value1&param2=value2#fragment",
			expected: &network.URLParts{
				Scheme: "https",
				Host:   "user:pass@example.com:443",
				Path:   "/path",
				Query: map[string]string{
					"param1": "value1",
					"param2": "value2",
				},
				Fragment: "fragment",
			},
			wantErr: false,
		},
	}
}

func getInvalidURLParseTestCases() []struct {
	name     string
	url      string
	expected *network.URLParts
	wantErr  bool
} {
	return []struct {
		name     string
		url      string
		expected *network.URLParts
		wantErr  bool
	}{
		{
			name:     "invalid URL",
			url:      "not-a-url",
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "empty URL",
			url:      "",
			expected: nil,
			wantErr:  true,
		},
	}
}

func executeURLParseTest(t *testing.T, service network.NetworkService, tt struct {
	name     string
	url      string
	expected *network.URLParts
	wantErr  bool
}) {
	result, err := service.ParseURL(tt.url)

	if tt.wantErr {
		assert.Error(t, err)
		assert.Nil(t, result)
	} else {
		assert.NoError(t, err)
		assert.Equal(t, tt.expected, result)
	}
}

func TestNetworkService_ParseURL(t *testing.T) {
	service := network.NewNetworkService()

	var tests []struct {
		name     string
		url      string
		expected *network.URLParts
		wantErr  bool
	}

	tests = append(tests, getBasicURLParseTestCases()...)
	tests = append(tests, getComplexURLParseTestCases()...)
	tests = append(tests, getInvalidURLParseTestCases()...)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executeURLParseTest(t, service, tt)
		})
	}
}

func getBasicURLBuildTestCases() []struct {
	name     string
	parts    *network.URLParts
	expected string
	wantErr  bool
} {
	return []struct {
		name     string
		parts    *network.URLParts
		expected string
		wantErr  bool
	}{
		{
			name: "simple URL",
			parts: &network.URLParts{
				Scheme: "https",
				Host:   "example.com",
			},
			expected: "https://example.com",
			wantErr:  false,
		},
		{
			name: "URL with path",
			parts: &network.URLParts{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/api/v1/users",
			},
			expected: "https://example.com/api/v1/users",
			wantErr:  false,
		},
		{
			name: "URL with fragment",
			parts: &network.URLParts{
				Scheme:   "https",
				Host:     "example.com",
				Path:     "/page",
				Fragment: "section1",
			},
			expected: "https://example.com/page#section1",
			wantErr:  false,
		},
	}
}

func getComplexURLBuildTestCases() []struct {
	name     string
	parts    *network.URLParts
	expected string
	wantErr  bool
} {
	return []struct {
		name     string
		parts    *network.URLParts
		expected string
		wantErr  bool
	}{
		{
			name: "URL with query parameters",
			parts: &network.URLParts{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/search",
				Query: map[string]string{
					"q":     "test query",
					"limit": "10",
				},
			},
			expected: "https://example.com/search?limit=10&q=test+query",
			wantErr:  false,
		},
		{
			name: "complex URL",
			parts: &network.URLParts{
				Scheme: "https",
				Host:   "example.com:8080",
				Path:   "/api/v1/search",
				Query: map[string]string{
					"q":      "test",
					"format": "json",
				},
				Fragment: "results",
			},
			expected: "https://example.com:8080/api/v1/search?format=json&q=test#results",
			wantErr:  false,
		},
	}
}

func getInvalidURLBuildTestCases() []struct {
	name     string
	parts    *network.URLParts
	expected string
	wantErr  bool
} {
	return []struct {
		name     string
		parts    *network.URLParts
		expected string
		wantErr  bool
	}{
		{
			name: "missing scheme",
			parts: &network.URLParts{
				Host: "example.com",
			},
			expected: "",
			wantErr:  true,
		},
		{
			name: "missing host",
			parts: &network.URLParts{
				Scheme: "https",
			},
			expected: "",
			wantErr:  true,
		},
	}
}

func executeURLBuildTest(t *testing.T, service network.NetworkService, tt struct {
	name     string
	parts    *network.URLParts
	expected string
	wantErr  bool
}) {
	result, err := service.BuildURL(tt.parts)

	if tt.wantErr {
		assert.Error(t, err)
		assert.Empty(t, result)
	} else {
		assert.NoError(t, err)
		assert.Equal(t, tt.expected, result)
	}
}

func TestNetworkService_BuildURL(t *testing.T) {
	service := network.NewNetworkService()

	var tests []struct {
		name     string
		parts    *network.URLParts
		expected string
		wantErr  bool
	}

	tests = append(tests, getBasicURLBuildTestCases()...)
	tests = append(tests, getComplexURLBuildTestCases()...)
	tests = append(tests, getInvalidURLBuildTestCases()...)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executeURLBuildTest(t, service, tt)
		})
	}
}

func TestNetworkService_GetHeaders(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Custom-Header", "test-value")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"message": "test"}`))
	}))
	defer server.Close()

	service := network.NewNetworkServiceWithOptions(true) // Disable SSRF protection for testing

	t.Run("successful request", func(t *testing.T) {
		result, err := service.GetHeaders(server.URL)

		assert.NoError(t, err)
		assert.Equal(t, server.URL, result.URL)
		assert.Equal(t, http.StatusOK, result.StatusCode)
		assert.Contains(t, result.Headers, "Content-Type")
		assert.Equal(t, "application/json", result.Headers["Content-Type"])
		assert.Contains(t, result.Headers, "X-Custom-Header")
		assert.Equal(t, "test-value", result.Headers["X-Custom-Header"])
	})

	t.Run("invalid URL", func(t *testing.T) {
		_, err := service.GetHeaders("not-a-url")
		assert.Error(t, err)
	})
}

func getValidateURLSSRFTestCases() []struct {
	name    string
	url     string
	wantErr bool
} {
	return []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			name:    "valid external URL",
			url:     "https://example.com",
			wantErr: false,
		},
		{
			name:    "localhost blocked",
			url:     "http://localhost:8080",
			wantErr: true,
		},
		{
			name:    "127.0.0.1 blocked",
			url:     "http://127.0.0.1:8080",
			wantErr: true,
		},
		{
			name:    "private IP 192.168.x.x blocked",
			url:     "http://192.168.1.1",
			wantErr: true,
		},
		{
			name:    "private IP 10.x.x.x blocked",
			url:     "http://10.0.0.1",
			wantErr: true,
		},
		{
			name:    "private IP 172.16.x.x blocked",
			url:     "http://172.16.0.1",
			wantErr: true,
		},
		{
			name:    "AWS metadata endpoint blocked",
			url:     "http://169.254.169.254/latest/meta-data/",
			wantErr: true,
		},
		{
			name:    "unsupported scheme",
			url:     "ftp://example.com",
			wantErr: true,
		},
		{
			name:    "invalid URL",
			url:     "not-a-url",
			wantErr: true,
		},
	}
}

func TestNetworkService_ValidateURL_SSRFProtection(t *testing.T) {
	service := network.NewNetworkService()
	tests := getValidateURLSSRFTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := service.GetHeaders(tt.url)

			if tt.wantErr {
				assert.Error(t, err)
			} else if err != nil {
				// Note: This test might fail for external URLs if DNS resolution fails
				// In a real environment, you might want to mock the DNS resolution
				t.Logf("URL validation failed (possibly due to DNS): %v", err)
			}
		})
	}
}

func getPrivateOrReservedIPTestCases() []struct {
	name     string
	ip       string
	expected bool
} {
	return []struct {
		name     string
		ip       string
		expected bool
	}{
		{
			name:     "private Class A",
			ip:       "10.0.0.1",
			expected: true,
		},
		{
			name:     "private Class B",
			ip:       "172.16.0.1",
			expected: true,
		},
		{
			name:     "private Class C",
			ip:       "192.168.1.1",
			expected: true,
		},
		{
			name:     "IPv6 unique local",
			ip:       "fc00::1",
			expected: true,
		},
		{
			name:     "public IP",
			ip:       "8.8.8.8",
			expected: false,
		},
		{
			name:     "public IPv6",
			ip:       "2001:4860:4860::8888",
			expected: false,
		},
	}
}

func TestNetworkService_IsPrivateOrReservedIP(t *testing.T) {
	service := network.NewNetworkService()
	tests := getPrivateOrReservedIPTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipInfo, err := service.AnalyzeIP(tt.ip)
			require.NoError(t, err)
			require.NotNil(t, ipInfo)

			assert.Equal(t, tt.expected, ipInfo.IsPrivate)
		})
	}
}

func TestNetworkService_DNSLookup(t *testing.T) {
	service := network.NewNetworkService()

	t.Run("A record lookup", func(t *testing.T) {
		result, err := service.DNSLookup("google.com", "A")

		if err != nil {
			t.Logf("DNS lookup failed (possibly due to network): %v", err)
			return
		}

		assert.NoError(t, err)
		assert.Equal(t, "google.com", result.Domain)
		assert.Equal(t, "A", result.RecordType)
		assert.NotEmpty(t, result.Records)
	})

	t.Run("unsupported record type", func(t *testing.T) {
		_, err := service.DNSLookup("example.com", "INVALID")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported record type")
	})
}

type analyzeIPTestCase struct {
	name     string
	ip       string
	expected *network.IPInfo
	wantErr  bool
}

func getIPv4AnalyzeTestCases() []analyzeIPTestCase {
	return []analyzeIPTestCase{
		{
			name: "IPv4 public",
			ip:   "8.8.8.8",
			expected: &network.IPInfo{
				IP:         "8.8.8.8",
				Version:    4,
				IsPrivate:  false,
				IsPublic:   true,
				IsLoopback: false,
			},
			wantErr: false,
		},
		{
			name: "IPv4 private",
			ip:   "192.168.1.1",
			expected: &network.IPInfo{
				IP:         "192.168.1.1",
				Version:    4,
				IsPrivate:  true,
				IsPublic:   false,
				IsLoopback: false,
			},
			wantErr: false,
		},
		{
			name: "IPv4 loopback",
			ip:   "127.0.0.1",
			expected: &network.IPInfo{
				IP:         "127.0.0.1",
				Version:    4,
				IsPrivate:  false,
				IsPublic:   false,
				IsLoopback: true,
			},
			wantErr: false,
		},
	}
}

func getIPv6AnalyzeTestCases() []analyzeIPTestCase {
	return []analyzeIPTestCase{
		{
			name: "IPv6 public",
			ip:   "2001:4860:4860::8888",
			expected: &network.IPInfo{
				IP:         "2001:4860:4860::8888",
				Version:    6,
				IsPrivate:  false,
				IsPublic:   true,
				IsLoopback: false,
			},
			wantErr: false,
		},
		{
			name: "IPv6 loopback",
			ip:   "::1",
			expected: &network.IPInfo{
				IP:         "::1",
				Version:    6,
				IsPrivate:  false,
				IsPublic:   false,
				IsLoopback: true,
			},
			wantErr: false,
		},
		{
			name: "IPv6 private",
			ip:   "fc00::1",
			expected: &network.IPInfo{
				IP:         "fc00::1",
				Version:    6,
				IsPrivate:  true,
				IsPublic:   false,
				IsLoopback: false,
			},
			wantErr: false,
		},
	}
}

func getInvalidIPAnalyzeTestCases() []analyzeIPTestCase {
	return []analyzeIPTestCase{
		{
			name:     "invalid IP",
			ip:       "not-an-ip",
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "empty IP",
			ip:       "",
			expected: nil,
			wantErr:  true,
		},
	}
}

func getAnalyzeIPTestCases() []analyzeIPTestCase {
	var cases []analyzeIPTestCase
	cases = append(cases, getIPv4AnalyzeTestCases()...)
	cases = append(cases, getIPv6AnalyzeTestCases()...)
	cases = append(cases, getInvalidIPAnalyzeTestCases()...)
	return cases
}

func TestNetworkService_AnalyzeIP(t *testing.T) {
	service := network.NewNetworkService()
	tests := getAnalyzeIPTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := service.AnalyzeIP(tt.ip)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}
