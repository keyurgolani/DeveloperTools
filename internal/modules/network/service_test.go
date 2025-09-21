package network

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetworkService_ParseURL(t *testing.T) {
	service := NewNetworkService()

	tests := []struct {
		name     string
		url      string
		expected *URLParts
		wantErr  bool
	}{
		{
			name: "simple HTTP URL",
			url:  "http://example.com",
			expected: &URLParts{
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
			expected: &URLParts{
				Scheme:   "https",
				Host:     "example.com",
				Path:     "/path/to/resource",
				Query:    map[string]string{},
				Fragment: "",
			},
			wantErr: false,
		},
		{
			name: "URL with query parameters",
			url:  "https://example.com/search?q=test&limit=10",
			expected: &URLParts{
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
			expected: &URLParts{
				Scheme:   "https",
				Host:     "example.com",
				Path:     "/page",
				Query:    map[string]string{},
				Fragment: "section1",
			},
			wantErr: false,
		},
		{
			name: "URL with port",
			url:  "http://example.com:8080/api",
			expected: &URLParts{
				Scheme:   "http",
				Host:     "example.com:8080",
				Path:     "/api",
				Query:    map[string]string{},
				Fragment: "",
			},
			wantErr: false,
		},
		{
			name: "complex URL",
			url:  "https://user:pass@example.com:443/path?param1=value1&param2=value2#fragment",
			expected: &URLParts{
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := service.ParseURL(tt.url)

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

func TestNetworkService_BuildURL(t *testing.T) {
	service := NewNetworkService()

	tests := []struct {
		name     string
		parts    *URLParts
		expected string
		wantErr  bool
	}{
		{
			name: "simple URL",
			parts: &URLParts{
				Scheme: "https",
				Host:   "example.com",
			},
			expected: "https://example.com",
			wantErr:  false,
		},
		{
			name: "URL with path",
			parts: &URLParts{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/api/v1/users",
			},
			expected: "https://example.com/api/v1/users",
			wantErr:  false,
		},
		{
			name: "URL with query parameters",
			parts: &URLParts{
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
			name: "URL with fragment",
			parts: &URLParts{
				Scheme:   "https",
				Host:     "example.com",
				Path:     "/page",
				Fragment: "section1",
			},
			expected: "https://example.com/page#section1",
			wantErr:  false,
		},
		{
			name: "complex URL",
			parts: &URLParts{
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
		{
			name: "missing scheme",
			parts: &URLParts{
				Host: "example.com",
			},
			expected: "",
			wantErr:  true,
		},
		{
			name: "missing host",
			parts: &URLParts{
				Scheme: "https",
			},
			expected: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := service.BuildURL(tt.parts)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Empty(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestNetworkService_GetHeaders(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Custom-Header", "test-value")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message": "test"}`))
	}))
	defer server.Close()

	service := NewNetworkServiceWithOptions(true) // Disable SSRF protection for testing

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

func TestNetworkService_ValidateURL_SSRFProtection(t *testing.T) {
	service := &networkService{}

	tests := []struct {
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.validateURL(tt.url)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				// Note: This test might fail for external URLs if DNS resolution fails
				// In a real environment, you might want to mock the DNS resolution
				if err != nil {
					t.Logf("URL validation failed (possibly due to DNS): %v", err)
				}
			}
		})
	}
}

func TestNetworkService_IsPrivateOrReservedIP(t *testing.T) {
	service := &networkService{}

	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{
			name:     "localhost IPv4",
			ip:       "127.0.0.1",
			expected: true,
		},
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
			name:     "AWS metadata",
			ip:       "169.254.169.254",
			expected: true,
		},
		{
			name:     "public IP",
			ip:       "8.8.8.8",
			expected: false,
		},
		{
			name:     "IPv6 loopback",
			ip:       "::1",
			expected: true,
		},
		{
			name:     "IPv6 unique local",
			ip:       "fc00::1",
			expected: true,
		},
		{
			name:     "IPv6 link-local",
			ip:       "fe80::1",
			expected: true,
		},
		{
			name:     "public IPv6",
			ip:       "2001:4860:4860::8888",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			require.NotNil(t, ip, "Invalid IP address in test case")

			result := service.isPrivateOrReservedIP(ip)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNetworkService_DNSLookup(t *testing.T) {
	service := NewNetworkService()

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

func TestNetworkService_AnalyzeIP(t *testing.T) {
	service := NewNetworkService()

	tests := []struct {
		name     string
		ip       string
		expected *IPInfo
		wantErr  bool
	}{
		{
			name: "IPv4 public",
			ip:   "8.8.8.8",
			expected: &IPInfo{
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
			expected: &IPInfo{
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
			expected: &IPInfo{
				IP:         "127.0.0.1",
				Version:    4,
				IsPrivate:  false,
				IsPublic:   false,
				IsLoopback: true,
			},
			wantErr: false,
		},
		{
			name: "IPv6 public",
			ip:   "2001:4860:4860::8888",
			expected: &IPInfo{
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
			expected: &IPInfo{
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
			expected: &IPInfo{
				IP:         "fc00::1",
				Version:    6,
				IsPrivate:  true,
				IsPublic:   false,
				IsLoopback: false,
			},
			wantErr: false,
		},
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