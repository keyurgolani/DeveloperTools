package network

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// NetworkService defines the interface for network operations
type NetworkService interface {
	ParseURL(urlStr string) (*URLParts, error)
	BuildURL(parts *URLParts) (string, error)
	GetHeaders(urlStr string) (*HeadersResponse, error)
	DNSLookup(domain, recordType string) (*DNSLookupResponse, error)
	AnalyzeIP(ip string) (*IPInfo, error)
}

// networkService implements the NetworkService interface
type networkService struct {
	httpClient         *http.Client
	disableSSRFProtection bool
}

// NewNetworkService creates a new instance of NetworkService
func NewNetworkService() NetworkService {
	return NewNetworkServiceWithOptions(false)
}

// NewNetworkServiceWithOptions creates a new instance of NetworkService with options
func NewNetworkServiceWithOptions(disableSSRFProtection bool) NetworkService {
	// Create HTTP client with timeout and disabled redirects
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Disable redirects
		},
	}

	return &networkService{
		httpClient:            client,
		disableSSRFProtection: disableSSRFProtection,
	}
}

// ParseURL parses a URL into its constituent parts
func (s *networkService) ParseURL(urlStr string) (*URLParts, error) {
	// Basic validation - empty URLs are invalid
	if strings.TrimSpace(urlStr) == "" {
		return nil, fmt.Errorf("empty URL")
	}

	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	// Validate that it's a proper URL - should have at least a scheme or host
	if parsedURL.Scheme == "" && parsedURL.Host == "" && !strings.Contains(urlStr, "://") {
		return nil, fmt.Errorf("invalid URL format")
	}

	// Parse query parameters into map
	queryMap := make(map[string]string)
	for key, values := range parsedURL.Query() {
		if len(values) > 0 {
			queryMap[key] = values[0] // Take first value if multiple
		}
	}

	// Handle user info in host for complex URLs
	host := parsedURL.Host
	if parsedURL.User != nil {
		if password, hasPassword := parsedURL.User.Password(); hasPassword {
			host = parsedURL.User.Username() + ":" + password + "@" + parsedURL.Host
		} else {
			host = parsedURL.User.Username() + "@" + parsedURL.Host
		}
	}

	parts := &URLParts{
		Scheme:   parsedURL.Scheme,
		Host:     host,
		Path:     parsedURL.Path,
		Query:    queryMap,
		Fragment: parsedURL.Fragment,
	}

	return parts, nil
}

// BuildURL constructs a URL from provided components
func (s *networkService) BuildURL(parts *URLParts) (string, error) {
	if parts.Scheme == "" {
		return "", fmt.Errorf("scheme is required")
	}
	if parts.Host == "" {
		return "", fmt.Errorf("host is required")
	}

	// Build the URL
	u := &url.URL{
		Scheme:   parts.Scheme,
		Host:     parts.Host,
		Path:     parts.Path,
		Fragment: parts.Fragment,
	}

	// Add query parameters
	if len(parts.Query) > 0 {
		values := url.Values{}
		for key, value := range parts.Query {
			values.Add(key, value)
		}
		u.RawQuery = values.Encode()
	}

	return u.String(), nil
}

// GetHeaders makes an HTTP GET request and returns response headers with SSRF protection
func (s *networkService) GetHeaders(urlStr string) (*HeadersResponse, error) {
	// Validate URL and implement SSRF protection (unless disabled for testing)
	if !s.disableSSRFProtection {
		if err := s.validateURL(urlStr); err != nil {
			return nil, fmt.Errorf("URL validation failed: %w", err)
		}
	}

	// Create request with custom User-Agent
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", "MCP-Network-Utility/1.1")

	// Make the request
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			// Log error but don't fail the operation
			_ = closeErr
		}
	}()

	// Convert headers to map
	headers := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			headers[key] = values[0] // Take first value if multiple
		}
	}

	response := &HeadersResponse{
		URL:        urlStr,
		StatusCode: resp.StatusCode,
		Headers:    headers,
	}

	return response, nil
}

// validateURL implements SSRF protection by checking if URL points to private/reserved IP ranges
func (s *networkService) validateURL(urlStr string) error {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// Only allow HTTP and HTTPS schemes
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("unsupported scheme: %s", parsedURL.Scheme)
	}

	hostname := parsedURL.Hostname()
	if hostname == "" {
		return fmt.Errorf("no hostname in URL")
	}

	// Resolve hostname to IP addresses
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return fmt.Errorf("failed to resolve hostname: %w", err)
	}

	// Check each resolved IP against blocked ranges
	for _, ip := range ips {
		if s.isPrivateOrReservedIP(ip) {
			return fmt.Errorf("access to private/reserved IP %s blocked", ip.String())
		}
	}

	return nil
}

// isPrivateOrReservedIP checks if an IP address is private or reserved
func (s *networkService) isPrivateOrReservedIP(ip net.IP) bool {
	// Define blocked CIDR ranges
	blockedRanges := []string{
		"127.0.0.0/8",    // Loopback
		"10.0.0.0/8",     // Private Class A
		"172.16.0.0/12",  // Private Class B
		"192.168.0.0/16", // Private Class C
		"169.254.0.0/16", // Link-local (AWS metadata)
		"::1/128",        // IPv6 loopback
		"fc00::/7",       // IPv6 unique local
		"fe80::/10",      // IPv6 link-local
	}

	for _, cidr := range blockedRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// DNSLookup performs DNS resolution for various record types
func (s *networkService) DNSLookup(domain, recordType string) (*DNSLookupResponse, error) {
	var records []string
	var err error

	switch strings.ToUpper(recordType) {
	case "A":
		ips, lookupErr := net.LookupIP(domain)
		if lookupErr != nil {
			err = lookupErr
		} else {
			for _, ip := range ips {
				if ip.To4() != nil { // IPv4 only
					records = append(records, ip.String())
				}
			}
		}
	case "AAAA":
		ips, lookupErr := net.LookupIP(domain)
		if lookupErr != nil {
			err = lookupErr
		} else {
			for _, ip := range ips {
				if ip.To4() == nil { // IPv6 only
					records = append(records, ip.String())
				}
			}
		}
	case "MX":
		mxRecords, lookupErr := net.LookupMX(domain)
		if lookupErr != nil {
			err = lookupErr
		} else {
			for _, mx := range mxRecords {
				records = append(records, fmt.Sprintf("%d %s", mx.Pref, mx.Host))
			}
		}
	case "TXT":
		txtRecords, lookupErr := net.LookupTXT(domain)
		if lookupErr != nil {
			err = lookupErr
		} else {
			records = txtRecords
		}
	case "NS":
		nsRecords, lookupErr := net.LookupNS(domain)
		if lookupErr != nil {
			err = lookupErr
		} else {
			for _, ns := range nsRecords {
				records = append(records, ns.Host)
			}
		}
	case "CNAME":
		cname, lookupErr := net.LookupCNAME(domain)
		if lookupErr != nil {
			err = lookupErr
		} else {
			records = append(records, cname)
		}
	default:
		return nil, fmt.Errorf("unsupported record type: %s", recordType)
	}

	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed: %w", err)
	}

	response := &DNSLookupResponse{
		Domain:     domain,
		RecordType: strings.ToUpper(recordType),
		Records:    records,
		// TTL is not available through Go's standard net package
	}

	return response, nil
}

// AnalyzeIP validates and classifies an IP address
func (s *networkService) AnalyzeIP(ipStr string) (*IPInfo, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	info := &IPInfo{
		IP:         ip.String(),
		IsLoopback: ip.IsLoopback(),
	}

	// Determine IP version
	if ip.To4() != nil {
		info.Version = 4
	} else {
		info.Version = 6
	}

	// Determine if private or public
	info.IsPrivate = s.isPrivateIP(ip)
	info.IsPublic = !info.IsPrivate && !info.IsLoopback

	return info, nil
}

// isPrivateIP checks if an IP address is in private ranges (excluding loopback)
func (s *networkService) isPrivateIP(ip net.IP) bool {
	// Define private CIDR ranges (excluding loopback)
	privateRanges := []string{
		"10.0.0.0/8",     // Private Class A
		"172.16.0.0/12",  // Private Class B
		"192.168.0.0/16", // Private Class C
		"fc00::/7",       // IPv6 unique local
	}

	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}

	return false
}