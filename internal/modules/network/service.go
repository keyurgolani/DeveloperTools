package network

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// NetworkService defines the interface for network operations.
type NetworkService interface {
	ParseURL(urlStr string) (*URLParts, error)
	BuildURL(parts *URLParts) (string, error)
	GetHeaders(urlStr string) (*HeadersResponse, error)
	DNSLookup(domain, recordType string) (*DNSLookupResponse, error)
	AnalyzeIP(ip string) (*IPInfo, error)
}

// networkService implements the NetworkService interface.
type networkService struct {
	httpClient            *http.Client
	disableSSRFProtection bool
}

// NewNetworkService creates a new instance of NetworkService.
func NewNetworkService() NetworkService {
	return NewNetworkServiceWithOptions(false)
}

// NewNetworkServiceWithOptions creates a new instance of NetworkService with options.
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

// ParseURL parses a URL into its constituent parts.
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

// BuildURL constructs a URL from provided components.
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

// GetHeaders makes an HTTP GET request and returns response headers with SSRF protection.
func (s *networkService) GetHeaders(urlStr string) (*HeadersResponse, error) {
	// Validate URL and implement SSRF protection (unless disabled for testing)
	if !s.disableSSRFProtection {
		if err := s.validateURL(urlStr); err != nil {
			return nil, fmt.Errorf("URL validation failed: %w", err)
		}
	}

	// Create request with custom User-Agent
	req, err := http.NewRequestWithContext(context.Background(), "GET", urlStr, nil)
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resolver := &net.Resolver{}
	ips, err := resolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		return fmt.Errorf("failed to resolve hostname: %w", err)
	}

	// Check each resolved IP against blocked ranges
	for _, ipAddr := range ips {
		if s.isPrivateOrReservedIP(ipAddr.IP) {
			return fmt.Errorf("access to private/reserved IP %s blocked", ipAddr.IP.String())
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
	recordTypeUpper := strings.ToUpper(recordType)

	records, err := s.performDNSLookup(domain, recordTypeUpper)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed: %w", err)
	}

	return &DNSLookupResponse{
		Domain:     domain,
		RecordType: recordTypeUpper,
		Records:    records,
		// TTL is not available through Go's standard net package
	}, nil
}

// performDNSLookup performs the actual DNS lookup based on record type
func (s *networkService) performDNSLookup(domain, recordType string) ([]string, error) {
	switch recordType {
	case "A":
		return s.lookupARecords(domain)
	case "AAAA":
		return s.lookupAAAARecords(domain)
	case "MX":
		return s.lookupMXRecords(domain)
	case "TXT":
		return s.lookupTXTRecords(domain)
	case "NS":
		return s.lookupNSRecords(domain)
	case "CNAME":
		return s.lookupCNAMERecord(domain)
	default:
		return nil, fmt.Errorf("unsupported record type: %s", recordType)
	}
}

// lookupARecords performs A record lookup (IPv4)
func (s *networkService) lookupARecords(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resolver := &net.Resolver{}
	ips, err := resolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return nil, err
	}

	var records []string
	for _, ip := range ips {
		if ip.IP.To4() != nil { // IPv4 only
			records = append(records, ip.IP.String())
		}
	}
	return records, nil
}

// lookupAAAARecords performs AAAA record lookup (IPv6)
func (s *networkService) lookupAAAARecords(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resolver := &net.Resolver{}
	ips, err := resolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return nil, err
	}

	var records []string
	for _, ip := range ips {
		if ip.IP.To4() == nil { // IPv6 only
			records = append(records, ip.IP.String())
		}
	}
	return records, nil
}

// lookupMXRecords performs MX record lookup
func (s *networkService) lookupMXRecords(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resolver := &net.Resolver{}
	mxRecords, err := resolver.LookupMX(ctx, domain)
	if err != nil {
		return nil, err
	}

	var records []string
	for _, mx := range mxRecords {
		records = append(records, fmt.Sprintf("%d %s", mx.Pref, mx.Host))
	}
	return records, nil
}

// lookupTXTRecords performs TXT record lookup
func (s *networkService) lookupTXTRecords(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resolver := &net.Resolver{}
	return resolver.LookupTXT(ctx, domain)
}

// lookupNSRecords performs NS record lookup
func (s *networkService) lookupNSRecords(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resolver := &net.Resolver{}
	nsRecords, err := resolver.LookupNS(ctx, domain)
	if err != nil {
		return nil, err
	}

	var records []string
	for _, ns := range nsRecords {
		records = append(records, ns.Host)
	}
	return records, nil
}

// lookupCNAMERecord performs CNAME record lookup
func (s *networkService) lookupCNAMERecord(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resolver := &net.Resolver{}
	cname, err := resolver.LookupCNAME(ctx, domain)
	if err != nil {
		return nil, err
	}
	return []string{cname}, nil
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
