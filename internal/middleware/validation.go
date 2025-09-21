package middleware

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	// MaxRequestBodySize is the maximum allowed request body size (1MB)
	MaxRequestBodySize = 1024 * 1024 // 1MB
)

// ValidationConfig holds validation configuration
type ValidationConfig struct {
	MaxBodySize         int64    `json:"maxBodySize"`
	AllowedSchemes      []string `json:"allowedSchemes"`
	BlockedCIDRs        []string `json:"blockedCidrs"`
	BlockedDomains      []string `json:"blockedDomains"`
	AllowPrivateIPs     bool     `json:"allowPrivateIps"`
	AllowLoopbackIPs    bool     `json:"allowLoopbackIps"`
	AllowLinkLocalIPs   bool     `json:"allowLinkLocalIps"`
	AllowMulticastIPs   bool     `json:"allowMulticastIps"`
	AllowBroadcastIPs   bool     `json:"allowBroadcastIps"`
}

// DefaultValidationConfig returns a secure default validation configuration
func DefaultValidationConfig() *ValidationConfig {
	return &ValidationConfig{
		MaxBodySize:         MaxRequestBodySize,
		AllowedSchemes:      []string{"http", "https"},
		BlockedCIDRs:        []string{},
		BlockedDomains:      []string{},
		AllowPrivateIPs:     false,
		AllowLoopbackIPs:    false,
		AllowLinkLocalIPs:   false,
		AllowMulticastIPs:   false,
		AllowBroadcastIPs:   false,
	}
}

// ValidationMiddleware provides input validation and SSRF protection
type ValidationMiddleware struct {
	config      *ValidationConfig
	logger      *slog.Logger
	blockedNets []*net.IPNet
}

// NewValidationMiddleware creates a new validation middleware
func NewValidationMiddleware(config *ValidationConfig, logger *slog.Logger) (*ValidationMiddleware, error) {
	if config == nil {
		config = DefaultValidationConfig()
	}

	middleware := &ValidationMiddleware{
		config: config,
		logger: logger,
	}

	// Parse blocked CIDRs
	for _, cidr := range config.BlockedCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %s: %w", cidr, err)
		}
		middleware.blockedNets = append(middleware.blockedNets, network)
	}

	return middleware, nil
}

// LimitRequestSize returns middleware that limits request body size
func (v *ValidationMiddleware) LimitRequestSize() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > v.config.MaxBodySize {
			v.logger.Warn("Request body too large",
				"content_length", c.Request.ContentLength,
				"max_size", v.config.MaxBodySize,
				"path", c.Request.URL.Path,
				"ip", c.ClientIP(),
			)

			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"error": gin.H{
					"code":    "REQUEST_TOO_LARGE",
					"message": "Request body too large",
					"details": fmt.Sprintf("Maximum allowed size is %d bytes", v.config.MaxBodySize),
				},
			})
			c.Abort()
			return
		}

		// Set MaxBytesReader to enforce the limit during reading
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, v.config.MaxBodySize)
		c.Next()
	}
}

// SanitizeInput returns middleware that sanitizes common input fields
func (v *ValidationMiddleware) SanitizeInput() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Sanitize query parameters
		for key, values := range c.Request.URL.Query() {
			for i, value := range values {
				c.Request.URL.Query()[key][i] = v.sanitizeString(value)
			}
		}

		// Note: Request body sanitization would need to be done per endpoint
		// since different endpoints expect different JSON structures
		c.Next()
	}
}

// ValidateURL validates a URL for SSRF protection
func (v *ValidationMiddleware) ValidateURL(urlStr string) error {
	if urlStr == "" {
		return fmt.Errorf("URL cannot be empty")
	}

	// Parse URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}

	// Validate scheme
	if !v.isAllowedScheme(parsedURL.Scheme) {
		return fmt.Errorf("scheme %s is not allowed", parsedURL.Scheme)
	}

	// Check for blocked domains
	if v.isDomainBlocked(parsedURL.Hostname()) {
		return fmt.Errorf("domain %s is blocked", parsedURL.Hostname())
	}

	// Resolve hostname to IP addresses
	ips, err := net.LookupIP(parsedURL.Hostname())
	if err != nil {
		return fmt.Errorf("failed to resolve hostname %s: %w", parsedURL.Hostname(), err)
	}

	// Validate each resolved IP
	for _, ip := range ips {
		if err := v.validateIP(ip); err != nil {
			return fmt.Errorf("IP %s is not allowed: %w", ip.String(), err)
		}
	}

	return nil
}

// validateIP checks if an IP address is allowed
func (v *ValidationMiddleware) validateIP(ip net.IP) error {
	// Check against explicitly blocked networks
	for _, network := range v.blockedNets {
		if network.Contains(ip) {
			return fmt.Errorf("IP is in blocked network %s", network.String())
		}
	}

	// Check IP type restrictions
	if ip.IsPrivate() && !v.config.AllowPrivateIPs {
		return fmt.Errorf("private IP addresses are not allowed")
	}

	if ip.IsLoopback() && !v.config.AllowLoopbackIPs {
		return fmt.Errorf("loopback IP addresses are not allowed")
	}

	if ip.IsLinkLocalUnicast() && !v.config.AllowLinkLocalIPs {
		return fmt.Errorf("link-local IP addresses are not allowed")
	}

	if ip.IsMulticast() && !v.config.AllowMulticastIPs {
		return fmt.Errorf("multicast IP addresses are not allowed")
	}

	// Check for broadcast addresses (IPv4 only)
	if ip.To4() != nil && v.isBroadcastIP(ip) && !v.config.AllowBroadcastIPs {
		return fmt.Errorf("broadcast IP addresses are not allowed")
	}

	// Additional checks for well-known dangerous IPs (only if not explicitly allowed)
	if v.isDangerousIP(ip) && !v.isIPExplicitlyAllowed(ip) {
		return fmt.Errorf("IP address is in dangerous range")
	}

	return nil
}

// isAllowedScheme checks if a URL scheme is allowed
func (v *ValidationMiddleware) isAllowedScheme(scheme string) bool {
	scheme = strings.ToLower(scheme)
	for _, allowed := range v.config.AllowedSchemes {
		if strings.ToLower(allowed) == scheme {
			return true
		}
	}
	return false
}

// isDomainBlocked checks if a domain is in the blocked list
func (v *ValidationMiddleware) isDomainBlocked(domain string) bool {
	domain = strings.ToLower(domain)
	for _, blocked := range v.config.BlockedDomains {
		if strings.ToLower(blocked) == domain {
			return true
		}
	}
	return false
}

// isBroadcastIP checks if an IPv4 address is a broadcast address
func (v *ValidationMiddleware) isBroadcastIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		// Check for limited broadcast (255.255.255.255)
		if ip4.Equal(net.IPv4bcast) {
			return true
		}
		// Note: Checking for directed broadcast would require network context
	}
	return false
}

// isDangerousIP checks for well-known dangerous IP ranges
func (v *ValidationMiddleware) isDangerousIP(ip net.IP) bool {
	dangerousRanges := []string{
		"169.254.169.254/32", // AWS/GCP/Azure metadata
		"169.254.0.0/16",     // Link-local (additional check)
		"127.0.0.0/8",        // Loopback (additional check)
		"0.0.0.0/8",          // "This network"
		"10.0.0.0/8",         // Private Class A
		"172.16.0.0/12",      // Private Class B
		"192.168.0.0/16",     // Private Class C
		"224.0.0.0/4",        // Multicast
		"240.0.0.0/4",        // Reserved
		"::1/128",            // IPv6 loopback
		"fc00::/7",           // IPv6 unique local
		"fe80::/10",          // IPv6 link-local
		"ff00::/8",           // IPv6 multicast
	}

	for _, rangeStr := range dangerousRanges {
		_, network, err := net.ParseCIDR(rangeStr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// isIPExplicitlyAllowed checks if an IP is explicitly allowed by configuration
func (v *ValidationMiddleware) isIPExplicitlyAllowed(ip net.IP) bool {
	// Check if private IPs are allowed and this is a private IP
	if ip.IsPrivate() && v.config.AllowPrivateIPs {
		return true
	}
	
	// Check if loopback IPs are allowed and this is a loopback IP
	if ip.IsLoopback() && v.config.AllowLoopbackIPs {
		return true
	}
	
	// Check if link-local IPs are allowed and this is a link-local IP
	if ip.IsLinkLocalUnicast() && v.config.AllowLinkLocalIPs {
		return true
	}
	
	// Check if multicast IPs are allowed and this is a multicast IP
	if ip.IsMulticast() && v.config.AllowMulticastIPs {
		return true
	}
	
	// Check if broadcast IPs are allowed and this is a broadcast IP
	if ip.To4() != nil && v.isBroadcastIP(ip) && v.config.AllowBroadcastIPs {
		return true
	}
	
	return false
}

// sanitizeString performs basic string sanitization
func (v *ValidationMiddleware) sanitizeString(input string) string {
	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")
	
	// Remove control characters except tab, newline, and carriage return
	var result strings.Builder
	for _, r := range input {
		if r >= 32 || r == '\t' || r == '\n' || r == '\r' {
			result.WriteRune(r)
		}
	}
	
	return result.String()
}

// ValidateInput performs comprehensive input validation
func (v *ValidationMiddleware) ValidateInput(input string, maxLength int, allowEmpty bool) error {
	if !allowEmpty && strings.TrimSpace(input) == "" {
		return fmt.Errorf("input cannot be empty")
	}

	if len(input) > maxLength {
		return fmt.Errorf("input too long: %d characters, maximum %d allowed", len(input), maxLength)
	}

	// Check for null bytes
	if strings.Contains(input, "\x00") {
		return fmt.Errorf("input contains null bytes")
	}

	// Check for excessive control characters
	controlCount := 0
	for _, r := range input {
		if r < 32 && r != '\t' && r != '\n' && r != '\r' {
			controlCount++
		}
	}

	if controlCount > len(input)/10 { // More than 10% control characters
		return fmt.Errorf("input contains too many control characters")
	}

	return nil
}

// ValidateRegex validates a regular expression pattern
func (v *ValidationMiddleware) ValidateRegex(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("regex pattern cannot be empty")
	}

	// Limit pattern length to prevent ReDoS
	if len(pattern) > 1000 {
		return fmt.Errorf("regex pattern too long: maximum 1000 characters allowed")
	}

	// Try to compile the regex
	_, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid regex pattern: %w", err)
	}

	// Check for potentially dangerous patterns
	dangerousPatterns := []string{
		`\(\?\#`,     // Comments can be used for injection
		`\(\?\:.*\)\+`, // Nested quantifiers can cause ReDoS
		`\(\?\=.*\)\*`, // Lookaheads with quantifiers
		`\(\?\!.*\)\+`, // Negative lookaheads with quantifiers
	}

	for _, dangerous := range dangerousPatterns {
		if matched, _ := regexp.MatchString(dangerous, pattern); matched {
			return fmt.Errorf("regex pattern contains potentially dangerous constructs")
		}
	}

	return nil
}

// ValidateJSON validates JSON input
func (v *ValidationMiddleware) ValidateJSON(input string, maxSize int) error {
	if len(input) > maxSize {
		return fmt.Errorf("JSON input too large: %d bytes, maximum %d allowed", len(input), maxSize)
	}

	// Basic JSON structure validation (without full parsing for performance)
	input = strings.TrimSpace(input)
	if !strings.HasPrefix(input, "{") && !strings.HasPrefix(input, "[") {
		return fmt.Errorf("input does not appear to be valid JSON")
	}

	// Check for balanced braces/brackets (basic check)
	braceCount := 0
	bracketCount := 0
	inString := false
	escaped := false

	for _, r := range input {
		if escaped {
			escaped = false
			continue
		}

		if r == '\\' {
			escaped = true
			continue
		}

		if r == '"' {
			inString = !inString
			continue
		}

		if !inString {
			switch r {
			case '{':
				braceCount++
			case '}':
				braceCount--
			case '[':
				bracketCount++
			case ']':
				bracketCount--
			}
		}
	}

	if braceCount != 0 || bracketCount != 0 {
		return fmt.Errorf("JSON input has unbalanced braces or brackets")
	}

	return nil
}