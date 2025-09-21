package network

// URLParseRequest represents a URL parsing request
type URLParseRequest struct {
	URL string `json:"url" binding:"required"`
}

// URLBuildRequest represents a URL building request
type URLBuildRequest struct {
	Scheme   string            `json:"scheme" binding:"required"`
	Host     string            `json:"host" binding:"required"`
	Path     string            `json:"path"`
	Query    map[string]string `json:"query"`
	Fragment string            `json:"fragment"`
}

// URLOperationRequest represents a URL operation request (parse/build)
type URLOperationRequest struct {
	Action string `json:"action" binding:"required,oneof=parse build"`
	
	// For parse operation
	URL string `json:"url"`
	
	// For build operation
	Scheme   string            `json:"scheme"`
	Host     string            `json:"host"`
	Path     string            `json:"path"`
	Query    map[string]string `json:"query"`
	Fragment string            `json:"fragment"`
}

// URLParts represents the constituent parts of a URL
type URLParts struct {
	Scheme   string            `json:"scheme"`
	Host     string            `json:"host"`
	Path     string            `json:"path"`
	Query    map[string]string `json:"query"`
	Fragment string            `json:"fragment"`
}

// URLParseResponse represents a URL parsing response
type URLParseResponse struct {
	Parts *URLParts `json:"parts"`
}

// URLBuildResponse represents a URL building response
type URLBuildResponse struct {
	URL string `json:"url"`
}

// URLOperationResponse represents a URL operation response
type URLOperationResponse struct {
	// For parse operation
	Parts *URLParts `json:"parts,omitempty"`
	
	// For build operation
	URL string `json:"url,omitempty"`
}

// HeadersRequest represents an HTTP headers inspection request
type HeadersRequest struct {
	URL string `json:"url" binding:"required"`
}

// HeadersResponse represents an HTTP headers inspection response
type HeadersResponse struct {
	URL        string            `json:"url"`
	StatusCode int               `json:"statusCode"`
	Headers    map[string]string `json:"headers"`
}

// DNSLookupRequest represents a DNS lookup request
type DNSLookupRequest struct {
	Domain     string `json:"domain" binding:"required"`
	RecordType string `json:"recordType" binding:"required,oneof=A AAAA MX TXT NS CNAME"`
}

// DNSLookupResponse represents a DNS lookup response
type DNSLookupResponse struct {
	Domain     string   `json:"domain"`
	RecordType string   `json:"recordType"`
	Records    []string `json:"records"`
	TTL        int      `json:"ttl,omitempty"`
}

// IPAnalysisRequest represents an IP address analysis request
type IPAnalysisRequest struct {
	IP string `json:"ip" binding:"required"`
}

// IPInfo represents IP address information
type IPInfo struct {
	IP         string `json:"ip"`
	Version    int    `json:"version"`
	IsPrivate  bool   `json:"isPrivate"`
	IsPublic   bool   `json:"isPublic"`
	IsLoopback bool   `json:"isLoopback"`
}

// IPAnalysisResponse represents an IP address analysis response
type IPAnalysisResponse struct {
	Info *IPInfo `json:"info"`
}