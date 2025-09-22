package transform

// Base64Request represents a request for Base64 encoding/decoding.
type Base64Request struct {
	Content string `json:"content" binding:"required"`
	Action  string `json:"action" binding:"required,oneof=encode decode"`
	URLSafe bool   `json:"urlSafe,omitempty"`
}

// Base64Response represents the response for Base64 operations.
type Base64Response struct {
	Result string `json:"result"`
}

// URLEncodeRequest represents a request for URL encoding/decoding.
type URLEncodeRequest struct {
	Content string `json:"content" binding:"required"`
	Action  string `json:"action" binding:"required,oneof=encode decode"`
}

// URLEncodeResponse represents the response for URL encoding operations.
type URLEncodeResponse struct {
	Result string `json:"result"`
}

// JWTDecodeRequest represents a request for JWT decoding.
type JWTDecodeRequest struct {
	Token string `json:"token" binding:"required"`
}

// JWTDecodeResponse represents the response for JWT decoding.
type JWTDecodeResponse struct {
	Header            map[string]interface{} `json:"header"`
	Payload           map[string]interface{} `json:"payload"`
	SignatureVerified bool                   `json:"signatureVerified"`
}

// CompressionRequest represents a request for compression/decompression.
type CompressionRequest struct {
	Content   string `json:"content" binding:"required"`
	Action    string `json:"action" binding:"required,oneof=compress decompress"`
	Algorithm string `json:"algorithm" binding:"required,oneof=gzip zlib"`
}

// CompressionResponse represents the response for compression operations.
type CompressionResponse struct {
	Result string `json:"result"`
}
