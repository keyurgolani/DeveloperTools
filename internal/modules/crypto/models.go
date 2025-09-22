package crypto

// HashRequest represents a hash calculation request.
type HashRequest struct {
	Content   string `json:"content"`
	Algorithm string `json:"algorithm" binding:"required,oneof=md5 sha1 sha256 sha512"`
}

// HashResponse represents a hash calculation response.
type HashResponse struct {
	Hash      string `json:"hash"`
	Algorithm string `json:"algorithm"`
}

// HMACRequest represents an HMAC generation request.
type HMACRequest struct {
	Content   string `json:"content"`
	Key       string `json:"key" binding:"required"`
	Algorithm string `json:"algorithm" binding:"required,oneof=sha256 sha512"`
}

// HMACResponse represents an HMAC generation response.
type HMACResponse struct {
	HMAC      string `json:"hmac"`
	Algorithm string `json:"algorithm"`
}

// PasswordHashRequest represents a password hashing request.
type PasswordHashRequest struct {
	Password string `json:"password"`
}

// PasswordHashResponse represents a password hashing response.
type PasswordHashResponse struct {
	Hash string `json:"hash"`
}

// PasswordVerifyRequest represents a password verification request.
type PasswordVerifyRequest struct {
	Password string `json:"password"`
	Hash     string `json:"hash" binding:"required"`
}

// PasswordVerifyResponse represents a password verification response.
type PasswordVerifyResponse struct {
	Valid bool `json:"valid"`
}

// CertificateDecodeRequest represents a certificate decoding request.
type CertificateDecodeRequest struct {
	Certificate string `json:"certificate" binding:"required"`
}

// CertificateDecodeResponse represents a certificate decoding response.
type CertificateDecodeResponse struct {
	Certificate *CertificateInfo `json:"certificate"`
}
