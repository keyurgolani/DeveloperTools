package crypto

import (
	"crypto/hmac"
	"crypto/md5" // #nosec G501 - MD5 is intentionally provided for utility/compatibility purposes
	"crypto/rand"
	"crypto/sha1" // #nosec G505 - SHA1 is intentionally provided for utility/compatibility purposes
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"hash"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// Argon2id configuration constants.
const (
	ArgonMemory      = 64 * 1024 // 64MB
	ArgonIterations  = 3
	ArgonParallelism = 4
	ArgonSaltLength  = 16
	ArgonKeyLength   = 32
	// ArgonHashParts is the expected number of parts in an Argon2 hash string.
	ArgonHashParts = 6
)

// CryptoService defines the interface for cryptographic operations.
type CryptoService interface {
	Hash(content string, algorithm string) (string, error)
	HMAC(content, key, algorithm string) (string, error)
	HashPassword(password string) (string, error)
	VerifyPassword(password, hash string) bool
	DecodeCertificate(pemData string) (*CertificateInfo, error)
}

// CertificateInfo represents decoded certificate information.
type CertificateInfo struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	NotBefore    time.Time `json:"notBefore"`
	NotAfter     time.Time `json:"notAfter"`
	SerialNumber string    `json:"serialNumber"`
	Version      int       `json:"version"`
	KeyUsage     []string  `json:"keyUsage"`
	DNSNames     []string  `json:"dnsNames,omitempty"`
}

// cryptoService implements the CryptoService interface.
type cryptoService struct{}

// NewCryptoService creates a new instance of CryptoService.
func NewCryptoService() CryptoService {
	return &cryptoService{}
}

// Hash calculates hash for the given content using the specified algorithm.
func (s *cryptoService) Hash(content string, algorithm string) (string, error) {
	switch algorithm {
	case "md5":
		hash := md5.Sum([]byte(content)) // #nosec G401 - MD5 is intentionally provided for utility/compatibility purposes
		return hex.EncodeToString(hash[:]), nil
	case "sha1":
		hash := sha1.Sum([]byte(content)) // #nosec G401 - SHA1 is intentionally provided for utility/compatibility purposes
		return hex.EncodeToString(hash[:]), nil
	case "sha256":
		hash := sha256.Sum256([]byte(content))
		return hex.EncodeToString(hash[:]), nil
	case "sha512":
		hash := sha512.Sum512([]byte(content))
		return hex.EncodeToString(hash[:]), nil
	default:
		return "", fmt.Errorf("unsupported hash algorithm: %s", algorithm)
	}
}

// HMAC generates HMAC for the given content and key using the specified algorithm.
func (s *cryptoService) HMAC(content, key, algorithm string) (string, error) {
	var hashFunc func() hash.Hash

	switch algorithm {
	case "sha256":
		hashFunc = sha256.New
	case "sha512":
		hashFunc = sha512.New
	default:
		return "", fmt.Errorf("unsupported HMAC algorithm: %s", algorithm)
	}

	h := hmac.New(hashFunc, []byte(key))
	h.Write([]byte(content))

	return hex.EncodeToString(h.Sum(nil)), nil
}

// HashPassword hashes a password using Argon2id with secure defaults.
func (s *cryptoService) HashPassword(password string) (string, error) {
	// Generate a random 16-byte salt
	salt := make([]byte, ArgonSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Generate the hash using Argon2id
	hash := argon2.IDKey([]byte(password), salt, ArgonIterations, ArgonMemory, ArgonParallelism, ArgonKeyLength)

	// Encode the hash in the standard format: $argon2id$v=19$m=65536,t=3,p=4$salt$hash
	saltEncoded := base64.RawStdEncoding.EncodeToString(salt)
	hashEncoded := base64.RawStdEncoding.EncodeToString(hash)

	encodedHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, ArgonMemory, ArgonIterations, ArgonParallelism, saltEncoded, hashEncoded)

	return encodedHash, nil
}

// VerifyPassword verifies a password against its Argon2id hash using constant-time comparison.
func (s *cryptoService) VerifyPassword(password, encodedHash string) bool {
	// Parse the encoded hash
	salt, hash, params, err := parseArgon2Hash(encodedHash)

	// To prevent timing attacks, we always perform the hash computation
	// even if parsing fails, using dummy values
	var actualSalt []byte
	var actualHash []byte
	var actualParams *argon2Params
	var validHash bool

	if err != nil || params == nil || params.parallelism == 0 || params.memory == 0 ||
		params.iterations == 0 || params.keyLength == 0 {
		// Use dummy values to maintain constant time
		actualSalt = make([]byte, ArgonSaltLength)
		actualHash = make([]byte, ArgonKeyLength)
		actualParams = &argon2Params{
			memory:      ArgonMemory,
			iterations:  ArgonIterations,
			parallelism: ArgonParallelism,
			keyLength:   ArgonKeyLength,
		}
		validHash = false
	} else {
		actualSalt = salt
		actualHash = hash
		actualParams = params
		validHash = true
	}

	// Generate hash for the provided password using the same parameters
	otherHash := argon2.IDKey(
		[]byte(password), actualSalt, actualParams.iterations, actualParams.memory,
		actualParams.parallelism, actualParams.keyLength,
	)

	// Use constant-time comparison to prevent timing attacks
	hashMatches := subtle.ConstantTimeCompare(actualHash, otherHash) == 1

	// Use constant-time selection to return the result
	// This ensures both branches take the same time
	validHashInt := subtle.ConstantTimeByteEq(boolToByte(validHash), 1)
	hashMatchesInt := subtle.ConstantTimeByteEq(boolToByte(hashMatches), 1)
	return subtle.ConstantTimeSelect(validHashInt, hashMatchesInt, 0) == 1
}

// boolToByte converts a boolean to a byte for constant-time operations.
func boolToByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}

// argon2Params holds the parameters for Argon2id.
type argon2Params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	keyLength   uint32
}

// parseArgon2Hash parses an Argon2id encoded hash and extracts the salt, hash, and parameters.
func parseArgon2Hash(encodedHash string) (salt, hash []byte, params *argon2Params, err error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != ArgonHashParts {
		return nil, nil, nil, fmt.Errorf("invalid hash format")
	}

	if parts[1] != "argon2id" {
		return nil, nil, nil, fmt.Errorf("unsupported algorithm: %s", parts[1])
	}

	// Parse version
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid version format: %w", err)
	}
	if version != argon2.Version {
		return nil, nil, nil, fmt.Errorf("unsupported version: %d", version)
	}

	// Parse parameters
	params = &argon2Params{}
	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.memory, &params.iterations, &params.parallelism)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid parameters format: %w", err)
	}

	// Decode salt
	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid salt encoding: %w", err)
	}

	// Decode hash
	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid hash encoding: %w", err)
	}

	// Validate hash length to prevent overflow
	hashLen := len(hash)
	if hashLen < 0 || hashLen > 0xFFFFFFFF {
		return nil, nil, nil, fmt.Errorf("invalid hash length: %d", hashLen)
	}
	params.keyLength = uint32(hashLen) // #nosec G115 - length validated above

	return salt, hash, params, nil
}

// DecodeCertificate decodes a PEM-encoded X.509 certificate and extracts key information.
func (s *cryptoService) DecodeCertificate(pemData string) (*CertificateInfo, error) {
	// Decode the PEM block
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("PEM block is not a certificate, got: %s", block.Type)
	}

	// Parse the X.509 certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Extract key usage information
	keyUsage := extractKeyUsage(cert)

	// Ensure DNSNames is never nil
	dnsNames := cert.DNSNames
	if dnsNames == nil {
		dnsNames = make([]string, 0)
	}

	// Create certificate info
	certInfo := &CertificateInfo{
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		SerialNumber: cert.SerialNumber.String(),
		Version:      cert.Version,
		KeyUsage:     keyUsage,
		DNSNames:     dnsNames,
	}

	return certInfo, nil
}

// extractKeyUsage converts x509.KeyUsage flags to string descriptions.
func extractKeyUsage(cert *x509.Certificate) []string {
	usage := make([]string, 0)

	usage = append(usage, extractBasicKeyUsage(cert)...)
	usage = append(usage, extractExtendedKeyUsage(cert)...)

	return usage
}

func extractBasicKeyUsage(cert *x509.Certificate) []string {
	usage := make([]string, 0)

	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		usage = append(usage, "Digital Signature")
	}
	if cert.KeyUsage&x509.KeyUsageContentCommitment != 0 {
		usage = append(usage, "Content Commitment")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		usage = append(usage, "Key Encipherment")
	}
	if cert.KeyUsage&x509.KeyUsageDataEncipherment != 0 {
		usage = append(usage, "Data Encipherment")
	}
	if cert.KeyUsage&x509.KeyUsageKeyAgreement != 0 {
		usage = append(usage, "Key Agreement")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		usage = append(usage, "Certificate Sign")
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign != 0 {
		usage = append(usage, "CRL Sign")
	}
	if cert.KeyUsage&x509.KeyUsageEncipherOnly != 0 {
		usage = append(usage, "Encipher Only")
	}
	if cert.KeyUsage&x509.KeyUsageDecipherOnly != 0 {
		usage = append(usage, "Decipher Only")
	}

	return usage
}

func extractExtendedKeyUsage(cert *x509.Certificate) []string {
	usage := make([]string, 0)

	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			usage = append(usage, "Server Authentication")
		case x509.ExtKeyUsageClientAuth:
			usage = append(usage, "Client Authentication")
		case x509.ExtKeyUsageCodeSigning:
			usage = append(usage, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			usage = append(usage, "Email Protection")
		case x509.ExtKeyUsageTimeStamping:
			usage = append(usage, "Time Stamping")
		case x509.ExtKeyUsageOCSPSigning:
			usage = append(usage, "OCSP Signing")
		case x509.ExtKeyUsageAny:
			usage = append(usage, "Any")
		case x509.ExtKeyUsageIPSECEndSystem:
			usage = append(usage, "IPSEC End System")
		case x509.ExtKeyUsageIPSECTunnel:
			usage = append(usage, "IPSEC Tunnel")
		case x509.ExtKeyUsageIPSECUser:
			usage = append(usage, "IPSEC User")
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			usage = append(usage, "Microsoft Server Gated Crypto")
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			usage = append(usage, "Netscape Server Gated Crypto")
		case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
			usage = append(usage, "Microsoft Commercial Code Signing")
		case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
			usage = append(usage, "Microsoft Kernel Code Signing")
		default:
			usage = append(usage, "Unknown")
		}
	}

	return usage
}
