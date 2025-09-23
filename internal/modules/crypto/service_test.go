package crypto_test

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/keyurgolani/DeveloperTools/internal/modules/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testSHA256Algorithm = "sha256"
	testBinaryData      = "\x00\x01\x02\x03\xff\xfe\xfd"
	testContent         = "test"
	testConsistencyData = "consistency test"
	testHMACKey         = "testkey"
	testHMACContent     = "test content"
	testCertificate     = `-----BEGIN CERTIFICATE-----
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
)

func TestCryptoService_Hash(t *testing.T) {
	service := crypto.NewCryptoService()
	tests := getHashTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executeHashTest(t, service, tt)
		})
	}
}

func getMD5TestCases() []struct {
	name      string
	content   string
	algorithm string
	expected  string
	wantErr   bool
} {
	return []struct {
		name      string
		content   string
		algorithm string
		expected  string
		wantErr   bool
	}{
		{
			name:      "MD5 empty string",
			content:   "",
			algorithm: "md5",
			expected:  "d41d8cd98f00b204e9800998ecf8427e",
			wantErr:   false,
		},
		{
			name:      "MD5 hello world",
			content:   "hello world",
			algorithm: "md5",
			expected:  "5eb63bbbe01eeed093cb22bb8f5acdc3",
			wantErr:   false,
		},
		{
			name:      "MD5 The quick brown fox",
			content:   "The quick brown fox jumps over the lazy dog",
			algorithm: "md5",
			expected:  "9e107d9d372bb6826bd81d3542a419d6",
			wantErr:   false,
		},
	}
}

func getSHA1TestCases() []struct {
	name      string
	content   string
	algorithm string
	expected  string
	wantErr   bool
} {
	return []struct {
		name      string
		content   string
		algorithm string
		expected  string
		wantErr   bool
	}{
		{
			name:      "SHA1 empty string",
			content:   "",
			algorithm: "sha1",
			expected:  "da39a3ee5e6b4b0d3255bfef95601890afd80709",
			wantErr:   false,
		},
		{
			name:      "SHA1 hello world",
			content:   "hello world",
			algorithm: "sha1",
			expected:  "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
			wantErr:   false,
		},
		{
			name:      "SHA1 The quick brown fox",
			content:   "The quick brown fox jumps over the lazy dog",
			algorithm: "sha1",
			expected:  "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
			wantErr:   false,
		},
	}
}

func getSHA256TestCases() []struct {
	name      string
	content   string
	algorithm string
	expected  string
	wantErr   bool
} {
	return []struct {
		name      string
		content   string
		algorithm string
		expected  string
		wantErr   bool
	}{
		{
			name:      "SHA256 empty string",
			content:   "",
			algorithm: "sha256",
			expected:  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantErr:   false,
		},
		{
			name:      "SHA256 hello world",
			content:   "hello world",
			algorithm: "sha256",
			expected:  "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
			wantErr:   false,
		},
		{
			name:      "SHA256 The quick brown fox",
			content:   "The quick brown fox jumps over the lazy dog",
			algorithm: "sha256",
			expected:  "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
			wantErr:   false,
		},
	}
}

func getSHA512TestCases() []struct {
	name      string
	content   string
	algorithm string
	expected  string
	wantErr   bool
} {
	return []struct {
		name      string
		content   string
		algorithm string
		expected  string
		wantErr   bool
	}{
		{
			name:      "SHA512 empty string",
			content:   "",
			algorithm: "sha512",
			expected: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
				"47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
			wantErr: false,
		},
		{
			name:      "SHA512 hello world",
			content:   "hello world",
			algorithm: "sha512",
			expected: "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f" +
				"989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f",
			wantErr: false,
		},
		{
			name:      "SHA512 The quick brown fox",
			content:   "The quick brown fox jumps over the lazy dog",
			algorithm: "sha512",
			expected: "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642" +
				"e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6",
			wantErr: false,
		},
	}
}

func getHashErrorTestCases() []struct {
	name      string
	content   string
	algorithm string
	expected  string
	wantErr   bool
} {
	return []struct {
		name      string
		content   string
		algorithm string
		expected  string
		wantErr   bool
	}{
		{
			name:      "SHA256 large content",
			content:   string(make([]byte, 10000)),
			algorithm: "sha256",
			expected:  "95b532cc4381affdff0d956e12520a04129ed49d37e154228368fe5621f0b9a2",
			wantErr:   false,
		},
		{
			name:      "Unsupported algorithm",
			content:   "test",
			algorithm: "unsupported",
			expected:  "",
			wantErr:   true,
		},
		{
			name:      "Empty algorithm",
			content:   "test",
			algorithm: "",
			expected:  "",
			wantErr:   true,
		},
	}
}

func getHashTestCases() []struct {
	name      string
	content   string
	algorithm string
	expected  string
	wantErr   bool
} {
	var testCases []struct {
		name      string
		content   string
		algorithm string
		expected  string
		wantErr   bool
	}

	testCases = append(testCases, getMD5TestCases()...)
	testCases = append(testCases, getSHA1TestCases()...)
	testCases = append(testCases, getSHA256TestCases()...)
	testCases = append(testCases, getSHA512TestCases()...)
	testCases = append(testCases, getHashErrorTestCases()...)

	return testCases
}

func executeHashTest(t *testing.T, service crypto.CryptoService, tt struct {
	name      string
	content   string
	algorithm string
	expected  string
	wantErr   bool
},
) {
	result, err := service.Hash(tt.content, tt.algorithm)

	if tt.wantErr {
		assert.Error(t, err)
		assert.Empty(t, result)
		return
	}

	require.NoError(t, err)
	assert.Equal(t, tt.expected, result)
}

func TestCryptoService_Hash_EdgeCases(t *testing.T) {
	service := crypto.NewCryptoService()

	t.Run("Binary data", func(t *testing.T) {
		// Test with binary data (null bytes)
		binaryData := testBinaryData
		result, err := service.Hash(binaryData, "sha256")
		require.NoError(t, err)
		assert.NotEmpty(t, result)
		assert.Len(t, result, 64) // SHA256 produces 64 hex characters
	})

	t.Run("Very long content", func(t *testing.T) {
		// Test with very long content
		longContent := make([]byte, 1024*1024) // 1MB
		for i := range longContent {
			longContent[i] = byte(i % 256)
		}

		result, err := service.Hash(string(longContent), "sha256")
		require.NoError(t, err)
		assert.NotEmpty(t, result)
		assert.Len(t, result, 64)
	})

	t.Run("All algorithms produce different results", func(t *testing.T) {
		content := "test content for different algorithms"
		algorithms := []string{"md5", "sha1", "sha256", "sha512"}
		results := make(map[string]string)

		for _, algo := range algorithms {
			result, err := service.Hash(content, algo)
			require.NoError(t, err)
			results[algo] = result
		}

		// Verify all results are different
		assert.Len(t, results, 4)
		assert.NotEqual(t, results["md5"], results["sha1"])
		assert.NotEqual(t, results["sha1"], results["sha256"])
		assert.NotEqual(t, results["sha256"], results["sha512"])
	})

	t.Run("Case sensitivity of algorithm parameter", func(t *testing.T) {
		content := testContent

		// Test that algorithm parameter is case sensitive
		_, err := service.Hash(content, "SHA256")
		assert.Error(t, err)

		_, err = service.Hash(content, "Sha256")
		assert.Error(t, err)

		// But lowercase works
		_, err = service.Hash(content, "sha256")
		assert.NoError(t, err)
	})
}

func TestCryptoService_Hash_Consistency(t *testing.T) {
	service := crypto.NewCryptoService()

	t.Run("Same input produces same output", func(t *testing.T) {
		content := testConsistencyData
		algorithm := testSHA256Algorithm

		result1, err1 := service.Hash(content, algorithm)
		result2, err2 := service.Hash(content, algorithm)

		require.NoError(t, err1)
		require.NoError(t, err2)
		assert.Equal(t, result1, result2)
	})

	t.Run("Different instances produce same output", func(t *testing.T) {
		service1 := crypto.NewCryptoService()
		service2 := crypto.NewCryptoService()

		content := "instance test"
		algorithm := testSHA256Algorithm

		result1, err1 := service1.Hash(content, algorithm)
		result2, err2 := service2.Hash(content, algorithm)

		require.NoError(t, err1)
		require.NoError(t, err2)
		assert.Equal(t, result1, result2)
	})
}

func getHMACSHA256TestCases() []struct {
	name      string
	content   string
	key       string
	algorithm string
	expected  string
	wantErr   bool
} {
	return []struct {
		name      string
		content   string
		key       string
		algorithm string
		expected  string
		wantErr   bool
	}{
		{
			name:      "HMAC-SHA256 test case 1",
			content:   "Hi There",
			key:       "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
			algorithm: "sha256",
			expected:  "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
			wantErr:   false,
		},
		{
			name:      "HMAC-SHA256 test case 2",
			content:   "what do ya want for nothing?",
			key:       "Jefe",
			algorithm: "sha256",
			expected:  "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
			wantErr:   false,
		},
		{
			name: "HMAC-SHA256 test case 3",
			content: "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd" +
				"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd" +
				"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd",
			key:       "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa",
			algorithm: "sha256",
			expected:  "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
			wantErr:   false,
		},
	}
}

func getHMACSHA512TestCases() []struct {
	name      string
	content   string
	key       string
	algorithm string
	expected  string
	wantErr   bool
} {
	return []struct {
		name      string
		content   string
		key       string
		algorithm string
		expected  string
		wantErr   bool
	}{
		{
			name:      "HMAC-SHA512 test case 1",
			content:   "Hi There",
			key:       "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
			algorithm: "sha512",
			expected: "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cded" +
				"aa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
			wantErr: false,
		},
		{
			name:      "HMAC-SHA512 test case 2",
			content:   "what do ya want for nothing?",
			key:       "Jefe",
			algorithm: "sha512",
			expected: "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549" +
				"758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
			wantErr: false,
		},
	}
}

func getHMACEdgeTestCases() []struct {
	name      string
	content   string
	key       string
	algorithm string
	expected  string
	wantErr   bool
} {
	return []struct {
		name      string
		content   string
		key       string
		algorithm string
		expected  string
		wantErr   bool
	}{
		{
			name:      "Empty content",
			content:   "",
			key:       "key",
			algorithm: "sha256",
			expected:  "5d5d139563c95b5967b9bd9a8c9b233a9dedb45072794cd232dc1b74832607d0",
			wantErr:   false,
		},
		{
			name:      "Empty key",
			content:   "content",
			key:       "",
			algorithm: "sha256",
			expected:  "2cc732a9b86e2ff403e8c0e07ee82e69dcb1820e424d465efe69c63eacb0ee95",
			wantErr:   false,
		},
		{
			name:      "Long key (longer than block size)",
			content:   "Test Using Larger Than Block-Size Key - Hash Key First",
			key:       "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", //nolint:lll
			algorithm: "sha256",
			expected:  "a98622a65f519a3e56acc5020d18ae0f2ded1db0af0e791a25dd3d7090e90df8",
			wantErr:   false,
		},
	}
}

func getHMACErrorTestCases() []struct {
	name      string
	content   string
	key       string
	algorithm string
	expected  string
	wantErr   bool
} {
	return []struct {
		name      string
		content   string
		key       string
		algorithm string
		expected  string
		wantErr   bool
	}{
		{
			name:      "Unsupported algorithm",
			content:   "test",
			key:       "key",
			algorithm: "md5",
			expected:  "",
			wantErr:   true,
		},
		{
			name:      "Empty algorithm",
			content:   "test",
			key:       "key",
			algorithm: "",
			expected:  "",
			wantErr:   true,
		},
	}
}

func executeHMACTest(t *testing.T, service crypto.CryptoService, tt struct {
	name      string
	content   string
	key       string
	algorithm string
	expected  string
	wantErr   bool
},
) {
	result, err := service.HMAC(tt.content, tt.key, tt.algorithm)

	if tt.wantErr {
		assert.Error(t, err)
		assert.Empty(t, result)
		return
	}

	require.NoError(t, err)
	assert.Equal(t, tt.expected, result)
}

func TestCryptoService_HMAC(t *testing.T) {
	service := crypto.NewCryptoService()

	var tests []struct {
		name      string
		content   string
		key       string
		algorithm string
		expected  string
		wantErr   bool
	}

	tests = append(tests, getHMACSHA256TestCases()...)
	tests = append(tests, getHMACSHA512TestCases()...)
	tests = append(tests, getHMACEdgeTestCases()...)
	tests = append(tests, getHMACErrorTestCases()...)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executeHMACTest(t, service, tt)
		})
	}
}

func TestCryptoService_HMAC_EdgeCases(t *testing.T) {
	service := crypto.NewCryptoService()

	t.Run("Binary data in content", func(t *testing.T) {
		binaryContent := "\x00\x01\x02\x03\xff\xfe\xfd"
		key := "testkey"

		result, err := service.HMAC(binaryContent, key, "sha256")
		require.NoError(t, err)
		assert.NotEmpty(t, result)
		assert.Len(t, result, 64) // SHA256 HMAC produces 64 hex characters
	})

	t.Run("Binary data in key", func(t *testing.T) {
		content := "test content"
		binaryKey := "\x00\x01\x02\x03\xff\xfe\xfd"

		result, err := service.HMAC(content, binaryKey, "sha256")
		require.NoError(t, err)
		assert.NotEmpty(t, result)
		assert.Len(t, result, 64)
	})

	t.Run("Very long content", func(t *testing.T) {
		longContent := make([]byte, 1024*1024) // 1MB
		for i := range longContent {
			longContent[i] = byte(i % 256)
		}

		result, err := service.HMAC(string(longContent), "key", "sha256")
		require.NoError(t, err)
		assert.NotEmpty(t, result)
		assert.Len(t, result, 64)
	})

	t.Run("Unicode in content and key", func(t *testing.T) {
		unicodeContent := "Hello, 世界! 🌍"
		unicodeKey := "密钥🔑"

		result, err := service.HMAC(unicodeContent, unicodeKey, "sha256")
		require.NoError(t, err)
		assert.NotEmpty(t, result)
		assert.Len(t, result, 64)
	})

	t.Run("Case sensitivity of algorithm parameter", func(t *testing.T) {
		content := "test"
		key := "key"

		// Test that algorithm parameter is case sensitive
		_, err := service.HMAC(content, key, "SHA256")
		assert.Error(t, err)

		_, err = service.HMAC(content, key, "Sha256")
		assert.Error(t, err)

		// But lowercase works
		_, err = service.HMAC(content, key, "sha256")
		assert.NoError(t, err)
	})
}

func TestCryptoService_HMAC_Consistency(t *testing.T) {
	service := crypto.NewCryptoService()

	t.Run("Same input produces same output", func(t *testing.T) {
		content := "consistency test"
		key := "testkey"
		algorithm := "sha256"

		result1, err1 := service.HMAC(content, key, algorithm)
		result2, err2 := service.HMAC(content, key, algorithm)

		require.NoError(t, err1)
		require.NoError(t, err2)
		assert.Equal(t, result1, result2)
	})

	t.Run("Different keys produce different results", func(t *testing.T) {
		content := "test content"
		key1 := "key1"
		key2 := "key2"
		algorithm := "sha256"

		result1, err1 := service.HMAC(content, key1, algorithm)
		result2, err2 := service.HMAC(content, key2, algorithm)

		require.NoError(t, err1)
		require.NoError(t, err2)
		assert.NotEqual(t, result1, result2)
	})

	t.Run("Different algorithms produce different results", func(t *testing.T) {
		content := testHMACContent
		key := testHMACKey

		result256, err256 := service.HMAC(content, key, "sha256")
		result512, err512 := service.HMAC(content, key, "sha512")

		require.NoError(t, err256)
		require.NoError(t, err512)
		assert.NotEqual(t, result256, result512)
		assert.Len(t, result256, 64)  // SHA256 produces 64 hex chars
		assert.Len(t, result512, 128) // SHA512 produces 128 hex chars
	})
}

// Benchmark tests for performance.
func BenchmarkCryptoService_Hash(b *testing.B) {
	service := crypto.NewCryptoService()
	content := "benchmark test content that is reasonably long to get meaningful measurements"

	algorithms := []string{"md5", "sha1", "sha256", "sha512"}

	for _, algo := range algorithms {
		b.Run(algo, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := service.Hash(content, algo)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkCryptoService_Hash_LargeContent(b *testing.B) {
	service := crypto.NewCryptoService()
	content := string(make([]byte, 1024*1024)) // 1MB

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := service.Hash(content, "sha256")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCryptoService_HMAC(b *testing.B) {
	service := crypto.NewCryptoService()
	content := "benchmark test content that is reasonably long to get meaningful measurements"
	key := "benchmark-secret-key"

	algorithms := []string{"sha256", "sha512"}

	for _, algo := range algorithms {
		b.Run(algo, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := service.HMAC(content, key, algo)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkCryptoService_HMAC_LargeContent(b *testing.B) {
	service := crypto.NewCryptoService()
	content := string(make([]byte, 1024*1024)) // 1MB
	key := "benchmark-key"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := service.HMAC(content, key, "sha256")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func TestCryptoService_HashPassword(t *testing.T) {
	service := crypto.NewCryptoService()
	tests := getHashPasswordTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := service.HashPassword(tt.password)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Empty(t, hash)
				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, hash)
			verifyHashFormat(t, hash)
		})
	}
}

func getHashPasswordTestCases() []struct {
	name     string
	password string
	wantErr  bool
} {
	return []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "Simple password",
			password: "password123",
			wantErr:  false,
		},
		{
			name:     "Empty password",
			password: "",
			wantErr:  false,
		},
		{
			name:     "Long password",
			password: strings.Repeat("a", 1000),
			wantErr:  false,
		},
		{
			name:     "Unicode password",
			password: "пароль123🔒",
			wantErr:  false,
		},
		{
			name:     "Password with special characters",
			password: "p@ssw0rd!#$%^&*()",
			wantErr:  false,
		},
		{
			name:     "Binary data in password",
			password: "password\x00\x01\x02\xff",
			wantErr:  false,
		},
	}
}

func verifyHashFormat(t *testing.T, hash string) {
	// Verify the hash format
	assert.True(t, strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=3,p=4$"))

	// Verify the hash has the correct number of parts
	parts := strings.Split(hash, "$")
	assert.Len(t, parts, 6)

	// Verify salt and hash are base64 encoded
	_, err := base64.RawStdEncoding.DecodeString(parts[4]) // salt
	assert.NoError(t, err)
	_, err = base64.RawStdEncoding.DecodeString(parts[5]) // hash
	assert.NoError(t, err)
}

func TestCryptoService_VerifyPassword(t *testing.T) {
	service := crypto.NewCryptoService()

	// Test with known good password/hash pairs
	testCases := []struct {
		name     string
		password string
	}{
		{"simple password", "password123"},
		{"empty password", ""},
		{"unicode password", "пароль123🔒"},
		{"special characters", "p@ssw0rd!#$%^&*()"},
		{"long password", strings.Repeat("a", 500)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Hash the password
			hash, err := service.HashPassword(tc.password)
			require.NoError(t, err)

			// Verify correct password
			assert.True(t, service.VerifyPassword(tc.password, hash))

			// Verify incorrect password
			assert.False(t, service.VerifyPassword(tc.password+"wrong", hash))
			assert.False(t, service.VerifyPassword("wrong"+tc.password, hash))

			if tc.password != "" {
				assert.False(t, service.VerifyPassword("", hash))
			}
		})
	}
}

func TestCryptoService_VerifyPassword_EdgeCases(t *testing.T) {
	service := crypto.NewCryptoService()

	t.Run("Invalid hash formats", func(t *testing.T) {
		password := "test"

		invalidHashes := []string{
			"",
			"invalid",
			"$argon2id$",
			"$argon2id$v=19$",
			"$argon2id$v=19$m=65536$",
			"$argon2id$v=19$m=65536,t=3,p=4$",
			"$argon2id$v=19$m=65536,t=3,p=4$salt$", // missing hash
			"$bcrypt$2a$10$salt$hash",              // wrong algorithm
			"$argon2id$v=18$m=65536,t=3,p=4$salt$hash",           // wrong version
			"$argon2id$v=19$m=invalid,t=3,p=4$salt$hash",         // invalid params
			"$argon2id$v=19$m=65536,t=3,p=4$invalid_base64$hash", // invalid salt
			"$argon2id$v=19$m=65536,t=3,p=4$salt$invalid_base64", // invalid hash
		}

		for _, invalidHash := range invalidHashes {
			assert.False(t, service.VerifyPassword(password, invalidHash),
				"Should reject invalid hash: %s", invalidHash)
		}
	})

	t.Run("Different parameters should not verify", func(t *testing.T) {
		password := "testpassword"

		// Create a hash with different parameters (this would be from a different system)
		differentHash := "$argon2id$v=19$m=32768,t=2,p=2$c2FsdA$aGFzaA"
		assert.False(t, service.VerifyPassword(password, differentHash))
	})
}

func TestCryptoService_Password_Consistency(t *testing.T) {
	service := crypto.NewCryptoService()

	t.Run("Same password produces different hashes", func(t *testing.T) {
		password := "consistency test"

		hash1, err1 := service.HashPassword(password)
		hash2, err2 := service.HashPassword(password)

		require.NoError(t, err1)
		require.NoError(t, err2)

		// Hashes should be different due to random salt
		assert.NotEqual(t, hash1, hash2)

		// But both should verify correctly
		assert.True(t, service.VerifyPassword(password, hash1))
		assert.True(t, service.VerifyPassword(password, hash2))
	})

	t.Run("Different instances produce verifiable hashes", func(t *testing.T) {
		service1 := crypto.NewCryptoService()
		service2 := crypto.NewCryptoService()

		password := "instance test"

		hash, err := service1.HashPassword(password)
		require.NoError(t, err)

		// Different instance should be able to verify
		assert.True(t, service2.VerifyPassword(password, hash))
	})
}

func TestCryptoService_Password_TimingAttackResistance(t *testing.T) {
	service := crypto.NewCryptoService()

	password := "testpassword"
	hash, err := service.HashPassword(password)
	require.NoError(t, err)

	// Test that verification time is consistent regardless of input
	// This is a basic test - in practice, more sophisticated timing analysis would be needed
	t.Run("Consistent timing for different inputs", func(t *testing.T) {
		iterations := 10

		// Measure time for correct password
		correctTimes := make([]time.Duration, iterations)
		for i := 0; i < iterations; i++ {
			start := time.Now()
			service.VerifyPassword(password, hash)
			correctTimes[i] = time.Since(start)
		}

		// Measure time for incorrect password
		incorrectTimes := make([]time.Duration, iterations)
		for i := 0; i < iterations; i++ {
			start := time.Now()
			service.VerifyPassword("wrongpassword", hash)
			incorrectTimes[i] = time.Since(start)
		}

		// Calculate average times
		var correctTotal, incorrectTotal time.Duration
		for i := 0; i < iterations; i++ {
			correctTotal += correctTimes[i]
			incorrectTotal += incorrectTimes[i]
		}

		correctAvg := correctTotal / time.Duration(iterations)
		incorrectAvg := incorrectTotal / time.Duration(iterations)

		// Times should be similar (within reasonable variance)
		// Allow up to 50% difference to account for system variance
		ratio := float64(correctAvg) / float64(incorrectAvg)
		assert.True(t, ratio > 0.5 && ratio < 2.0,
			"Timing difference too large: correct=%v, incorrect=%v, ratio=%f",
			correctAvg, incorrectAvg, ratio)
	})
}

func BenchmarkCryptoService_HashPassword(b *testing.B) {
	service := crypto.NewCryptoService()
	password := "benchmark password"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := service.HashPassword(password)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCryptoService_VerifyPassword(b *testing.B) {
	service := crypto.NewCryptoService()
	password := "benchmark password"

	hash, err := service.HashPassword(password)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !service.VerifyPassword(password, hash) {
			b.Fatal("verification failed")
		}
	}
}

func testCertificateWithDNSNames(t *testing.T, service crypto.CryptoService) {
	testCert := testCertificate

	result, err := service.DecodeCertificate(testCert)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Check that DNSNames field exists (may be empty for this test cert)
	assert.NotNil(t, result.DNSNames)
}

func testMultiplePEMBlocks(t *testing.T, service crypto.CryptoService) {
	multiplePEM := `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
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

	// Should decode the first certificate only
	result, err := service.DecodeCertificate(multiplePEM)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func testCertificateWithWhitespace(t *testing.T, service crypto.CryptoService) {
	certWithWhitespace := `
		
-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
		
		`

	result, err := service.DecodeCertificate(certWithWhitespace)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestCryptoService_DecodeCertificate_EdgeCases(t *testing.T) {
	service := crypto.NewCryptoService()

	t.Run("Certificate with DNS names", func(t *testing.T) {
		testCertificateWithDNSNames(t, service)
	})

	t.Run("Multiple PEM blocks", func(t *testing.T) {
		testMultiplePEMBlocks(t, service)
	})

	t.Run("Certificate with whitespace", func(t *testing.T) {
		testCertificateWithWhitespace(t, service)
	})
}

func TestExtractKeyUsage(t *testing.T) {
	// This is tested indirectly through DecodeCertificate, but we can add specific tests
	// if we need to test the key usage extraction logic more thoroughly
	service := crypto.NewCryptoService()

	// Use a valid, complete certificate for testing
	result, err := service.DecodeCertificate(testCertificate)
	require.NoError(t, err)
	require.NotNil(t, result)

	// KeyUsage should be a slice (may be empty for this test cert)
	// The function should always return a non-nil slice
	assert.NotNil(t, result.KeyUsage)

	// Verify it's actually a slice
	assert.IsType(t, []string{}, result.KeyUsage)

	// Verify we can get the length (this would panic if nil)
	assert.GreaterOrEqual(t, len(result.KeyUsage), 0)
}

func BenchmarkCryptoService_DecodeCertificate(b *testing.B) {
	service := crypto.NewCryptoService()
	testCert := `-----BEGIN CERTIFICATE-----
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

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := service.DecodeCertificate(testCert)
		if err != nil {
			b.Fatal(err)
		}
	}
}
