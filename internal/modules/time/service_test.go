package time

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestService_ConvertTime(t *testing.T) {
	service := NewService()

	// Test time: 2023-12-25 15:30:45 UTC (Unix: 1703518245)
	testUnixSeconds := "1703518245"
	testUnixMilliseconds := "1703518245000"
	testISO8601 := "2023-12-25T15:30:45Z"
	testRFC3339 := "2023-12-25T15:30:45Z"
	testHuman := "2023-12-25 15:30:45 UTC"

	tests := []struct {
		name         string
		input        string
		inputFormat  string
		outputFormat string
		expected     string
		expectError  bool
		errorMsg     string
	}{
		// Unix seconds conversions
		{
			name:         "Unix to ISO8601",
			input:        testUnixSeconds,
			inputFormat:  FormatUnixSeconds,
			outputFormat: FormatISO8601,
			expected:     testISO8601,
		},
		{
			name:         "Unix to RFC3339",
			input:        testUnixSeconds,
			inputFormat:  FormatUnixSeconds,
			outputFormat: FormatRFC3339,
			expected:     testRFC3339,
		},
		{
			name:         "Unix to Human",
			input:        testUnixSeconds,
			inputFormat:  FormatUnixSeconds,
			outputFormat: FormatHumanReadable,
			expected:     testHuman,
		},
		{
			name:         "Unix to Unix milliseconds",
			input:        testUnixSeconds,
			inputFormat:  FormatUnixSeconds,
			outputFormat: FormatUnixMilliseconds,
			expected:     testUnixMilliseconds,
		},

		// Unix milliseconds conversions
		{
			name:         "Unix milliseconds to Unix seconds",
			input:        testUnixMilliseconds,
			inputFormat:  FormatUnixMilliseconds,
			outputFormat: FormatUnixSeconds,
			expected:     testUnixSeconds,
		},
		{
			name:         "Unix milliseconds to ISO8601",
			input:        testUnixMilliseconds,
			inputFormat:  FormatUnixMilliseconds,
			outputFormat: FormatISO8601,
			expected:     testISO8601,
		},

		// ISO8601 conversions
		{
			name:         "ISO8601 to Unix",
			input:        testISO8601,
			inputFormat:  FormatISO8601,
			outputFormat: FormatUnixSeconds,
			expected:     testUnixSeconds,
		},
		{
			name:         "ISO8601 to RFC3339",
			input:        testISO8601,
			inputFormat:  FormatISO8601,
			outputFormat: FormatRFC3339,
			expected:     testRFC3339,
		},
		{
			name:         "ISO8601 to Human",
			input:        testISO8601,
			inputFormat:  FormatISO8601,
			outputFormat: FormatHumanReadable,
			expected:     testHuman,
		},

		// RFC3339 conversions
		{
			name:         "RFC3339 to Unix",
			input:        testRFC3339,
			inputFormat:  FormatRFC3339,
			outputFormat: FormatUnixSeconds,
			expected:     testUnixSeconds,
		},
		{
			name:         "RFC3339 to ISO8601",
			input:        testRFC3339,
			inputFormat:  FormatRFC3339,
			outputFormat: FormatISO8601,
			expected:     testISO8601,
		},

		// Human readable conversions
		{
			name:         "Human to Unix",
			input:        testHuman,
			inputFormat:  FormatHumanReadable,
			outputFormat: FormatUnixSeconds,
			expected:     testUnixSeconds,
		},
		{
			name:         "Human to ISO8601",
			input:        testHuman,
			inputFormat:  FormatHumanReadable,
			outputFormat: FormatISO8601,
			expected:     testISO8601,
		},

		// Same format conversions (should work)
		{
			name:         "Unix to Unix (same)",
			input:        testUnixSeconds,
			inputFormat:  FormatUnixSeconds,
			outputFormat: FormatUnixSeconds,
			expected:     testUnixSeconds,
		},

		// Error cases
		{
			name:         "Invalid Unix timestamp",
			input:        "invalid",
			inputFormat:  FormatUnixSeconds,
			outputFormat: FormatISO8601,
			expectError:  true,
			errorMsg:     "invalid unix timestamp",
		},
		{
			name:         "Invalid Unix milliseconds",
			input:        "invalid",
			inputFormat:  FormatUnixMilliseconds,
			outputFormat: FormatISO8601,
			expectError:  true,
			errorMsg:     "invalid unix milliseconds timestamp",
		},
		{
			name:         "Invalid ISO8601",
			input:        "2023-13-45T25:70:90Z",
			inputFormat:  FormatISO8601,
			outputFormat: FormatUnixSeconds,
			expectError:  true,
			errorMsg:     "invalid ISO8601 format",
		},
		{
			name:         "Invalid RFC3339",
			input:        "invalid-rfc3339",
			inputFormat:  FormatRFC3339,
			outputFormat: FormatUnixSeconds,
			expectError:  true,
			errorMsg:     "invalid RFC3339 format",
		},
		{
			name:         "Invalid human format",
			input:        "not a date",
			inputFormat:  FormatHumanReadable,
			outputFormat: FormatUnixSeconds,
			expectError:  true,
			errorMsg:     "invalid human-readable format",
		},
		{
			name:         "Unsupported input format",
			input:        testUnixSeconds,
			inputFormat:  "unsupported",
			outputFormat: FormatISO8601,
			expectError:  true,
			errorMsg:     "unsupported input format",
		},
		{
			name:         "Unsupported output format",
			input:        testUnixSeconds,
			inputFormat:  FormatUnixSeconds,
			outputFormat: "unsupported",
			expectError:  true,
			errorMsg:     "unsupported output format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := service.ConvertTime(tt.input, tt.inputFormat, tt.outputFormat)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Empty(t, result)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestService_ConvertTime_VariousISO8601Formats(t *testing.T) {
	service := NewService()

	// Test various ISO8601 input formats
	iso8601Variants := []string{
		"2023-12-25T15:30:45Z",
		"2023-12-25T15:30:45.000Z",
		"2023-12-25T15:30:45.000000Z",
		"2023-12-25T15:30:45",
	}

	expectedUnix := "1703518245"

	for _, variant := range iso8601Variants {
		t.Run("ISO8601_variant_"+variant, func(t *testing.T) {
			result, err := service.ConvertTime(variant, FormatISO8601, FormatUnixSeconds)
			require.NoError(t, err)
			assert.Equal(t, expectedUnix, result)
		})
	}
}

func TestService_ConvertTime_VariousHumanFormats(t *testing.T) {
	service := NewService()

	// Test various human-readable input formats
	humanVariants := []struct {
		input    string
		expected string
	}{
		{"2023-12-25 15:30:45 UTC", "1703518245"},
		{"2023-12-25 15:30:45", "1703518245"},
		{"2023-12-25T15:30:45", "1703518245"},
	}

	for _, variant := range humanVariants {
		t.Run("Human_variant_"+variant.input, func(t *testing.T) {
			result, err := service.ConvertTime(variant.input, FormatHumanReadable, FormatUnixSeconds)
			require.NoError(t, err)
			assert.Equal(t, variant.expected, result)
		})
	}
}

func TestService_GetCurrentTime(t *testing.T) {
	service := NewService()

	// Record time before the call
	beforeCall := time.Now().UTC()
	
	result, err := service.GetCurrentTime()
	require.NoError(t, err)
	require.NotNil(t, result)

	// Record time after the call
	afterCall := time.Now().UTC()

	// Verify that all fields are populated
	assert.NotZero(t, result.UnixSeconds)
	assert.NotZero(t, result.UnixMilliseconds)
	assert.NotEmpty(t, result.ISO8601)
	assert.NotEmpty(t, result.RFC3339)
	assert.NotEmpty(t, result.HumanReadable)

	// Verify that the time is within a reasonable range (within 1 second of when we called it)
	assert.True(t, result.UnixSeconds >= beforeCall.Unix()-1)
	assert.True(t, result.UnixSeconds <= afterCall.Unix()+1)

	// Verify that milliseconds are consistent with seconds
	expectedMilliseconds := result.UnixSeconds * 1000
	assert.True(t, result.UnixMilliseconds >= expectedMilliseconds)
	assert.True(t, result.UnixMilliseconds < expectedMilliseconds+1000)

	// Verify format consistency by parsing the formatted strings
	parsedISO, err := time.Parse(ISO8601Layout, result.ISO8601)
	require.NoError(t, err)
	assert.Equal(t, result.UnixSeconds, parsedISO.Unix())

	parsedRFC, err := time.Parse(RFC3339Layout, result.RFC3339)
	require.NoError(t, err)
	assert.Equal(t, result.UnixSeconds, parsedRFC.Unix())

	parsedHuman, err := time.Parse(HumanLayout, result.HumanReadable)
	require.NoError(t, err)
	assert.Equal(t, result.UnixSeconds, parsedHuman.Unix())

	// Verify that all times are in UTC
	assert.Contains(t, result.ISO8601, "Z")
	assert.Contains(t, result.RFC3339, "Z")
	assert.Contains(t, result.HumanReadable, "UTC")
}

func TestService_EdgeCases(t *testing.T) {
	service := NewService()

	tests := []struct {
		name        string
		input       string
		inputFormat string
		expectError bool
	}{
		{
			name:        "Empty input",
			input:       "",
			inputFormat: FormatUnixSeconds,
			expectError: true,
		},
		{
			name:        "Whitespace input",
			input:       "   ",
			inputFormat: FormatUnixSeconds,
			expectError: true,
		},
		{
			name:        "Negative Unix timestamp",
			input:       "-1",
			inputFormat: FormatUnixSeconds,
			expectError: false, // Should work (before epoch)
		},
		{
			name:        "Very large Unix timestamp",
			input:       "9999999999",
			inputFormat: FormatUnixSeconds,
			expectError: false, // Should work (far future)
		},
		{
			name:        "Zero Unix timestamp",
			input:       "0",
			inputFormat: FormatUnixSeconds,
			expectError: false, // Should work (epoch)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := service.ConvertTime(tt.input, tt.inputFormat, FormatISO8601)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetSupportedFormats(t *testing.T) {
	formats := GetSupportedFormats()
	
	expectedFormats := []string{
		FormatUnixSeconds,
		FormatUnixMilliseconds,
		FormatISO8601,
		FormatRFC3339,
		FormatHumanReadable,
	}
	
	assert.ElementsMatch(t, expectedFormats, formats)
	assert.Len(t, formats, 5)
}

func TestConstants(t *testing.T) {
	// Test that constants have expected values
	assert.Equal(t, "unix", FormatUnixSeconds)
	assert.Equal(t, "unix_ms", FormatUnixMilliseconds)
	assert.Equal(t, "iso8601", FormatISO8601)
	assert.Equal(t, "rfc3339", FormatRFC3339)
	assert.Equal(t, "human", FormatHumanReadable)
	
	assert.Equal(t, "2006-01-02T15:04:05Z", ISO8601Layout)
	assert.Equal(t, time.RFC3339, RFC3339Layout)
	assert.Equal(t, "2006-01-02 15:04:05 UTC", HumanLayout)
}

func BenchmarkConvertTime(b *testing.B) {
	service := NewService()
	
	b.Run("Unix to ISO8601", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := service.ConvertTime("1703518245", FormatUnixSeconds, FormatISO8601)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	
	b.Run("ISO8601 to Unix", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := service.ConvertTime("2023-12-25T15:30:45Z", FormatISO8601, FormatUnixSeconds)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkGetCurrentTime(b *testing.B) {
	service := NewService()
	
	for i := 0; i < b.N; i++ {
		_, err := service.GetCurrentTime()
		if err != nil {
			b.Fatal(err)
		}
	}
}