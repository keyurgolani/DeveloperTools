package time_test

import (
	"testing"
	stdtime "time"

	"github.com/keyurgolani/DeveloperTools/internal/modules/time"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestService_ConvertTime(t *testing.T) {
	service := time.NewService()
	testData := getTestTimeData()

	tests := []struct {
		name         string
		input        string
		inputFormat  string
		outputFormat string
		expected     string
		expectError  bool
		errorMsg     string
	}{}

	// Add all test cases
	tests = append(tests, getUnixConversionTests(testData)...)
	tests = append(tests, getISO8601ConversionTests(testData)...)
	tests = append(tests, getRFC3339ConversionTests(testData)...)
	tests = append(tests, getHumanConversionTests(testData)...)
	tests = append(tests, getSameFormatConversionTests(testData)...)
	tests = append(tests, getErrorCaseTests(testData)...)

	runConversionTests(t, service, tests)
}

type testTimeData struct {
	unixSeconds      string
	unixMilliseconds string
	iso8601          string
	rfc3339          string
	human            string
}

func getTestTimeData() testTimeData {
	return testTimeData{
		unixSeconds:      "1703518245",
		unixMilliseconds: "1703518245000",
		iso8601:          "2023-12-25T15:30:45Z",
		rfc3339:          "2023-12-25T15:30:45Z",
		human:            "2023-12-25 15:30:45 UTC",
	}
}

func getUnixConversionTests(data testTimeData) []struct {
	name         string
	input        string
	inputFormat  string
	outputFormat string
	expected     string
	expectError  bool
	errorMsg     string
} {
	return []struct {
		name         string
		input        string
		inputFormat  string
		outputFormat string
		expected     string
		expectError  bool
		errorMsg     string
	}{
		{
			name:         "Unix to ISO8601",
			input:        data.unixSeconds,
			inputFormat:  time.FormatUnixSeconds,
			outputFormat: time.FormatISO8601,
			expected:     data.iso8601,
		},
		{
			name:         "Unix to RFC3339",
			input:        data.unixSeconds,
			inputFormat:  time.FormatUnixSeconds,
			outputFormat: time.FormatRFC3339,
			expected:     data.rfc3339,
		},
		{
			name:         "Unix to Human",
			input:        data.unixSeconds,
			inputFormat:  time.FormatUnixSeconds,
			outputFormat: time.FormatHumanReadable,
			expected:     data.human,
		},
		{
			name:         "Unix to Unix milliseconds",
			input:        data.unixSeconds,
			inputFormat:  time.FormatUnixSeconds,
			outputFormat: time.FormatUnixMilliseconds,
			expected:     data.unixMilliseconds,
		},
		{
			name:         "Unix milliseconds to Unix seconds",
			input:        data.unixMilliseconds,
			inputFormat:  time.FormatUnixMilliseconds,
			outputFormat: time.FormatUnixSeconds,
			expected:     data.unixSeconds,
		},
		{
			name:         "Unix milliseconds to ISO8601",
			input:        data.unixMilliseconds,
			inputFormat:  time.FormatUnixMilliseconds,
			outputFormat: time.FormatISO8601,
			expected:     data.iso8601,
		},
	}
}

func getISO8601ConversionTests(data testTimeData) []struct {
	name         string
	input        string
	inputFormat  string
	outputFormat string
	expected     string
	expectError  bool
	errorMsg     string
} {
	return []struct {
		name         string
		input        string
		inputFormat  string
		outputFormat string
		expected     string
		expectError  bool
		errorMsg     string
	}{
		{
			name:         "ISO8601 to Unix",
			input:        data.iso8601,
			inputFormat:  time.FormatISO8601,
			outputFormat: time.FormatUnixSeconds,
			expected:     data.unixSeconds,
		},
		{
			name:         "ISO8601 to RFC3339",
			input:        data.iso8601,
			inputFormat:  time.FormatISO8601,
			outputFormat: time.FormatRFC3339,
			expected:     data.rfc3339,
		},
		{
			name:         "ISO8601 to Human",
			input:        data.iso8601,
			inputFormat:  time.FormatISO8601,
			outputFormat: time.FormatHumanReadable,
			expected:     data.human,
		},
	}
}

func getRFC3339ConversionTests(data testTimeData) []struct {
	name         string
	input        string
	inputFormat  string
	outputFormat string
	expected     string
	expectError  bool
	errorMsg     string
} {
	return []struct {
		name         string
		input        string
		inputFormat  string
		outputFormat string
		expected     string
		expectError  bool
		errorMsg     string
	}{
		{
			name:         "RFC3339 to Unix",
			input:        data.rfc3339,
			inputFormat:  time.FormatRFC3339,
			outputFormat: time.FormatUnixSeconds,
			expected:     data.unixSeconds,
		},
		{
			name:         "RFC3339 to ISO8601",
			input:        data.rfc3339,
			inputFormat:  time.FormatRFC3339,
			outputFormat: time.FormatISO8601,
			expected:     data.iso8601,
		},
	}
}

func getHumanConversionTests(data testTimeData) []struct {
	name         string
	input        string
	inputFormat  string
	outputFormat string
	expected     string
	expectError  bool
	errorMsg     string
} {
	return []struct {
		name         string
		input        string
		inputFormat  string
		outputFormat string
		expected     string
		expectError  bool
		errorMsg     string
	}{
		{
			name:         "Human to Unix",
			input:        data.human,
			inputFormat:  time.FormatHumanReadable,
			outputFormat: time.FormatUnixSeconds,
			expected:     data.unixSeconds,
		},
		{
			name:         "Human to ISO8601",
			input:        data.human,
			inputFormat:  time.FormatHumanReadable,
			outputFormat: time.FormatISO8601,
			expected:     data.iso8601,
		},
	}
}

func getSameFormatConversionTests(data testTimeData) []struct {
	name         string
	input        string
	inputFormat  string
	outputFormat string
	expected     string
	expectError  bool
	errorMsg     string
} {
	return []struct {
		name         string
		input        string
		inputFormat  string
		outputFormat string
		expected     string
		expectError  bool
		errorMsg     string
	}{
		{
			name:         "Unix to Unix (same)",
			input:        data.unixSeconds,
			inputFormat:  time.FormatUnixSeconds,
			outputFormat: time.FormatUnixSeconds,
			expected:     data.unixSeconds,
		},
	}
}

func getErrorCaseTests(data testTimeData) []struct {
	name         string
	input        string
	inputFormat  string
	outputFormat string
	expected     string
	expectError  bool
	errorMsg     string
} {
	var tests []struct {
		name         string
		input        string
		inputFormat  string
		outputFormat string
		expected     string
		expectError  bool
		errorMsg     string
	}

	tests = append(tests, getInvalidInputTests()...)
	tests = append(tests, getUnsupportedFormatTests(data)...)

	return tests
}

func getInvalidInputTests() []struct {
	name         string
	input        string
	inputFormat  string
	outputFormat string
	expected     string
	expectError  bool
	errorMsg     string
} {
	return []struct {
		name         string
		input        string
		inputFormat  string
		outputFormat string
		expected     string
		expectError  bool
		errorMsg     string
	}{
		{
			name:         "Invalid Unix timestamp",
			input:        "invalid",
			inputFormat:  time.FormatUnixSeconds,
			outputFormat: time.FormatISO8601,
			expectError:  true,
			errorMsg:     "invalid unix timestamp",
		},
		{
			name:         "Invalid Unix milliseconds",
			input:        "invalid",
			inputFormat:  time.FormatUnixMilliseconds,
			outputFormat: time.FormatISO8601,
			expectError:  true,
			errorMsg:     "invalid unix milliseconds timestamp",
		},
		{
			name:         "Invalid ISO8601",
			input:        "2023-13-45T25:70:90Z",
			inputFormat:  time.FormatISO8601,
			outputFormat: time.FormatUnixSeconds,
			expectError:  true,
			errorMsg:     "invalid ISO8601 format",
		},
		{
			name:         "Invalid RFC3339",
			input:        "invalid-rfc3339",
			inputFormat:  time.FormatRFC3339,
			outputFormat: time.FormatUnixSeconds,
			expectError:  true,
			errorMsg:     "invalid RFC3339 format",
		},
		{
			name:         "Invalid human format",
			input:        "not a date",
			inputFormat:  time.FormatHumanReadable,
			outputFormat: time.FormatUnixSeconds,
			expectError:  true,
			errorMsg:     "invalid human-readable format",
		},
	}
}

func getUnsupportedFormatTests(data testTimeData) []struct {
	name         string
	input        string
	inputFormat  string
	outputFormat string
	expected     string
	expectError  bool
	errorMsg     string
} {
	return []struct {
		name         string
		input        string
		inputFormat  string
		outputFormat string
		expected     string
		expectError  bool
		errorMsg     string
	}{
		{
			name:         "Unsupported input format",
			input:        data.unixSeconds,
			inputFormat:  "unsupported",
			outputFormat: time.FormatISO8601,
			expectError:  true,
			errorMsg:     "unsupported input format",
		},
		{
			name:         "Unsupported output format",
			input:        data.unixSeconds,
			inputFormat:  time.FormatUnixSeconds,
			outputFormat: "unsupported",
			expectError:  true,
			errorMsg:     "unsupported output format",
		},
	}
}

func runConversionTests(t *testing.T, service time.TimeService, tests []struct {
	name         string
	input        string
	inputFormat  string
	outputFormat string
	expected     string
	expectError  bool
	errorMsg     string
},
) {
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
	service := time.NewService()

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
			result, err := service.ConvertTime(variant, time.FormatISO8601, time.FormatUnixSeconds)
			require.NoError(t, err)
			assert.Equal(t, expectedUnix, result)
		})
	}
}

func TestService_ConvertTime_VariousHumanFormats(t *testing.T) {
	service := time.NewService()

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
			result, err := service.ConvertTime(variant.input, time.FormatHumanReadable, time.FormatUnixSeconds)
			require.NoError(t, err)
			assert.Equal(t, variant.expected, result)
		})
	}
}

func TestService_GetCurrentTime(t *testing.T) {
	service := time.NewService()

	// Record time before the call
	beforeCall := stdtime.Now().UTC()

	result, err := service.GetCurrentTime()
	require.NoError(t, err)
	require.NotNil(t, result)

	// Record time after the call
	afterCall := stdtime.Now().UTC()

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
	parsedISO, err := stdtime.Parse(time.ISO8601Layout, result.ISO8601)
	require.NoError(t, err)
	assert.Equal(t, result.UnixSeconds, parsedISO.Unix())

	parsedRFC, err := stdtime.Parse(time.RFC3339Layout, result.RFC3339)
	require.NoError(t, err)
	assert.Equal(t, result.UnixSeconds, parsedRFC.Unix())

	parsedHuman, err := stdtime.Parse(time.HumanLayout, result.HumanReadable)
	require.NoError(t, err)
	assert.Equal(t, result.UnixSeconds, parsedHuman.Unix())

	// Verify that all times are in UTC
	assert.Contains(t, result.ISO8601, "Z")
	assert.Contains(t, result.RFC3339, "Z")
	assert.Contains(t, result.HumanReadable, "UTC")
}

func TestService_EdgeCases(t *testing.T) {
	service := time.NewService()

	tests := []struct {
		name        string
		input       string
		inputFormat string
		expectError bool
	}{
		{
			name:        "Empty input",
			input:       "",
			inputFormat: time.FormatUnixSeconds,
			expectError: true,
		},
		{
			name:        "Whitespace input",
			input:       "   ",
			inputFormat: time.FormatUnixSeconds,
			expectError: true,
		},
		{
			name:        "Negative Unix timestamp",
			input:       "-1",
			inputFormat: time.FormatUnixSeconds,
			expectError: false, // Should work (before epoch)
		},
		{
			name:        "Very large Unix timestamp",
			input:       "9999999999",
			inputFormat: time.FormatUnixSeconds,
			expectError: false, // Should work (far future)
		},
		{
			name:        "Zero Unix timestamp",
			input:       "0",
			inputFormat: time.FormatUnixSeconds,
			expectError: false, // Should work (epoch)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := service.ConvertTime(tt.input, tt.inputFormat, time.FormatISO8601)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetSupportedFormats(t *testing.T) {
	formats := time.GetSupportedFormats()

	expectedFormats := []string{
		time.FormatUnixSeconds,
		time.FormatUnixMilliseconds,
		time.FormatISO8601,
		time.FormatRFC3339,
		time.FormatHumanReadable,
	}

	assert.ElementsMatch(t, expectedFormats, formats)
	assert.Len(t, formats, 5)
}

func TestConstants(t *testing.T) {
	// Test that constants have expected values
	assert.Equal(t, "unix", time.FormatUnixSeconds)
	assert.Equal(t, "unix_ms", time.FormatUnixMilliseconds)
	assert.Equal(t, "iso8601", time.FormatISO8601)
	assert.Equal(t, "rfc3339", time.FormatRFC3339)
	assert.Equal(t, "human", time.FormatHumanReadable)

	assert.Equal(t, "2006-01-02T15:04:05Z", time.ISO8601Layout)
	assert.Equal(t, stdtime.RFC3339, time.RFC3339Layout)
	assert.Equal(t, "2006-01-02 15:04:05 UTC", time.HumanLayout)
}

func BenchmarkConvertTime(b *testing.B) {
	service := time.NewService()

	b.Run("Unix to ISO8601", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := service.ConvertTime("1703518245", time.FormatUnixSeconds, time.FormatISO8601)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ISO8601 to Unix", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := service.ConvertTime("2023-12-25T15:30:45Z", time.FormatISO8601, time.FormatUnixSeconds)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkGetCurrentTime(b *testing.B) {
	service := time.NewService()

	for i := 0; i < b.N; i++ {
		_, err := service.GetCurrentTime()
		if err != nil {
			b.Fatal(err)
		}
	}
}
