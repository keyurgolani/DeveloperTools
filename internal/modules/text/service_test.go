package text_test

import (
	"testing"

	"github.com/keyurgolani/DeveloperTools/internal/modules/text"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTextService_ConvertCase(t *testing.T) {
	service := text.NewTextService()

	var tests []struct {
		name     string
		content  string
		caseType string
		expected string
		wantErr  bool
	}

	// Add all test cases
	tests = append(tests, getUppercaseTests()...)
	tests = append(tests, getLowercaseTests()...)
	tests = append(tests, getTitleCaseTests()...)
	tests = append(tests, getSentenceCaseTests()...)
	tests = append(tests, getCamelCaseTests()...)
	tests = append(tests, getPascalCaseTests()...)
	tests = append(tests, getSnakeCaseTests()...)
	tests = append(tests, getKebabCaseTests()...)
	tests = append(tests, getCaseConversionErrorTests()...)

	runCaseConversionTests(t, service, tests)
}

func getUppercaseTests() []struct {
	name     string
	content  string
	caseType string
	expected string
	wantErr  bool
} {
	return []struct {
		name     string
		content  string
		caseType string
		expected string
		wantErr  bool
	}{
		{
			name:     "UPPERCASE basic",
			content:  "hello world",
			caseType: "UPPERCASE",
			expected: "HELLO WORLD",
			wantErr:  false,
		},
		{
			name:     "UPPERCASE with unicode",
			content:  "héllo wörld",
			caseType: "UPPERCASE",
			expected: "HÉLLO WÖRLD",
			wantErr:  false,
		},
		{
			name:     "UPPERCASE empty string",
			content:  "",
			caseType: "UPPERCASE",
			expected: "",
			wantErr:  false,
		},
	}
}

func getLowercaseTests() []struct {
	name     string
	content  string
	caseType string
	expected string
	wantErr  bool
} {
	return []struct {
		name     string
		content  string
		caseType string
		expected string
		wantErr  bool
	}{
		{
			name:     "lowercase basic",
			content:  "HELLO WORLD",
			caseType: "lowercase",
			expected: "hello world",
			wantErr:  false,
		},
		{
			name:     "lowercase with unicode",
			content:  "HÉLLO WÖRLD",
			caseType: "lowercase",
			expected: "héllo wörld",
			wantErr:  false,
		},
	}
}

func getTitleCaseTests() []struct {
	name     string
	content  string
	caseType string
	expected string
	wantErr  bool
} {
	return []struct {
		name     string
		content  string
		caseType string
		expected string
		wantErr  bool
	}{
		{
			name:     "Title Case basic",
			content:  "hello world",
			caseType: "Title Case",
			expected: "Hello World",
			wantErr:  false,
		},
	}
}

func getSentenceCaseTests() []struct {
	name     string
	content  string
	caseType string
	expected string
	wantErr  bool
} {
	return []struct {
		name     string
		content  string
		caseType string
		expected string
		wantErr  bool
	}{
		{
			name:     "Sentence case basic",
			content:  "hello WORLD",
			caseType: "Sentence case",
			expected: "Hello world",
			wantErr:  false,
		},
		{
			name:     "Sentence case with numbers",
			content:  "123 hello WORLD",
			caseType: "Sentence case",
			expected: "123 Hello world",
			wantErr:  false,
		},
		{
			name:     "Sentence case empty",
			content:  "",
			caseType: "Sentence case",
			expected: "",
			wantErr:  false,
		},
	}
}

func getCamelCaseTests() []struct {
	name     string
	content  string
	caseType string
	expected string
	wantErr  bool
} {
	return []struct {
		name     string
		content  string
		caseType string
		expected string
		wantErr  bool
	}{
		{
			name:     "camelCase basic",
			content:  "hello world test",
			caseType: "camelCase",
			expected: "helloWorldTest",
			wantErr:  false,
		},
		{
			name:     "camelCase with punctuation",
			content:  "hello-world_test",
			caseType: "camelCase",
			expected: "helloWorldTest",
			wantErr:  false,
		},
		{
			name:     "camelCase single word",
			content:  "hello",
			caseType: "camelCase",
			expected: "hello",
			wantErr:  false,
		},
		{
			name:     "camelCase empty",
			content:  "",
			caseType: "camelCase",
			expected: "",
			wantErr:  false,
		},
	}
}

func getPascalCaseTests() []struct {
	name     string
	content  string
	caseType string
	expected string
	wantErr  bool
} {
	return []struct {
		name     string
		content  string
		caseType string
		expected string
		wantErr  bool
	}{
		{
			name:     "PascalCase basic",
			content:  "hello world test",
			caseType: "PascalCase",
			expected: "HelloWorldTest",
			wantErr:  false,
		},
		{
			name:     "PascalCase with punctuation",
			content:  "hello-world_test",
			caseType: "PascalCase",
			expected: "HelloWorldTest",
			wantErr:  false,
		},
	}
}

func getSnakeCaseTests() []struct {
	name     string
	content  string
	caseType string
	expected string
	wantErr  bool
} {
	return []struct {
		name     string
		content  string
		caseType string
		expected string
		wantErr  bool
	}{
		{
			name:     "snake_case basic",
			content:  "hello world test",
			caseType: "snake_case",
			expected: "hello_world_test",
			wantErr:  false,
		},
		{
			name:     "snake_case with punctuation",
			content:  "hello-world.test",
			caseType: "snake_case",
			expected: "hello_world_test",
			wantErr:  false,
		},
	}
}

func getKebabCaseTests() []struct {
	name     string
	content  string
	caseType string
	expected string
	wantErr  bool
} {
	return []struct {
		name     string
		content  string
		caseType string
		expected string
		wantErr  bool
	}{
		{
			name:     "kebab-case basic",
			content:  "hello world test",
			caseType: "kebab-case",
			expected: "hello-world-test",
			wantErr:  false,
		},
		{
			name:     "kebab-case with punctuation",
			content:  "hello_world.test",
			caseType: "kebab-case",
			expected: "hello-world-test",
			wantErr:  false,
		},
	}
}

func getCaseConversionErrorTests() []struct {
	name     string
	content  string
	caseType string
	expected string
	wantErr  bool
} {
	return []struct {
		name     string
		content  string
		caseType string
		expected string
		wantErr  bool
	}{
		{
			name:     "unsupported case type",
			content:  "hello world",
			caseType: "invalidCase",
			expected: "",
			wantErr:  true,
		},
	}
}

func runCaseConversionTests(t *testing.T, service text.TextService, tests []struct {
	name     string
	content  string
	caseType string
	expected string
	wantErr  bool
},
) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := service.ConvertCase(tt.content, tt.caseType)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

type analyzeTextTestCase struct {
	name     string
	content  string
	expected *text.TextInfo
}

func getBasicAnalyzeTextTestCases() []analyzeTextTestCase {
	return []analyzeTextTestCase{
		{
			name:    "basic text",
			content: "Hello world! How are you?",
			expected: &text.TextInfo{
				CharacterCount: 25,
				WordCount:      5,
				LineCount:      1,
				SentenceCount:  2,
				ByteSize:       25,
			},
		},
		{
			name:    "multiline text",
			content: "Hello world!\nHow are you?\nI am fine.",
			expected: &text.TextInfo{
				CharacterCount: 36,
				WordCount:      8,
				LineCount:      3,
				SentenceCount:  3,
				ByteSize:       36,
			},
		},
		{
			name:    "unicode text",
			content: "Héllo wörld! 你好世界",
			expected: &text.TextInfo{
				CharacterCount: 17,
				WordCount:      3,
				LineCount:      1,
				SentenceCount:  1,
				ByteSize:       27, // UTF-8 bytes
			},
		},
	}
}

func getEdgeCaseAnalyzeTextTestCases() []analyzeTextTestCase {
	return []analyzeTextTestCase{
		{
			name:    "empty string",
			content: "",
			expected: &text.TextInfo{
				CharacterCount: 0,
				WordCount:      0,
				LineCount:      0,
				SentenceCount:  0,
				ByteSize:       0,
			},
		},
		{
			name:    "whitespace only",
			content: "   \n\t  ",
			expected: &text.TextInfo{
				CharacterCount: 7,
				WordCount:      0,
				LineCount:      2,
				SentenceCount:  0,
				ByteSize:       7,
			},
		},
		{
			name:    "no sentence endings",
			content: "Hello world",
			expected: &text.TextInfo{
				CharacterCount: 11,
				WordCount:      2,
				LineCount:      1,
				SentenceCount:  1, // Should count as 1 sentence even without ending
				ByteSize:       11,
			},
		},
		{
			name:    "multiple sentence endings",
			content: "Hello! How are you? I'm fine. Great!",
			expected: &text.TextInfo{
				CharacterCount: 36,
				WordCount:      7,
				LineCount:      1,
				SentenceCount:  4,
				ByteSize:       36,
			},
		},
	}
}

func getAnalyzeTextTestCases() []analyzeTextTestCase {
	var cases []analyzeTextTestCase
	cases = append(cases, getBasicAnalyzeTextTestCases()...)
	cases = append(cases, getEdgeCaseAnalyzeTextTestCases()...)
	return cases
}

func TestTextService_AnalyzeText(t *testing.T) {
	service := text.NewTextService()
	tests := getAnalyzeTextTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := service.AnalyzeText(tt.content)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func getBasicRegexTestCases() []struct {
	name     string
	content  string
	pattern  string
	flags    string
	expected []string
	wantErr  bool
} {
	return []struct {
		name     string
		content  string
		pattern  string
		flags    string
		expected []string
		wantErr  bool
	}{
		{
			name:     "basic match",
			content:  "hello world hello",
			pattern:  "hello",
			flags:    "",
			expected: []string{"hello", "hello"},
			wantErr:  false,
		},
		{
			name:     "no matches",
			content:  "hello world",
			pattern:  "xyz",
			flags:    "",
			expected: []string{},
			wantErr:  false,
		},
		{
			name:     "digit pattern",
			content:  "abc123def456ghi",
			pattern:  `\d+`,
			flags:    "",
			expected: []string{"123", "456"},
			wantErr:  false,
		},
		{
			name:     "word boundaries",
			content:  "password and pass",
			pattern:  `\bpass\b`,
			flags:    "",
			expected: []string{"pass"},
			wantErr:  false,
		},
	}
}

func getAdvancedRegexTestCases() []struct {
	name     string
	content  string
	pattern  string
	flags    string
	expected []string
	wantErr  bool
} {
	return []struct {
		name     string
		content  string
		pattern  string
		flags    string
		expected []string
		wantErr  bool
	}{
		{
			name:     "email pattern",
			content:  "Contact us at test@example.com or admin@test.org",
			pattern:  `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
			flags:    "",
			expected: []string{"test@example.com", "admin@test.org"},
			wantErr:  false,
		},
		{
			name:     "invalid regex",
			content:  "hello world",
			pattern:  "[invalid",
			flags:    "",
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "empty content",
			content:  "",
			pattern:  "hello",
			flags:    "",
			expected: []string{},
			wantErr:  false,
		},
	}
}

func getTestRegexTestCases() []struct {
	name     string
	content  string
	pattern  string
	flags    string
	expected []string
	wantErr  bool
} {
	var cases []struct {
		name     string
		content  string
		pattern  string
		flags    string
		expected []string
		wantErr  bool
	}
	cases = append(cases, getBasicRegexTestCases()...)
	cases = append(cases, getAdvancedRegexTestCases()...)
	return cases
}

func TestTextService_TestRegex(t *testing.T) {
	service := text.NewTextService()
	tests := getTestRegexTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := service.TestRegex(tt.content, tt.pattern, tt.flags)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result.Matches)
			assert.Equal(t, tt.pattern, result.Pattern)
		})
	}
}

func getValidJSONFormatTestCases() []struct {
	name     string
	content  string
	action   string
	indent   int
	expected string
	wantErr  bool
} {
	return []struct {
		name     string
		content  string
		action   string
		indent   int
		expected string
		wantErr  bool
	}{
		{
			name:     "format with default indent",
			content:  `{"name":"John","age":30,"city":"New York"}`,
			action:   "format",
			indent:   0,
			expected: "{\n  \"age\": 30,\n  \"city\": \"New York\",\n  \"name\": \"John\"\n}",
			wantErr:  false,
		},
		{
			name:     "format with custom indent",
			content:  `{"name":"John","age":30}`,
			action:   "format",
			indent:   4,
			expected: "{\n    \"age\": 30,\n    \"name\": \"John\"\n}",
			wantErr:  false,
		},
		{
			name:     "minify JSON",
			content:  "{\n  \"name\": \"John\",\n  \"age\": 30\n}",
			action:   "minify",
			indent:   0,
			expected: `{"age":30,"name":"John"}`,
			wantErr:  false,
		},
		{
			name:     "format array",
			content:  `[1,2,3]`,
			action:   "format",
			indent:   2,
			expected: "[\n  1,\n  2,\n  3\n]",
			wantErr:  false,
		},
		{
			name:     "empty JSON object",
			content:  `{}`,
			action:   "format",
			indent:   2,
			expected: "{}",
			wantErr:  false,
		},
	}
}

func getInvalidJSONFormatTestCases() []struct {
	name     string
	content  string
	action   string
	indent   int
	expected string
	wantErr  bool
} {
	return []struct {
		name     string
		content  string
		action   string
		indent   int
		expected string
		wantErr  bool
	}{
		{
			name:     "invalid JSON",
			content:  `{"name":"John",}`,
			action:   "format",
			indent:   2,
			expected: "",
			wantErr:  true,
		},
		{
			name:     "unsupported action",
			content:  `{"name":"John"}`,
			action:   "invalid",
			indent:   2,
			expected: "",
			wantErr:  true,
		},
	}
}

func getFormatJSONTestCases() []struct {
	name     string
	content  string
	action   string
	indent   int
	expected string
	wantErr  bool
} {
	var cases []struct {
		name     string
		content  string
		action   string
		indent   int
		expected string
		wantErr  bool
	}
	cases = append(cases, getValidJSONFormatTestCases()...)
	cases = append(cases, getInvalidJSONFormatTestCases()...)
	return cases
}

func TestTextService_FormatJSON(t *testing.T) {
	service := text.NewTextService()
	tests := getFormatJSONTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := service.FormatJSON(tt.content, tt.action, tt.indent)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

type sortTextTestCase struct {
	name     string
	content  string
	order    string
	sortType string
	expected string
	wantErr  bool
}

func getAlphabeticalSortTestCases() []sortTextTestCase {
	return []sortTextTestCase{
		{
			name:     "alphabetical ascending",
			content:  "zebra\napple\nbanana",
			order:    "asc",
			sortType: "alpha",
			expected: "apple\nbanana\nzebra",
			wantErr:  false,
		},
		{
			name:     "alphabetical descending",
			content:  "apple\nbanana\nzebra",
			order:    "desc",
			sortType: "alpha",
			expected: "zebra\nbanana\napple",
			wantErr:  false,
		},
	}
}

func getNumericalSortTestCases() []sortTextTestCase {
	return []sortTextTestCase{
		{
			name:     "numerical ascending",
			content:  "10\n2\n1\n20",
			order:    "asc",
			sortType: "numeric",
			expected: "1\n2\n10\n20",
			wantErr:  false,
		},
		{
			name:     "numerical descending",
			content:  "1\n2\n10\n20",
			order:    "desc",
			sortType: "numeric",
			expected: "20\n10\n2\n1",
			wantErr:  false,
		},
		{
			name:     "numerical with decimals",
			content:  "1.5\n2.1\n1.2\n10.5",
			order:    "asc",
			sortType: "numeric",
			expected: "1.2\n1.5\n2.1\n10.5",
			wantErr:  false,
		},
		{
			name:     "numerical with non-numeric lines",
			content:  "10\nabc\n5\ndef\n1",
			order:    "asc",
			sortType: "numeric",
			expected: "1\n5\n10\nabc\ndef",
			wantErr:  false,
		},
	}
}

func getEdgeCaseSortTestCases() []sortTextTestCase {
	return []sortTextTestCase{
		{
			name:     "empty content",
			content:  "",
			order:    "asc",
			sortType: "alpha",
			expected: "",
			wantErr:  false,
		},
		{
			name:     "single line",
			content:  "hello",
			order:    "asc",
			sortType: "alpha",
			expected: "hello",
			wantErr:  false,
		},
		{
			name:     "unsupported order",
			content:  "a\nb\nc",
			order:    "invalid",
			sortType: "alpha",
			expected: "",
			wantErr:  true,
		},
		{
			name:     "unsupported sort type",
			content:  "a\nb\nc",
			order:    "asc",
			sortType: "invalid",
			expected: "",
			wantErr:  true,
		},
		{
			name:     "whitespace only content",
			content:  "   ",
			order:    "asc",
			sortType: "alpha",
			expected: "   ",
			wantErr:  false,
		},
	}
}

func getSortTextTestCases() []sortTextTestCase {
	var cases []sortTextTestCase
	cases = append(cases, getAlphabeticalSortTestCases()...)
	cases = append(cases, getNumericalSortTestCases()...)
	cases = append(cases, getEdgeCaseSortTestCases()...)
	return cases
}

func TestTextService_SortText(t *testing.T) {
	service := text.NewTextService()
	tests := getSortTextTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := service.SortText(tt.content, tt.order, tt.sortType)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test edge cases for case conversion.
func TestTextService_CaseConversion_EdgeCases(t *testing.T) {
	service := text.NewTextService()

	t.Run("camelCase with numbers", func(t *testing.T) {
		result, err := service.ConvertCase("hello 123 world", "camelCase")
		require.NoError(t, err)
		assert.Equal(t, "hello123World", result)
	})

	t.Run("PascalCase with special characters", func(t *testing.T) {
		result, err := service.ConvertCase("hello@world#test", "PascalCase")
		require.NoError(t, err)
		assert.Equal(t, "HelloWorldTest", result)
	})

	t.Run("snake_case with mixed case", func(t *testing.T) {
		result, err := service.ConvertCase("Hello WORLD Test", "snake_case")
		require.NoError(t, err)
		assert.Equal(t, "hello_world_test", result)
	})

	t.Run("sentence case with unicode", func(t *testing.T) {
		result, err := service.ConvertCase("héllo WÖRLD", "Sentence case")
		require.NoError(t, err)
		assert.Equal(t, "Héllo wörld", result)
	})
}
