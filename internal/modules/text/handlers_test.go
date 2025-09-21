package text

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	
	service := NewTextService()
	handler := NewHandler(service, nil) // Pass nil for metrics in tests
	
	api := router.Group("/api/v1")
	handler.RegisterRoutes(api)
	
	return router
}

func TestHandler_ConvertCase(t *testing.T) {
	router := setupTestRouter()

	tests := []struct {
		name           string
		request        CaseConvertRequest
		expectedStatus int
		expectedResult string
		expectError    bool
	}{
		{
			name: "successful UPPERCASE conversion",
			request: CaseConvertRequest{
				Content:  "hello world",
				CaseType: "UPPERCASE",
			},
			expectedStatus: http.StatusOK,
			expectedResult: "HELLO WORLD",
			expectError:    false,
		},
		{
			name: "successful camelCase conversion",
			request: CaseConvertRequest{
				Content:  "hello world test",
				CaseType: "camelCase",
			},
			expectedStatus: http.StatusOK,
			expectedResult: "helloWorldTest",
			expectError:    false,
		},
		{
			name: "invalid case type",
			request: CaseConvertRequest{
				Content:  "hello world",
				CaseType: "invalidCase",
			},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name: "empty content",
			request: CaseConvertRequest{
				Content:  "",
				CaseType: "UPPERCASE",
			},
			expectedStatus: http.StatusOK,
			expectedResult: "",
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonData, err := json.Marshal(tt.request)
			require.NoError(t, err)

			req, err := http.NewRequest("POST", "/api/v1/text/case", bytes.NewBuffer(jsonData))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)

			if tt.expectError {
				assert.Contains(t, response, "error")
				assert.NotContains(t, response, "success")
			} else {
				assert.Equal(t, true, response["success"])
				data := response["data"].(map[string]interface{})
				assert.Equal(t, tt.expectedResult, data["result"])
				assert.Equal(t, tt.request.CaseType, data["caseType"])
			}
		})
	}
}

func TestHandler_AnalyzeText(t *testing.T) {
	router := setupTestRouter()

	tests := []struct {
		name           string
		request        TextAnalyzeRequest
		expectedStatus int
		expectedInfo   *TextInfo
		expectError    bool
	}{
		{
			name: "successful text analysis",
			request: TextAnalyzeRequest{
				Content: "Hello world! How are you?",
			},
			expectedStatus: http.StatusOK,
			expectedInfo: &TextInfo{
				CharacterCount: 25,
				WordCount:      5,
				LineCount:      1,
				SentenceCount:  2,
				ByteSize:       25,
			},
			expectError: false,
		},
		{
			name: "empty content analysis",
			request: TextAnalyzeRequest{
				Content: "",
			},
			expectedStatus: http.StatusOK,
			expectedInfo: &TextInfo{
				CharacterCount: 0,
				WordCount:      0,
				LineCount:      0,
				SentenceCount:  0,
				ByteSize:       0,
			},
			expectError: false,
		},
		{
			name: "multiline text analysis",
			request: TextAnalyzeRequest{
				Content: "Hello world!\nHow are you?",
			},
			expectedStatus: http.StatusOK,
			expectedInfo: &TextInfo{
				CharacterCount: 25,
				WordCount:      5,
				LineCount:      2,
				SentenceCount:  2,
				ByteSize:       25,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonData, err := json.Marshal(tt.request)
			require.NoError(t, err)

			req, err := http.NewRequest("POST", "/api/v1/text/info", bytes.NewBuffer(jsonData))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)

			if tt.expectError {
				assert.Contains(t, response, "error")
			} else {
				assert.Equal(t, true, response["success"])
				data := response["data"].(map[string]interface{})
				
				assert.Equal(t, float64(tt.expectedInfo.CharacterCount), data["characterCount"])
				assert.Equal(t, float64(tt.expectedInfo.WordCount), data["wordCount"])
				assert.Equal(t, float64(tt.expectedInfo.LineCount), data["lineCount"])
				assert.Equal(t, float64(tt.expectedInfo.SentenceCount), data["sentenceCount"])
				assert.Equal(t, float64(tt.expectedInfo.ByteSize), data["byteSize"])
			}
		})
	}
}

func TestHandler_TestRegex(t *testing.T) {
	router := setupTestRouter()

	tests := []struct {
		name           string
		request        RegexTestRequest
		expectedStatus int
		expectedMatches []string
		expectError    bool
	}{
		{
			name: "successful regex match",
			request: RegexTestRequest{
				Content: "hello world hello",
				Pattern: "hello",
				Flags:   "",
			},
			expectedStatus:  http.StatusOK,
			expectedMatches: []string{"hello", "hello"},
			expectError:     false,
		},
		{
			name: "no matches",
			request: RegexTestRequest{
				Content: "hello world",
				Pattern: "xyz",
				Flags:   "",
			},
			expectedStatus:  http.StatusOK,
			expectedMatches: []string{},
			expectError:     false,
		},
		{
			name: "invalid regex pattern",
			request: RegexTestRequest{
				Content: "hello world",
				Pattern: "[invalid",
				Flags:   "",
			},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name: "digit pattern",
			request: RegexTestRequest{
				Content: "abc123def456",
				Pattern: `\d+`,
				Flags:   "",
			},
			expectedStatus:  http.StatusOK,
			expectedMatches: []string{"123", "456"},
			expectError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonData, err := json.Marshal(tt.request)
			require.NoError(t, err)

			req, err := http.NewRequest("POST", "/api/v1/text/regex", bytes.NewBuffer(jsonData))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)

			if tt.expectError {
				assert.Contains(t, response, "error")
			} else {
				assert.Equal(t, true, response["success"])
				data := response["data"].(map[string]interface{})
				
				matches := data["matches"].([]interface{})
				actualMatches := make([]string, len(matches))
				for i, match := range matches {
					actualMatches[i] = match.(string)
				}
				
				assert.Equal(t, tt.expectedMatches, actualMatches)
				assert.Equal(t, tt.request.Pattern, data["pattern"])
			}
		})
	}
}

func TestHandler_FormatJSON(t *testing.T) {
	router := setupTestRouter()

	tests := []struct {
		name           string
		request        JSONFormatRequest
		expectedStatus int
		expectError    bool
		validateResult func(t *testing.T, result string)
	}{
		{
			name: "successful JSON formatting",
			request: JSONFormatRequest{
				Content: `{"name":"John","age":30}`,
				Action:  "format",
				Indent:  2,
			},
			expectedStatus: http.StatusOK,
			expectError:    false,
			validateResult: func(t *testing.T, result string) {
				assert.Contains(t, result, "\"name\": \"John\"")
				assert.Contains(t, result, "\"age\": 30")
				// Should be formatted with indentation
				assert.Contains(t, result, "\n")
			},
		},
		{
			name: "successful JSON minification",
			request: JSONFormatRequest{
				Content: "{\n  \"name\": \"John\",\n  \"age\": 30\n}",
				Action:  "minify",
				Indent:  0,
			},
			expectedStatus: http.StatusOK,
			expectError:    false,
			validateResult: func(t *testing.T, result string) {
				// Should be minified (no whitespace)
				assert.NotContains(t, result, "\n")
				assert.NotContains(t, result, "  ")
				assert.Contains(t, result, `"name":"John"`)
			},
		},
		{
			name: "invalid JSON",
			request: JSONFormatRequest{
				Content: `{"name":"John",}`,
				Action:  "format",
				Indent:  2,
			},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name: "unsupported action",
			request: JSONFormatRequest{
				Content: `{"name":"John"}`,
				Action:  "invalid",
				Indent:  2,
			},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonData, err := json.Marshal(tt.request)
			require.NoError(t, err)

			req, err := http.NewRequest("POST", "/api/v1/data/json/format", bytes.NewBuffer(jsonData))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)

			if tt.expectError {
				assert.Contains(t, response, "error")
			} else {
				assert.Equal(t, true, response["success"])
				data := response["data"].(map[string]interface{})
				result := data["result"].(string)
				
				if tt.validateResult != nil {
					tt.validateResult(t, result)
				}
			}
		})
	}
}

func TestHandler_SortText(t *testing.T) {
	router := setupTestRouter()

	tests := []struct {
		name           string
		request        TextSortRequest
		expectedStatus int
		expectedResult string
		expectError    bool
	}{
		{
			name: "alphabetical ascending sort",
			request: TextSortRequest{
				Content:  "zebra\napple\nbanana",
				Order:    "asc",
				SortType: "alpha",
			},
			expectedStatus: http.StatusOK,
			expectedResult: "apple\nbanana\nzebra",
			expectError:    false,
		},
		{
			name: "numerical ascending sort",
			request: TextSortRequest{
				Content:  "10\n2\n1\n20",
				Order:    "asc",
				SortType: "numeric",
			},
			expectedStatus: http.StatusOK,
			expectedResult: "1\n2\n10\n20",
			expectError:    false,
		},
		{
			name: "alphabetical descending sort",
			request: TextSortRequest{
				Content:  "apple\nbanana\nzebra",
				Order:    "desc",
				SortType: "alpha",
			},
			expectedStatus: http.StatusOK,
			expectedResult: "zebra\nbanana\napple",
			expectError:    false,
		},
		{
			name: "unsupported order",
			request: TextSortRequest{
				Content:  "a\nb\nc",
				Order:    "invalid",
				SortType: "alpha",
			},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name: "unsupported sort type",
			request: TextSortRequest{
				Content:  "a\nb\nc",
				Order:    "asc",
				SortType: "invalid",
			},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name: "empty content",
			request: TextSortRequest{
				Content:  "",
				Order:    "asc",
				SortType: "alpha",
			},
			expectedStatus: http.StatusOK,
			expectedResult: "",
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonData, err := json.Marshal(tt.request)
			require.NoError(t, err)

			req, err := http.NewRequest("POST", "/api/v1/text/sort", bytes.NewBuffer(jsonData))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)

			if tt.expectError {
				assert.Contains(t, response, "error")
			} else {
				assert.Equal(t, true, response["success"])
				data := response["data"].(map[string]interface{})
				assert.Equal(t, tt.expectedResult, data["result"])
			}
		})
	}
}

func TestHandler_InvalidJSON(t *testing.T) {
	router := setupTestRouter()

	tests := []struct {
		name     string
		endpoint string
		body     string
	}{
		{
			name:     "invalid JSON for case conversion",
			endpoint: "/api/v1/text/case",
			body:     `{"content":"hello","caseType":}`,
		},
		{
			name:     "missing required field for regex test",
			endpoint: "/api/v1/text/regex",
			body:     `{"content":"hello"}`,
		},
		{
			name:     "invalid JSON for regex test",
			endpoint: "/api/v1/text/regex",
			body:     `{"content":"hello","pattern":}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("POST", tt.endpoint, bytes.NewBufferString(tt.body))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)

			var response map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)

			assert.Contains(t, response, "error")
		})
	}
}