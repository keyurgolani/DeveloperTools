package text

// CaseConvertRequest represents a case conversion request
type CaseConvertRequest struct {
	Content  string `json:"content"`
	CaseType string `json:"caseType" binding:"required,oneof=UPPERCASE lowercase 'Title Case' 'Sentence case' camelCase PascalCase snake_case kebab-case"`
}

// CaseConvertResponse represents a case conversion response
type CaseConvertResponse struct {
	Result   string `json:"result"`
	CaseType string `json:"caseType"`
}

// TextAnalyzeRequest represents a text analysis request
type TextAnalyzeRequest struct {
	Content string `json:"content"`
}

// TextInfo represents text analysis information
type TextInfo struct {
	CharacterCount int `json:"characterCount"`
	WordCount      int `json:"wordCount"`
	LineCount      int `json:"lineCount"`
	SentenceCount  int `json:"sentenceCount"`
	ByteSize       int `json:"byteSize"`
}

// TextAnalyzeResponse represents a text analysis response
type TextAnalyzeResponse struct {
	Info *TextInfo `json:"info"`
}

// RegexTestRequest represents a regex testing request
type RegexTestRequest struct {
	Content string `json:"content"`
	Pattern string `json:"pattern" binding:"required"`
	Flags   string `json:"flags"`
}

// RegexTestResponse represents a regex testing response
type RegexTestResponse struct {
	Matches []string `json:"matches"`
	Pattern string   `json:"pattern"`
}

// JSONFormatRequest represents a JSON formatting request
type JSONFormatRequest struct {
	Content string `json:"content" binding:"required"`
	Action  string `json:"action" binding:"required,oneof=format minify"`
	Indent  int    `json:"indent,omitempty"`
}

// JSONFormatResponse represents a JSON formatting response
type JSONFormatResponse struct {
	Result string `json:"result"`
}

// TextSortRequest represents a text sorting request
type TextSortRequest struct {
	Content  string `json:"content"`
	Order    string `json:"order" binding:"required,oneof=asc desc"`
	SortType string `json:"sortType" binding:"required,oneof=alpha numeric"`
}

// TextSortResponse represents a text sorting response
type TextSortResponse struct {
	Result string `json:"result"`
}