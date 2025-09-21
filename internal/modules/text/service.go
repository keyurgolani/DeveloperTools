package text

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// TextService defines the interface for text manipulation operations
type TextService interface {
	ConvertCase(content, caseType string) (string, error)
	AnalyzeText(content string) (*TextInfo, error)
	TestRegex(content, pattern, flags string) (*RegexTestResponse, error)
	FormatJSON(content, action string, indent int) (string, error)
	SortText(content, order, sortType string) (string, error)
}

// textService implements the TextService interface
type textService struct{}

// NewTextService creates a new instance of TextService
func NewTextService() TextService {
	return &textService{}
}

// ConvertCase converts text to the specified case type
func (s *textService) ConvertCase(content, caseType string) (string, error) {
	switch caseType {
	case "UPPERCASE":
		return strings.ToUpper(content), nil
	case "lowercase":
		return strings.ToLower(content), nil
	case "Title Case":
		return s.toTitleCase(content), nil
	case "Sentence case":
		return s.toSentenceCase(content), nil
	case "camelCase":
		return s.toCamelCase(content), nil
	case "PascalCase":
		return s.toPascalCase(content), nil
	case "snake_case":
		return s.toSnakeCase(content), nil
	case "kebab-case":
		return s.toKebabCase(content), nil
	default:
		return "", fmt.Errorf("unsupported case type: %s", caseType)
	}
}

// toSentenceCase converts text to sentence case (first letter uppercase, rest lowercase)
func (s *textService) toSentenceCase(content string) string {
	if len(content) == 0 {
		return content
	}
	
	runes := []rune(content)
	result := make([]rune, len(runes))
	
	// Find the first letter and make it uppercase
	firstLetterFound := false
	for i, r := range runes {
		if unicode.IsLetter(r) && !firstLetterFound {
			result[i] = unicode.ToUpper(r)
			firstLetterFound = true
		} else {
			result[i] = unicode.ToLower(r)
		}
	}
	
	return string(result)
}

// toCamelCase converts text to camelCase
func (s *textService) toCamelCase(content string) string {
	words := s.splitIntoWords(content)
	if len(words) == 0 {
		return ""
	}
	
	result := strings.ToLower(words[0])
	for i := 1; i < len(words); i++ {
		if len(words[i]) > 0 {
			result += strings.ToUpper(string(words[i][0])) + strings.ToLower(words[i][1:])
		}
	}
	
	return result
}

// toPascalCase converts text to PascalCase
func (s *textService) toPascalCase(content string) string {
	words := s.splitIntoWords(content)
	var result strings.Builder
	
	for _, word := range words {
		if len(word) > 0 {
			result.WriteString(strings.ToUpper(string(word[0])) + strings.ToLower(word[1:]))
		}
	}
	
	return result.String()
}

// toSnakeCase converts text to snake_case
func (s *textService) toSnakeCase(content string) string {
	words := s.splitIntoWords(content)
	var result []string
	
	for _, word := range words {
		if len(word) > 0 {
			result = append(result, strings.ToLower(word))
		}
	}
	
	return strings.Join(result, "_")
}

// toTitleCase converts text to proper Title Case (first letter of each word capitalized)
func (s *textService) toTitleCase(content string) string {
	words := s.splitIntoWords(content)
	var result []string
	
	for _, word := range words {
		if len(word) > 0 {
			result = append(result, strings.ToUpper(string(word[0]))+strings.ToLower(word[1:]))
		}
	}
	
	return strings.Join(result, " ")
}

// toKebabCase converts text to kebab-case
func (s *textService) toKebabCase(content string) string {
	words := s.splitIntoWords(content)
	var result []string
	
	for _, word := range words {
		if len(word) > 0 {
			result = append(result, strings.ToLower(word))
		}
	}
	
	return strings.Join(result, "-")
}

// splitIntoWords splits content into words by whitespace and punctuation
func (s *textService) splitIntoWords(content string) []string {
	// Split by whitespace and common punctuation
	re := regexp.MustCompile(`[\s\-_.,;:!?()[\]{}@#$%^&*+=<>/\\|~`+"`"+`]+`)
	words := re.Split(content, -1)
	
	// Filter out empty strings
	var result []string
	for _, word := range words {
		if len(strings.TrimSpace(word)) > 0 {
			result = append(result, strings.TrimSpace(word))
		}
	}
	
	// Return empty slice instead of nil
	if result == nil {
		return []string{}
	}
	
	return result
}

// AnalyzeText analyzes text and returns various statistics
func (s *textService) AnalyzeText(content string) (*TextInfo, error) {
	info := &TextInfo{
		CharacterCount: len([]rune(content)),                    // Unicode-correct character count
		WordCount:      s.countWords(content),                   // Word count
		LineCount:      s.countLines(content),                   // Line count
		SentenceCount:  s.countSentences(content),               // Sentence count
		ByteSize:       len([]byte(content)),                    // Byte size
	}
	
	return info, nil
}

// countWords counts words by splitting on whitespace
func (s *textService) countWords(content string) int {
	if len(strings.TrimSpace(content)) == 0 {
		return 0
	}
	
	// Split on whitespace regex
	re := regexp.MustCompile(`\s+`)
	words := re.Split(strings.TrimSpace(content), -1)
	
	// Filter out empty strings
	count := 0
	for _, word := range words {
		if len(strings.TrimSpace(word)) > 0 {
			count++
		}
	}
	
	return count
}

// countLines counts lines by splitting on newline character
func (s *textService) countLines(content string) int {
	if len(content) == 0 {
		return 0
	}
	
	lines := strings.Split(content, "\n")
	return len(lines)
}

// countSentences counts sentences using heuristic (split by ., ?, ! followed by space or end-of-string)
func (s *textService) countSentences(content string) int {
	if len(strings.TrimSpace(content)) == 0 {
		return 0
	}
	
	// Regex to match sentence endings: ., ?, ! followed by space or end of string
	re := regexp.MustCompile(`[.!?](?:\s|$)`)
	matches := re.FindAllString(content, -1)
	
	count := len(matches)
	
	// If no sentence endings found but content exists, count as 1 sentence
	if count == 0 && len(strings.TrimSpace(content)) > 0 {
		return 1
	}
	
	return count
}

// TestRegex tests a regex pattern against content and returns matches
func (s *textService) TestRegex(content, pattern, flags string) (*RegexTestResponse, error) {
	// Compile the regex pattern
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex pattern: %w", err)
	}
	
	// Find all matches
	matches := compiled.FindAllString(content, -1)
	if matches == nil {
		matches = []string{} // Return empty slice instead of nil
	}
	
	response := &RegexTestResponse{
		Matches: matches,
		Pattern: pattern,
	}
	
	return response, nil
}

// FormatJSON formats or minifies JSON with configurable indentation
func (s *textService) FormatJSON(content, action string, indent int) (string, error) {
	// First, validate that the content is valid JSON
	var jsonData interface{}
	if err := json.Unmarshal([]byte(content), &jsonData); err != nil {
		return "", fmt.Errorf("invalid JSON: %w", err)
	}
	
	switch action {
	case "format":
		// Format with indentation
		indentStr := strings.Repeat(" ", indent)
		if indent <= 0 {
			indentStr = "  " // Default to 2 spaces
		}
		
		formatted, err := json.MarshalIndent(jsonData, "", indentStr)
		if err != nil {
			return "", fmt.Errorf("failed to format JSON: %w", err)
		}
		
		return string(formatted), nil
		
	case "minify":
		// Minify (no indentation)
		minified, err := json.Marshal(jsonData)
		if err != nil {
			return "", fmt.Errorf("failed to minify JSON: %w", err)
		}
		
		return string(minified), nil
		
	default:
		return "", fmt.Errorf("unsupported action: %s", action)
	}
}

// SortText sorts text lines alphabetically or numerically
func (s *textService) SortText(content, order, sortType string) (string, error) {
	if len(strings.TrimSpace(content)) == 0 {
		return content, nil
	}
	
	lines := strings.Split(content, "\n")
	
	switch sortType {
	case "alpha":
		// Alphabetical sorting
		if order == "asc" {
			sort.Strings(lines)
		} else if order == "desc" {
			sort.Sort(sort.Reverse(sort.StringSlice(lines)))
		} else {
			return "", fmt.Errorf("unsupported order: %s", order)
		}
		
	case "numeric":
		// Numerical sorting
		err := s.sortLinesNumerically(lines, order)
		if err != nil {
			return "", fmt.Errorf("failed to sort numerically: %w", err)
		}
		
	default:
		return "", fmt.Errorf("unsupported sort type: %s", sortType)
	}
	
	return strings.Join(lines, "\n"), nil
}

// sortLinesNumerically sorts lines numerically
func (s *textService) sortLinesNumerically(lines []string, order string) error {
	// Create a slice of structs to hold both the original line and its numeric value
	type lineWithValue struct {
		line  string
		value float64
		isNum bool
	}
	
	lineValues := make([]lineWithValue, len(lines))
	
	// Parse each line to extract numeric value
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if val, err := strconv.ParseFloat(trimmed, 64); err == nil {
			lineValues[i] = lineWithValue{line: line, value: val, isNum: true}
		} else {
			// For non-numeric lines, use 0 and mark as non-numeric
			lineValues[i] = lineWithValue{line: line, value: 0, isNum: false}
		}
	}
	
	// Sort based on order
	if order == "asc" {
		sort.Slice(lineValues, func(i, j int) bool {
			// Non-numeric lines go to the end
			if !lineValues[i].isNum && lineValues[j].isNum {
				return false
			}
			if lineValues[i].isNum && !lineValues[j].isNum {
				return true
			}
			// Both numeric or both non-numeric
			if lineValues[i].isNum && lineValues[j].isNum {
				return lineValues[i].value < lineValues[j].value
			}
			// Both non-numeric, sort alphabetically
			return lineValues[i].line < lineValues[j].line
		})
	} else if order == "desc" {
		sort.Slice(lineValues, func(i, j int) bool {
			// Non-numeric lines go to the end
			if !lineValues[i].isNum && lineValues[j].isNum {
				return false
			}
			if lineValues[i].isNum && !lineValues[j].isNum {
				return true
			}
			// Both numeric or both non-numeric
			if lineValues[i].isNum && lineValues[j].isNum {
				return lineValues[i].value > lineValues[j].value
			}
			// Both non-numeric, sort alphabetically (reverse)
			return lineValues[i].line > lineValues[j].line
		})
	} else {
		return fmt.Errorf("unsupported order: %s", order)
	}
	
	// Update the original lines slice
	for i, lv := range lineValues {
		lines[i] = lv.line
	}
	
	return nil
}