# Regular Expression Testing

Test regex patterns against text content and extract matches.

## Tool: `mcp_dev_utilities_mcp_text_regex_test`

### Example 1: Email Validation Pattern
**Input:**
```
Pattern: "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
Content: "user@example.com"
```
**Output:**
```json
{
  "data": {
    "matches": [
      "user@example.com"
    ],
    "pattern": "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"
  },
  "success": true
}
```

### Example 2: Phone Number Extraction
**Input:**
```
Pattern: "\\d{3}-\\d{3}-\\d{4}"
Content: "Call me at 555-123-4567 or 999-888-7777"
```
**Output:**
```json
{
  "data": {
    "matches": [
      "555-123-4567",
      "999-888-7777"
    ],
    "pattern": "\\d{3}-\\d{3}-\\d{4}"
  },
  "success": true
}
```

### Example 3: URL Extraction
**Input:**
```
Pattern: "https?://[^\\s]+"
Content: "Visit https://example.com or http://test.org for more info"
```
**Output:**
```json
{
  "data": {
    "matches": [
      "https://example.com",
      "http://test.org"
    ],
    "pattern": "https?://[^\\s]+"
  },
  "success": true
}
```

### Example 4: Capitalized Words with Global Flag
**Input:**
```
Pattern: "[A-Z][a-z]+"
Content: "John Smith and Mary Johnson went to New York"
Flags: "g"
```
**Output:**
```json
{
  "data": {
    "matches": [
      "John",
      "Smith",
      "Mary",
      "Johnson",
      "New",
      "York"
    ],
    "pattern": "[A-Z][a-z]+"
  },
  "success": true
}
```

### Example 5: No Matches Found
**Input:**
```
Pattern: "no-match-pattern"
Content: "This text doesn't contain the pattern"
```
**Output:**
```json
{
  "data": {
    "matches": [],
    "pattern": "no-match-pattern"
  },
  "success": true
}
```

## Common Regex Patterns

### Email Validation
```regex
^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$
```

### Phone Numbers (US Format)
```regex
\d{3}-\d{3}-\d{4}
```

### URLs (HTTP/HTTPS)
```regex
https?://[^\s]+
```

### IP Addresses
```regex
\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b
```

### Hexadecimal Colors
```regex
#[0-9A-Fa-f]{6}
```

### Credit Card Numbers
```regex
\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}
```

### Date Formats (YYYY-MM-DD)
```regex
\d{4}-\d{2}-\d{2}
```

### HTML Tags
```regex
<[^>]+>
```

## Regex Flags

### Global (`g`)
Find all matches, not just the first one.

### Case Insensitive (`i`)
Ignore case when matching.

### Multiline (`m`)
`^` and `$` match line breaks.

### Dot All (`s`)
`.` matches newline characters.

## Use Cases
- **Data Validation**: Email, phone, URL validation
- **Data Extraction**: Extracting specific patterns from text
- **Log Analysis**: Finding error patterns in log files
- **Content Processing**: Extracting structured data from unstructured text
- **Form Validation**: Client-side and server-side input validation
- **Search and Replace**: Finding patterns for replacement operations
- **Data Cleaning**: Identifying and processing malformed data
- **Security**: Detecting potentially malicious patterns

## Best Practices
- Test regex patterns thoroughly with various inputs
- Use specific patterns rather than overly broad ones
- Consider performance implications of complex patterns
- Escape special characters when matching literal text
- Use non-capturing groups `(?:...)` when grouping is needed but capture isn't
- Be careful with greedy vs. non-greedy quantifiers