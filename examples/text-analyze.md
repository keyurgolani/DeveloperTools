# Text Analysis

Analyze text content to get detailed statistics including character count, word count, line count, sentence count, and byte size.

## Tool: `mcp_dev_utilities_mcp_text_analyze`

### Example 1: Simple Text Analysis
**Input:**
```
Content: "Hello world! This is a sample text for analysis."
```
**Output:**
```json
{
  "data": {
    "characterCount": 48,
    "wordCount": 9,
    "lineCount": 1,
    "sentenceCount": 2,
    "byteSize": 48
  },
  "success": true
}
```

### Example 2: Multi-line Text with Numbers and Special Characters
**Input:**
```
Content: "Multi-line text\nwith different lines\nand various content\nincluding numbers: 123, 456\nand special characters: !@#$%"
```
**Output:**
```json
{
  "data": {
    "characterCount": 114,
    "wordCount": 16,
    "lineCount": 5,
    "sentenceCount": 1,
    "byteSize": 114
  },
  "success": true
}
```

### Example 3: Empty String Analysis
**Input:**
```
Content: ""
```
**Output:**
```json
{
  "data": {
    "characterCount": 0,
    "wordCount": 0,
    "lineCount": 0,
    "sentenceCount": 0,
    "byteSize": 0
  },
  "success": true
}
```

### Example 4: Lorem Ipsum Analysis
**Input:**
```
Content: "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
```
**Output:**
```json
{
  "data": {
    "characterCount": 445,
    "wordCount": 69,
    "lineCount": 1,
    "sentenceCount": 5,
    "byteSize": 445
  },
  "success": true
}
```

### Example 5: Text with Emojis and Unicode
**Input:**
```
Content: "Short text with emojis 🚀 and unicode characters: café, naïve, résumé"
```
**Output:**
```json
{
  "data": {
    "characterCount": 68,
    "wordCount": 11,
    "lineCount": 1,
    "sentenceCount": 1,
    "byteSize": 75
  },
  "success": true
}
```

## Metrics Explained

### Character Count
Total number of characters including spaces, punctuation, and special characters.

### Word Count
Number of words separated by whitespace. Hyphenated words are counted as single words.

### Line Count
Number of lines in the text, determined by newline characters (`\n`).

### Sentence Count
Number of sentences, determined by sentence-ending punctuation (`.`, `!`, `?`).

### Byte Size
Total size of the text in bytes. May differ from character count for Unicode characters.

## Use Cases
- **Content Management**: Validating text length limits
- **SEO Analysis**: Checking content length for optimization
- **Social Media**: Ensuring posts fit platform character limits
- **Documentation**: Analyzing documentation size and complexity
- **Data Processing**: Understanding text data characteristics
- **Translation Services**: Estimating translation costs based on word count
- **Academic Writing**: Meeting word count requirements
- **Performance Optimization**: Understanding memory usage of text data

## Notes
- Unicode characters (like emojis) may have different byte sizes than character counts
- Sentence detection is based on punctuation and may not be perfect for all text types
- Word counting follows standard whitespace-based tokenization