# Base64 Encoding and Decoding

Encode and decode content using Base64 encoding, with support for both standard and URL-safe variants.

## Tools: `mcp_dev_utilities_mcp_transform_base64_encode` & `mcp_dev_utilities_mcp_transform_base64_decode`

## Base64 Encoding Examples

### Example 1: Basic Text Encoding
**Input:**
```
Content: "Hello World!"
```
**Output:**
```json
{
  "success": true,
  "data": {
    "result": "SGVsbG8gV29ybGQh"
  }
}
```

### Example 2: JSON Data with URL-Safe Encoding
**Input:**
```
Content: "{\"user\": \"john\", \"role\": \"admin\"}"
URL Safe: true
```
**Output:**
```json
{
  "success": true,
  "data": {
    "result": "eyJ1c2VyIjogImpvaG4iLCAicm9sZSI6ICJhZG1pbiJ9"
  }
}
```

### Example 3: Special Characters Encoding
**Input:**
```
Content: "Special chars: !@#$%^&*()_+-=[]{}|;:,.<>?"
```
**Output:**
```json
{
  "success": true,
  "data": {
    "result": "U3BlY2lhbCBjaGFyczogIUAjJCVeJiooKV8rLT1bXXt9fDs6LC48Pj8="
  }
}
```

### Example 4: Multi-line Content Encoding
**Input:**
```
Content: "Multi-line content\nwith newlines\nand tabs\there"
```
**Output:**
```json
{
  "success": true,
  "data": {
    "result": "TXVsdGktbGluZSBjb250ZW50CndpdGggbmV3bGluZXMKYW5kIHRhYnMJaGVyZQ=="
  }
}
```

## Base64 Decoding Examples

### Example 1: Basic Text Decoding
**Input:**
```
Content: "SGVsbG8gV29ybGQh"
```
**Output:**
```json
{
  "success": true,
  "data": {
    "result": "Hello World!"
  }
}
```

### Example 2: JSON Data with URL-Safe Decoding
**Input:**
```
Content: "eyJ1c2VyIjogImpvaG4iLCAicm9sZSI6ICJhZG1pbiJ9"
URL Safe: true
```
**Output:**
```json
{
  "success": true,
  "data": {
    "result": "{\"user\": \"john\", \"role\": \"admin\"}"
  }
}
```

### Example 3: Special Characters Decoding
**Input:**
```
Content: "U3BlY2lhbCBjaGFyczogIUAjJCVeJiooKV8rLT1bXXt9fDs6LC48Pj8="
```
**Output:**
```json
{
  "success": true,
  "data": {
    "result": "Special chars: !@#$%^&*()_+-=[]{}|;:,.<>?"
  }
}
```

### Example 4: Multi-line Content Decoding
**Input:**
```
Content: "TXVsdGktbGluZSBjb250ZW50CndpdGggbmV3bGluZXMKYW5kIHRhYnMJaGVyZQ=="
```
**Output:**
```json
{
  "success": true,
  "data": {
    "result": "Multi-line content\nwith newlines\nand tabs\there"
  }
}
```

### Example 5: Simple Word Decoding
**Input:**
```
Content: "aW52YWxpZA=="
```
**Output:**
```json
{
  "success": true,
  "data": {
    "result": "invalid"
  }
}
```

## Base64 Variants

### Standard Base64
- Uses characters: `A-Z`, `a-z`, `0-9`, `+`, `/`
- Padding character: `=`
- Used in email attachments, data URLs, etc.

### URL-Safe Base64
- Uses characters: `A-Z`, `a-z`, `0-9`, `-`, `_`
- Padding character: `=` (often omitted)
- Safe for use in URLs and filenames

## Use Cases

### Web Development
- Encoding binary data in JSON
- Data URLs for images
- Basic authentication headers
- Storing binary data in text formats

### API Development
- Encoding request/response payloads
- Token generation and storage
- File upload handling
- Data serialization

### Security
- Encoding sensitive data (not encryption!)
- JWT token components
- API key formatting
- Session data storage

### Data Processing
- Binary data transmission over text protocols
- Database storage of binary data
- Configuration file encoding
- Log data formatting

## Important Notes

### Security Considerations
- Base64 is **encoding**, not **encryption**
- Data is easily decodable by anyone
- Do not use for sensitive data protection
- Use proper encryption for security needs

### Performance
- Base64 increases data size by ~33%
- Consider compression before encoding for large data
- URL-safe variant is preferred for web applications
- Padding may be optional in some contexts

### Common Pitfalls
- Confusing encoding with encryption
- Not handling padding correctly
- Using wrong variant for the context
- Assuming Base64 provides security