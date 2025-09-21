# URL Encoding and Decoding

Encode and decode content using URL percent encoding for safe transmission in URLs.

## Tools: `mcp_dev_utilities_mcp_transform_url_encode` & `mcp_dev_utilities_mcp_transform_url_decode`

## URL Encoding Examples

### Example 1: Basic Text with Spaces
**Input:**
```
Content: "Hello World!"
```
**Output:**
```json
{
  "success": true,
  "data": {
    "result": "Hello+World%21"
  }
}
```

### Example 2: Email Address
**Input:**
```
Content: "user@example.com"
```
**Output:**
```json
{
  "success": true,
  "data": {
    "result": "user%40example.com"
  }
}
```

### Example 3: Special Characters
**Input:**
```
Content: "Special chars: !@#$%^&*()_+-=[]{}|;:,.<>?"
```
**Output:**
```json
{
  "success": true,
  "data": {
    "result": "Special+chars%3A+%21%40%23%24%25%5E%26%2A%28%29_%2B-%3D%5B%5D%7B%7D%7C%3B%3A%2C.%3C%3E%3F"
  }
}
```

### Example 4: Search Query
**Input:**
```
Content: "search query with spaces"
```
**Output:**
```json
{
  "success": true,
  "data": {
    "result": "search+query+with+spaces"
  }
}
```

### Example 5: Unicode Characters
**Input:**
```
Content: "café naïve résumé"
```
**Output:**
```json
{
  "success": true,
  "data": {
    "result": "caf%C3%A9+na%C3%AFve+r%C3%A9sum%C3%A9"
  }
}
```

## URL Decoding Examples

### Example 1: Basic Text with Spaces
**Input:**
```
Content: "Hello+World%21"
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

### Example 2: Email Address
**Input:**
```
Content: "user%40example.com"
```
**Output:**
```json
{
  "success": true,
  "data": {
    "result": "user@example.com"
  }
}
```

### Example 3: Special Characters
**Input:**
```
Content: "Special+chars%3A+%21%40%23%24%25%5E%26%2A%28%29_%2B-%3D%5B%5D%7B%7D%7C%3B%3A%2C.%3C%3E%3F"
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

### Example 4: Search Query
**Input:**
```
Content: "search+query+with+spaces"
```
**Output:**
```json
{
  "success": true,
  "data": {
    "result": "search query with spaces"
  }
}
```

### Example 5: Unicode Characters
**Input:**
```
Content: "caf%C3%A9+na%C3%AFve+r%C3%A9sum%C3%A9"
```
**Output:**
```json
{
  "success": true,
  "data": {
    "result": "café naïve résumé"
  }
}
```

## URL Encoding Rules

### Characters That Must Be Encoded
- **Space**: `%20` or `+`
- **Reserved characters**: `!*'();:@&=+$,/?#[]`
- **Unsafe characters**: `<>\"{}|\\^~[]`\`
- **Non-ASCII characters**: Encoded as UTF-8 bytes

### Characters That Don't Need Encoding
- **Alphanumeric**: `A-Z`, `a-z`, `0-9`
- **Safe characters**: `-`, `_`, `.`, `~`

### Common Encodings
| Character | Encoded | Description |
|-----------|---------|-------------|
| Space     | `%20` or `+` | Space character |
| `!`       | `%21`   | Exclamation mark |
| `@`       | `%40`   | At symbol |
| `#`       | `%23`   | Hash/pound |
| `$`       | `%24`   | Dollar sign |
| `%`       | `%25`   | Percent sign |
| `&`       | `%26`   | Ampersand |
| `+`       | `%2B`   | Plus sign |
| `=`       | `%3D`   | Equals sign |
| `?`       | `%3F`   | Question mark |

## Use Cases

### Web Development
- Form data submission
- Query parameter values
- URL path components
- Search functionality

### API Development
- Query string parameters
- Path parameters with special characters
- Request body encoding (form data)
- Webhook URLs

### Data Processing
- Log file analysis
- URL parsing and manipulation
- Configuration file processing
- Data import/export

### Security
- Preventing URL injection attacks
- Sanitizing user input in URLs
- Safe parameter transmission
- XSS prevention

## Best Practices

### When to Encode
- Always encode user input in URLs
- Encode query parameter values
- Encode path segments with special characters
- Encode form data values

### When Not to Encode
- Don't double-encode already encoded data
- Don't encode the entire URL structure
- Don't encode URL schemes or domains
- Don't encode path separators (`/`)

### Common Mistakes
- Encoding the entire URL instead of just parameters
- Not encoding user input leading to broken URLs
- Double-encoding data
- Using wrong encoding for the context (URL vs. HTML)

## URL Structure and Encoding

```
https://example.com/path/to/resource?param1=value1&param2=value2#fragment
```

- **Scheme**: `https://` - Never encode
- **Domain**: `example.com` - Never encode
- **Path**: `/path/to/resource` - Encode individual segments if needed
- **Query**: `?param1=value1&param2=value2` - Encode parameter values
- **Fragment**: `#fragment` - Encode if needed