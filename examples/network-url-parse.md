# URL Parsing

Parse URLs into their component parts including scheme, host, path, query parameters, and fragments.

## Tool: `mcp_dev_utilities_mcp_network_url_parse`

### Example 1: Complex API URL with Query Parameters
**Input:**
```
URL: "https://api.example.com:8080/v1/users?page=1&limit=10#results"
```
**Output:**
```json
{
  "data": {
    "scheme": "https",
    "host": "api.example.com:8080",
    "path": "/v1/users",
    "query": {
      "limit": "10",
      "page": "1"
    },
    "fragment": "results"
  },
  "success": true
}
```

### Example 2: Local Development URL
**Input:**
```
URL: "http://localhost:3000/api/auth/login"
```
**Output:**
```json
{
  "data": {
    "scheme": "http",
    "host": "localhost:3000",
    "path": "/api/auth/login",
    "query": {},
    "fragment": ""
  },
  "success": true
}
```

### Example 3: FTP URL with Authentication
**Input:**
```
URL: "ftp://user:pass@files.example.com/documents/file.txt"
```
**Output:**
```json
{
  "data": {
    "scheme": "ftp",
    "host": "user:pass@files.example.com",
    "path": "/documents/file.txt",
    "query": {},
    "fragment": ""
  },
  "success": true
}
```

### Example 4: Search URL with Multiple Parameters
**Input:**
```
URL: "https://example.com/search?q=hello%20world&category=all&sort=date"
```
**Output:**
```json
{
  "data": {
    "scheme": "https",
    "host": "example.com",
    "path": "/search",
    "query": {
      "category": "all",
      "q": "hello world",
      "sort": "date"
    },
    "fragment": ""
  },
  "success": true
}
```

### Example 5: HTTPS URL with Subdomain and Port
**Input:**
```
URL: "https://subdomain.example.com:443/path/to/resource"
```
**Output:**
```json
{
  "data": {
    "scheme": "https",
    "host": "subdomain.example.com:443",
    "path": "/path/to/resource",
    "query": {},
    "fragment": ""
  },
  "success": true
}
```

## URL Components Explained

### Scheme
- **Description**: Protocol used to access the resource
- **Examples**: `http`, `https`, `ftp`, `file`, `mailto`
- **Case**: Typically lowercase
- **Required**: Yes

### Host
- **Description**: Domain name or IP address, optionally with port
- **Format**: `hostname[:port]` or `username:password@hostname[:port]`
- **Examples**: 
  - `example.com`
  - `api.example.com:8080`
  - `user:pass@ftp.example.com`
- **Required**: Yes for most schemes

### Path
- **Description**: Hierarchical path to the resource
- **Format**: Starts with `/` for absolute paths
- **Examples**: `/`, `/api/v1/users`, `/path/to/file.html`
- **Encoding**: URL-encoded special characters
- **Default**: `/` if not specified

### Query
- **Description**: Key-value pairs for parameters
- **Format**: `key1=value1&key2=value2`
- **Parsing**: Automatically parsed into object
- **Encoding**: URL-decoded automatically
- **Optional**: Yes

### Fragment
- **Description**: Reference to a section within the resource
- **Format**: Text after `#` symbol
- **Examples**: `section1`, `results`, `top`
- **Client-side**: Typically handled by client, not sent to server
- **Optional**: Yes

## Common URL Patterns

### REST API URLs
```
https://api.example.com/v1/users/123
├── scheme: https
├── host: api.example.com
├── path: /v1/users/123
├── query: {}
└── fragment: ""
```

### Search URLs
```
https://search.example.com/results?q=javascript&type=web&page=2
├── scheme: https
├── host: search.example.com
├── path: /results
├── query: { q: "javascript", type: "web", page: "2" }
└── fragment: ""
```

### Single Page Application URLs
```
https://app.example.com/dashboard#/users/profile
├── scheme: https
├── host: app.example.com
├── path: /dashboard
├── query: {}
└── fragment: "/users/profile"
```

## Use Cases

### API Development
```javascript
// Parse incoming request URLs
const urlComponents = parseUrl(request.url);
const apiVersion = urlComponents.path.split('/')[1]; // Extract version
const resource = urlComponents.path.split('/')[2]; // Extract resource
const filters = urlComponents.query; // Extract query parameters
```

### URL Validation
```javascript
// Validate URL structure
const parsed = parseUrl(userInput);
if (parsed.scheme !== 'https') {
  throw new Error('Only HTTPS URLs are allowed');
}
if (!parsed.host.includes('trusted-domain.com')) {
  throw new Error('Untrusted domain');
}
```

### Query Parameter Processing
```javascript
// Extract and process query parameters
const parsed = parseUrl(request.url);
const page = parseInt(parsed.query.page) || 1;
const limit = parseInt(parsed.query.limit) || 10;
const sortBy = parsed.query.sort || 'created_at';
```

### URL Rewriting
```javascript
// Modify URL components
const parsed = parseUrl(originalUrl);
parsed.scheme = 'https'; // Force HTTPS
parsed.host = 'cdn.example.com'; // Change host
parsed.query.version = '2'; // Add version parameter
```

### Security Analysis
```javascript
// Check for suspicious URLs
const parsed = parseUrl(suspiciousUrl);
if (parsed.host.includes('malicious-site.com')) {
  blockRequest();
}
if (parsed.path.includes('../')) {
  // Potential directory traversal
  blockRequest();
}
```

## Query Parameter Handling

### Automatic URL Decoding
```javascript
// Input: "q=hello%20world&category=tech%26science"
// Output: { q: "hello world", category: "tech&science" }
```

### Multiple Values
```javascript
// URLs with repeated parameters
// Input: "tags=javascript&tags=nodejs&tags=api"
// Note: This tool returns the last value for repeated keys
// Output: { tags: "api" }
```

### Empty Values
```javascript
// Parameters without values
// Input: "debug&verbose=true&test="
// Output: { debug: "", verbose: "true", test: "" }
```

## Best Practices

### Input Validation
- Always validate parsed URLs before use
- Check scheme against allowed protocols
- Validate host against trusted domains
- Sanitize path components

### Security Considerations
- Never trust user-provided URLs without validation
- Check for directory traversal attempts (`../`)
- Validate against SSRF (Server-Side Request Forgery)
- Use allowlists for trusted domains

### Performance
- Cache parsed results for frequently accessed URLs
- Use parsed components instead of regex parsing
- Consider URL normalization for comparison

### Error Handling
```javascript
try {
  const parsed = parseUrl(userUrl);
  // Process parsed URL
} catch (error) {
  console.error('Invalid URL:', userUrl);
  // Handle invalid URL
}
```

## URL Normalization

### Common Variations
```javascript
// These URLs are functionally equivalent:
"https://example.com/path"
"https://example.com:443/path"
"https://EXAMPLE.COM/path"
"https://example.com/path/"
```

### Port Handling
- Default ports are often omitted in display
- HTTP: port 80 (default)
- HTTPS: port 443 (default)
- FTP: port 21 (default)

### Case Sensitivity
- Scheme: Case-insensitive (usually lowercase)
- Host: Case-insensitive (usually lowercase)
- Path: Case-sensitive
- Query: Case-sensitive
- Fragment: Case-sensitive

## Integration Examples

### Express.js Route Handler
```javascript
app.get('/proxy', (req, res) => {
  const targetUrl = req.query.url;
  const parsed = parseUrl(targetUrl);
  
  if (parsed.scheme !== 'https') {
    return res.status(400).json({ error: 'Only HTTPS URLs allowed' });
  }
  
  // Proxy request to parsed.host + parsed.path
});
```

### URL Builder Integration
```javascript
// Parse existing URL and modify
const parsed = parseUrl(baseUrl);
parsed.query.timestamp = Date.now();
parsed.query.signature = generateSignature(parsed.path);

// Rebuild URL with modifications
const modifiedUrl = buildUrl(parsed);
```

### Analytics and Logging
```javascript
// Extract URL components for analytics
const parsed = parseUrl(request.url);
analytics.track('page_view', {
  domain: parsed.host,
  path: parsed.path,
  query_params: Object.keys(parsed.query),
  has_fragment: !!parsed.fragment
});
```