# URL Building

Build URLs from individual components including scheme, host, path, query parameters, and fragments.

## Tool: `mcp_dev_utilities_mcp_network_url_build`

### Example 1: API URL with Query Parameters
**Input:**
```
Scheme: https
Host: api.example.com
Path: /v1/users
Query: page=1&limit=10
```
**Output:**
```json
{
  "data": {
    "url": "https://api.example.com/v1/users?limit=10&page=1"
  },
  "success": true
}
```

### Example 2: Local Development URL with Port
**Input:**
```
Scheme: http
Host: localhost
Path: /api/auth
Port: 3000
```
**Output:**
```json
{
  "data": {
    "url": "http://localhost/api/auth"
  },
  "success": true
}
```

### Example 3: Search URL with Fragment
**Input:**
```
Scheme: https
Host: example.com
Path: /search
Query: q=test&category=all
Fragment: results
```
**Output:**
```json
{
  "data": {
    "url": "https://example.com/search?category=all&q=test#results"
  },
  "success": true
}
```

### Example 4: Secure URL with Custom Port
**Input:**
```
Scheme: https
Host: secure.example.com
Path: /
Port: 8443
```
**Output:**
```json
{
  "data": {
    "url": "https://secure.example.com/"
  },
  "success": true
}
```

### Example 5: Minimal URL
**Input:**
```
Scheme: https
Host: api.service.com
```
**Output:**
```json
{
  "data": {
    "url": "https://api.service.com"
  },
  "success": true
}
```

## Required Parameters

### Scheme (Required)
- **Description**: Protocol to use for the URL
- **Examples**: `http`, `https`, `ftp`, `file`
- **Format**: Lowercase string without `://`
- **Common values**: `https` (recommended), `http`

### Host (Required)
- **Description**: Domain name or IP address
- **Examples**: `example.com`, `api.service.com`, `192.168.1.1`
- **Format**: Domain name or IP address without port
- **Note**: Port is specified separately

## Optional Parameters

### Path
- **Description**: Path component of the URL
- **Default**: Empty (results in no path)
- **Format**: Should start with `/` for absolute paths
- **Examples**: `/`, `/api/v1`, `/users/profile`

### Port
- **Description**: Port number for the connection
- **Default**: Standard port for the scheme (80 for HTTP, 443 for HTTPS)
- **Format**: Integer
- **Note**: May not appear in final URL if it's the default port

### Query
- **Description**: Query string parameters
- **Format**: `key1=value1&key2=value2`
- **Encoding**: Values should be URL-encoded if needed
- **Examples**: `page=1&limit=10`, `q=search%20term`

### Fragment
- **Description**: Fragment identifier (anchor)
- **Format**: String without the `#` prefix
- **Examples**: `section1`, `results`, `top`
- **Use case**: Client-side navigation, page anchors

## URL Building Patterns

### REST API URLs
```javascript
// Build API endpoint URL
const apiUrl = buildUrl({
  scheme: 'https',
  host: 'api.example.com',
  path: '/v1/users/123',
  query: 'include=profile&fields=name,email'
});
// Result: "https://api.example.com/v1/users/123?include=profile&fields=name,email"
```

### Search URLs
```javascript
// Build search URL with parameters
const searchUrl = buildUrl({
  scheme: 'https',
  host: 'search.example.com',
  path: '/results',
  query: 'q=javascript&type=web&page=2'
});
// Result: "https://search.example.com/results?q=javascript&type=web&page=2"
```

### CDN URLs
```javascript
// Build CDN asset URL
const assetUrl = buildUrl({
  scheme: 'https',
  host: 'cdn.example.com',
  path: '/assets/images/logo.png',
  query: 'v=1.2.3&format=webp'
});
// Result: "https://cdn.example.com/assets/images/logo.png?v=1.2.3&format=webp"
```

## Use Cases

### Dynamic API URL Generation
```javascript
// Build API URLs dynamically
function buildApiUrl(endpoint, params = {}) {
  const queryString = Object.entries(params)
    .map(([key, value]) => `${key}=${encodeURIComponent(value)}`)
    .join('&');
    
  return buildUrl({
    scheme: 'https',
    host: 'api.example.com',
    path: `/v1/${endpoint}`,
    query: queryString
  });
}

const usersUrl = buildApiUrl('users', { page: 1, limit: 10 });
// Result: "https://api.example.com/v1/users?page=1&limit=10"
```

### Configuration-Based URL Building
```javascript
// Build URLs from configuration
const config = {
  api: {
    scheme: 'https',
    host: 'api.production.com',
    port: 443
  }
};

const endpoint = buildUrl({
  scheme: config.api.scheme,
  host: config.api.host,
  path: '/health',
  port: config.api.port
});
```

### URL Modification
```javascript
// Modify existing URL components
const originalComponents = parseUrl('https://example.com/old-path');
const newUrl = buildUrl({
  ...originalComponents,
  path: '/new-path',
  query: 'updated=true'
});
```

### Webhook URL Generation
```javascript
// Generate webhook URLs with signatures
function generateWebhookUrl(endpoint, payload) {
  const signature = generateSignature(payload);
  
  return buildUrl({
    scheme: 'https',
    host: 'webhooks.example.com',
    path: `/hooks/${endpoint}`,
    query: `signature=${signature}&timestamp=${Date.now()}`
  });
}
```

### Multi-Environment URL Building
```javascript
// Build URLs for different environments
const environments = {
  development: { host: 'localhost', port: 3000, scheme: 'http' },
  staging: { host: 'staging.example.com', scheme: 'https' },
  production: { host: 'api.example.com', scheme: 'https' }
};

function buildEnvironmentUrl(env, path, query) {
  const config = environments[env];
  return buildUrl({
    scheme: config.scheme,
    host: config.host,
    port: config.port,
    path: path,
    query: query
  });
}
```

## Query String Handling

### Manual Query Building
```javascript
// Build query string manually
const params = { page: 1, limit: 10, sort: 'name' };
const queryString = Object.entries(params)
  .map(([key, value]) => `${key}=${encodeURIComponent(value)}`)
  .join('&');

const url = buildUrl({
  scheme: 'https',
  host: 'api.example.com',
  path: '/users',
  query: queryString
});
```

### Array Parameters
```javascript
// Handle array parameters
const tags = ['javascript', 'nodejs', 'api'];
const queryString = tags.map(tag => `tags=${encodeURIComponent(tag)}`).join('&');

const url = buildUrl({
  scheme: 'https',
  host: 'example.com',
  path: '/search',
  query: queryString
});
// Result: "https://example.com/search?tags=javascript&tags=nodejs&tags=api"
```

### Special Characters in Query
```javascript
// Handle special characters
const searchTerm = 'hello world & more';
const queryString = `q=${encodeURIComponent(searchTerm)}`;

const url = buildUrl({
  scheme: 'https',
  host: 'search.example.com',
  path: '/results',
  query: queryString
});
// Result: "https://search.example.com/results?q=hello%20world%20%26%20more"
```

## Best Practices

### Input Validation
```javascript
function buildValidatedUrl(components) {
  // Validate required components
  if (!components.scheme || !components.host) {
    throw new Error('Scheme and host are required');
  }
  
  // Validate scheme
  const validSchemes = ['http', 'https', 'ftp'];
  if (!validSchemes.includes(components.scheme)) {
    throw new Error('Invalid scheme');
  }
  
  // Ensure path starts with /
  if (components.path && !components.path.startsWith('/')) {
    components.path = '/' + components.path;
  }
  
  return buildUrl(components);
}
```

### URL Encoding
```javascript
// Always encode query parameters
function buildUrlWithParams(base, params) {
  const queryString = Object.entries(params)
    .map(([key, value]) => 
      `${encodeURIComponent(key)}=${encodeURIComponent(value)}`
    )
    .join('&');
    
  return buildUrl({
    ...base,
    query: queryString
  });
}
```

### Environment Configuration
```javascript
// Use environment-specific configuration
const urlConfig = {
  scheme: process.env.API_SCHEME || 'https',
  host: process.env.API_HOST || 'api.example.com',
  port: process.env.API_PORT ? parseInt(process.env.API_PORT) : undefined
};

function buildApiUrl(path, query) {
  return buildUrl({
    ...urlConfig,
    path: path,
    query: query
  });
}
```

### Error Handling
```javascript
function safeUrlBuild(components) {
  try {
    return buildUrl(components);
  } catch (error) {
    console.error('Failed to build URL:', error);
    return null;
  }
}
```

## Common Patterns

### API Client Pattern
```javascript
class ApiClient {
  constructor(baseUrl) {
    const parsed = parseUrl(baseUrl);
    this.scheme = parsed.scheme;
    this.host = parsed.host;
    this.basePath = parsed.path;
  }
  
  buildEndpointUrl(endpoint, params = {}) {
    const queryString = new URLSearchParams(params).toString();
    
    return buildUrl({
      scheme: this.scheme,
      host: this.host,
      path: `${this.basePath}/${endpoint}`,
      query: queryString
    });
  }
}
```

### URL Template Pattern
```javascript
function urlTemplate(template, variables) {
  let path = template;
  Object.entries(variables).forEach(([key, value]) => {
    path = path.replace(`{${key}}`, encodeURIComponent(value));
  });
  
  return buildUrl({
    scheme: 'https',
    host: 'api.example.com',
    path: path
  });
}

// Usage: urlTemplate('/users/{userId}/posts/{postId}', { userId: 123, postId: 456 })
```

### Pagination URL Pattern
```javascript
function buildPaginationUrl(baseUrl, page, limit) {
  const parsed = parseUrl(baseUrl);
  
  return buildUrl({
    scheme: parsed.scheme,
    host: parsed.host,
    path: parsed.path,
    query: `page=${page}&limit=${limit}`
  });
}
```