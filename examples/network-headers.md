# HTTP Headers Inspection

Inspect HTTP headers of URLs to analyze server responses, security headers, and configuration details.

## Tool: `mcp_dev_utilities_mcp_network_headers_inspect`

### Example 1: API Endpoint Headers
**Input:**
```
URL: "https://httpbin.org/get"
```
**Output:**
```json
{
  "data": {
    "url": "https://httpbin.org/get",
    "statusCode": 200,
    "headers": {
      "Access-Control-Allow-Credentials": "true",
      "Access-Control-Allow-Origin": "*",
      "Content-Length": "276",
      "Content-Type": "application/json",
      "Date": "Sun, 21 Sep 2025 05:44:29 GMT",
      "Server": "gunicorn/19.9.0"
    }
  },
  "success": true
}
```

### Example 2: Redirect Response
**Input:**
```
URL: "https://google.com"
```
**Output:**
```json
{
  "data": {
    "url": "https://google.com",
    "statusCode": 301,
    "headers": {
      "Alt-Svc": "h3=\":443\"; ma=2592000,h3-29=\":443\"; ma=2592000",
      "Cache-Control": "public, max-age=2592000",
      "Content-Length": "220",
      "Content-Security-Policy-Report-Only": "object-src 'none';base-uri 'self';script-src 'nonce-PVpo7YGZC4i-9S6mwKTQDQ' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp",
      "Content-Type": "text/html; charset=UTF-8",
      "Date": "Sun, 21 Sep 2025 05:44:32 GMT",
      "Expires": "Tue, 21 Oct 2025 05:44:32 GMT",
      "Location": "https://www.google.com/",
      "Server": "gws",
      "X-Frame-Options": "SAMEORIGIN",
      "X-Xss-Protection": "0"
    }
  },
  "success": true
}
```

### Example 3: Error Response
**Input:**
```
URL: "https://httpbin.org/status/404"
```
**Output:**
```json
{
  "data": {
    "url": "https://httpbin.org/status/404",
    "statusCode": 404,
    "headers": {
      "Access-Control-Allow-Credentials": "true",
      "Access-Control-Allow-Origin": "*",
      "Content-Length": "0",
      "Content-Type": "text/html; charset=utf-8",
      "Date": "Sun, 21 Sep 2025 05:44:36 GMT",
      "Server": "gunicorn/19.9.0"
    }
  },
  "success": true
}
```

### Example 4: GitHub API Headers
**Input:**
```
URL: "https://api.github.com"
```
**Output:**
```json
{
  "data": {
    "url": "https://api.github.com",
    "statusCode": 200,
    "headers": {
      "Accept-Ranges": "bytes",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Expose-Headers": "ETag, Link, Location, Retry-After, X-GitHub-OTP, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Used, X-RateLimit-Resource, X-RateLimit-Reset, X-OAuth-Scopes, X-Accepted-OAuth-Scopes, X-Poll-Interval, X-GitHub-Media-Type, X-GitHub-SSO, X-GitHub-Request-Id, Deprecation, Sunset",
      "Cache-Control": "public, max-age=60, s-maxage=60",
      "Content-Security-Policy": "default-src 'none'",
      "Content-Type": "application/json; charset=utf-8",
      "Date": "Sun, 21 Sep 2025 05:44:34 GMT",
      "Etag": "\"cb8c56af7fcef970136a8acacba4e16ea32ab6762dbaaddf6909fae9db2c9f5e\"",
      "Referrer-Policy": "origin-when-cross-origin, strict-origin-when-cross-origin",
      "Server": "github.com",
      "Strict-Transport-Security": "max-age=31536000; includeSubdomains; preload",
      "Vary": "Accept,Accept-Encoding, Accept, X-Requested-With",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "deny",
      "X-Github-Api-Version-Selected": "2022-11-28",
      "X-Github-Media-Type": "github.v3; format=json",
      "X-Github-Request-Id": "E36D:1E1D2B:5D5498A:6058B0A:68CF90C7",
      "X-Ratelimit-Limit": "60",
      "X-Ratelimit-Remaining": "57",
      "X-Ratelimit-Reset": "1758434204",
      "X-Ratelimit-Resource": "core",
      "X-Ratelimit-Used": "3",
      "X-Xss-Protection": "0"
    }
  },
  "success": true
}
```

### Example 5: Redirect Chain
**Input:**
```
URL: "https://httpbin.org/redirect/3"
```
**Output:**
```json
{
  "data": {
    "url": "https://httpbin.org/redirect/3",
    "statusCode": 302,
    "headers": {
      "Access-Control-Allow-Credentials": "true",
      "Access-Control-Allow-Origin": "*",
      "Content-Length": "247",
      "Content-Type": "text/html; charset=utf-8",
      "Date": "Sun, 21 Sep 2025 05:44:42 GMT",
      "Location": "/relative-redirect/2",
      "Server": "gunicorn/19.9.0"
    }
  },
  "success": true
}
```

## HTTP Status Codes

### Success Codes (2xx)
- **200 OK**: Request successful
- **201 Created**: Resource created successfully
- **204 No Content**: Success with no response body

### Redirection Codes (3xx)
- **301 Moved Permanently**: Permanent redirect
- **302 Found**: Temporary redirect
- **304 Not Modified**: Cached version is still valid

### Client Error Codes (4xx)
- **400 Bad Request**: Invalid request syntax
- **401 Unauthorized**: Authentication required
- **403 Forbidden**: Access denied
- **404 Not Found**: Resource not found
- **429 Too Many Requests**: Rate limit exceeded

### Server Error Codes (5xx)
- **500 Internal Server Error**: Server error
- **502 Bad Gateway**: Invalid response from upstream
- **503 Service Unavailable**: Server temporarily unavailable

## Important HTTP Headers

### Security Headers

#### Content Security Policy (CSP)
```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'
```
- **Purpose**: Prevent XSS attacks
- **Controls**: Script sources, styles, images, etc.

#### Strict Transport Security (HSTS)
```
Strict-Transport-Security: max-age=31536000; includeSubdomains; preload
```
- **Purpose**: Force HTTPS connections
- **Parameters**: max-age, includeSubdomains, preload

#### X-Frame-Options
```
X-Frame-Options: DENY
X-Frame-Options: SAMEORIGIN
```
- **Purpose**: Prevent clickjacking attacks
- **Values**: DENY, SAMEORIGIN, ALLOW-FROM

#### X-Content-Type-Options
```
X-Content-Type-Options: nosniff
```
- **Purpose**: Prevent MIME type sniffing
- **Value**: nosniff (only valid value)

### Caching Headers

#### Cache-Control
```
Cache-Control: public, max-age=3600, s-maxage=7200
```
- **Directives**: public, private, no-cache, max-age
- **Purpose**: Control caching behavior

#### ETag
```
ETag: "33a64df551425fcc55e4d42a148795d9f25f89d4"
```
- **Purpose**: Resource version identifier
- **Use**: Conditional requests, cache validation

#### Expires
```
Expires: Wed, 21 Oct 2025 07:28:00 GMT
```
- **Purpose**: Absolute expiration time
- **Format**: HTTP date format

### CORS Headers

#### Access-Control-Allow-Origin
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Origin: https://example.com
```
- **Purpose**: Allow cross-origin requests
- **Values**: *, specific origins

#### Access-Control-Allow-Methods
```
Access-Control-Allow-Methods: GET, POST, PUT, DELETE
```
- **Purpose**: Allowed HTTP methods for CORS
- **Values**: Comma-separated method list

## Use Cases

### Security Audit
```javascript
// Analyze security headers
function analyzeSecurityHeaders(headers) {
  const securityAnalysis = {
    hsts: !!headers['Strict-Transport-Security'],
    csp: !!headers['Content-Security-Policy'],
    xFrameOptions: !!headers['X-Frame-Options'],
    xContentTypeOptions: !!headers['X-Content-Type-Options'],
    xssProtection: !!headers['X-Xss-Protection']
  };
  
  const score = Object.values(securityAnalysis).filter(Boolean).length;
  
  return {
    ...securityAnalysis,
    score: `${score}/5`,
    grade: score >= 4 ? 'A' : score >= 3 ? 'B' : score >= 2 ? 'C' : 'F'
  };
}
```

### Performance Analysis
```javascript
// Analyze performance-related headers
function analyzePerformanceHeaders(headers) {
  const cacheControl = headers['Cache-Control'] || '';
  const hasETag = !!headers['ETag'];
  const hasExpires = !!headers['Expires'];
  const contentEncoding = headers['Content-Encoding'] || '';
  
  return {
    caching: {
      hasCacheControl: !!cacheControl,
      hasETag,
      hasExpires,
      maxAge: cacheControl.match(/max-age=(\d+)/)?.[1] || null
    },
    compression: {
      enabled: !!contentEncoding,
      type: contentEncoding
    },
    cdn: {
      detected: !!(headers['CF-Ray'] || headers['X-Amz-Cf-Id'] || headers['X-Fastly-Request-ID'])
    }
  };
}
```

### API Health Check
```javascript
// Monitor API endpoint health
async function checkAPIHealth(url) {
  const inspection = await inspectHeaders(url);
  
  const isHealthy = inspection.statusCode >= 200 && inspection.statusCode < 400;
  const responseTime = inspection.headers['X-Response-Time'] || 'unknown';
  const rateLimit = {
    limit: inspection.headers['X-Ratelimit-Limit'],
    remaining: inspection.headers['X-Ratelimit-Remaining'],
    reset: inspection.headers['X-Ratelimit-Reset']
  };
  
  return {
    url,
    healthy: isHealthy,
    statusCode: inspection.statusCode,
    responseTime,
    rateLimit,
    server: inspection.headers['Server']
  };
}
```

### CDN Detection
```javascript
// Detect CDN provider from headers
function detectCDN(headers) {
  const cdnIndicators = {
    cloudflare: ['CF-Ray', 'CF-Cache-Status'],
    fastly: ['X-Fastly-Request-ID', 'Fastly-Debug-Digest'],
    cloudfront: ['X-Amz-Cf-Id', 'X-Amz-Cf-Pop'],
    akamai: ['X-Akamai-Request-ID', 'X-Akamai-Transformed'],
    maxcdn: ['X-MaxCDN-Cache-Control'],
    keycdn: ['X-Edge-Location']
  };
  
  for (const [provider, indicators] of Object.entries(cdnIndicators)) {
    if (indicators.some(indicator => headers[indicator])) {
      return {
        provider,
        detected: true,
        headers: indicators.filter(indicator => headers[indicator])
      };
    }
  }
  
  return { provider: null, detected: false };
}
```

### Rate Limit Monitoring
```javascript
// Monitor rate limits across APIs
async function monitorRateLimits(urls) {
  const results = [];
  
  for (const url of urls) {
    const inspection = await inspectHeaders(url);
    const headers = inspection.headers;
    
    results.push({
      url,
      rateLimit: {
        limit: headers['X-Ratelimit-Limit'] || headers['X-Rate-Limit-Limit'],
        remaining: headers['X-Ratelimit-Remaining'] || headers['X-Rate-Limit-Remaining'],
        reset: headers['X-Ratelimit-Reset'] || headers['X-Rate-Limit-Reset'],
        retryAfter: headers['Retry-After']
      },
      status: inspection.statusCode
    });
  }
  
  return results;
}
```

## Security Analysis Patterns

### HTTPS Configuration Check
```javascript
// Verify HTTPS security configuration
function analyzeHTTPSConfig(headers) {
  const hsts = headers['Strict-Transport-Security'];
  const hstsAnalysis = {
    enabled: !!hsts,
    maxAge: hsts?.match(/max-age=(\d+)/)?.[1],
    includeSubdomains: hsts?.includes('includeSubdomains'),
    preload: hsts?.includes('preload')
  };
  
  return {
    hsts: hstsAnalysis,
    grade: hstsAnalysis.enabled && hstsAnalysis.maxAge >= 31536000 ? 'A' : 'F'
  };
}
```

### Content Security Policy Analysis
```javascript
// Analyze CSP configuration
function analyzeCSP(headers) {
  const csp = headers['Content-Security-Policy'] || headers['Content-Security-Policy-Report-Only'];
  
  if (!csp) {
    return { enabled: false, grade: 'F' };
  }
  
  const directives = csp.split(';').map(d => d.trim());
  const analysis = {
    enabled: true,
    reportOnly: !!headers['Content-Security-Policy-Report-Only'],
    directives: directives.length,
    hasDefaultSrc: directives.some(d => d.startsWith('default-src')),
    hasScriptSrc: directives.some(d => d.startsWith('script-src')),
    allowsUnsafeInline: csp.includes("'unsafe-inline'"),
    allowsUnsafeEval: csp.includes("'unsafe-eval'")
  };
  
  return analysis;
}
```

### Cookie Security Analysis
```javascript
// Analyze cookie security settings
function analyzeCookieSecurity(headers) {
  const setCookies = headers['Set-Cookie'] || [];
  const cookies = Array.isArray(setCookies) ? setCookies : [setCookies];
  
  return cookies.map(cookie => ({
    secure: cookie.includes('Secure'),
    httpOnly: cookie.includes('HttpOnly'),
    sameSite: cookie.match(/SameSite=(\w+)/)?.[1] || 'none'
  }));
}
```

## Best Practices

### Error Handling
```javascript
async function safeHeaderInspection(url) {
  try {
    const result = await inspectHeaders(url);
    return {
      success: true,
      data: result
    };
  } catch (error) {
    return {
      success: false,
      error: error.message,
      url
    };
  }
}
```

### Batch Header Analysis
```javascript
async function batchHeaderAnalysis(urls) {
  const promises = urls.map(url => safeHeaderInspection(url));
  const results = await Promise.all(promises);
  
  return results.reduce((acc, result, index) => {
    acc[urls[index]] = result;
    return acc;
  }, {});
}
```

### Header Comparison
```javascript
// Compare headers across environments
async function compareEnvironmentHeaders(environments) {
  const results = {};
  
  for (const [env, url] of Object.entries(environments)) {
    results[env] = await inspectHeaders(url);
  }
  
  // Find differences
  const differences = {};
  const baseEnv = Object.keys(results)[0];
  const baseHeaders = results[baseEnv].headers;
  
  for (const [env, result] of Object.entries(results)) {
    if (env === baseEnv) continue;
    
    differences[env] = {
      missing: [],
      different: [],
      extra: []
    };
    
    // Check for missing or different headers
    for (const [header, value] of Object.entries(baseHeaders)) {
      if (!result.headers[header]) {
        differences[env].missing.push(header);
      } else if (result.headers[header] !== value) {
        differences[env].different.push({
          header,
          base: value,
          current: result.headers[header]
        });
      }
    }
    
    // Check for extra headers
    for (const header of Object.keys(result.headers)) {
      if (!baseHeaders[header]) {
        differences[env].extra.push(header);
      }
    }
  }
  
  return { results, differences };
}
```