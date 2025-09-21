# IP Address Analysis

Analyze IP addresses to determine their version, type, and classification (private, public, loopback).

## Tool: `mcp_dev_utilities_mcp_network_ip_analyze`

### Example 1: Private IPv4 Address
**Input:**
```
IP: "192.168.1.1"
```
**Output:**
```json
{
  "data": {
    "ip": "192.168.1.1",
    "version": 4,
    "isPrivate": true,
    "isPublic": false,
    "isLoopback": false
  },
  "success": true
}
```

### Example 2: Public IPv4 Address (Google DNS)
**Input:**
```
IP: "8.8.8.8"
```
**Output:**
```json
{
  "data": {
    "ip": "8.8.8.8",
    "version": 4,
    "isPrivate": false,
    "isPublic": true,
    "isLoopback": false
  },
  "success": true
}
```

### Example 3: IPv4 Loopback Address
**Input:**
```
IP: "127.0.0.1"
```
**Output:**
```json
{
  "data": {
    "ip": "127.0.0.1",
    "version": 4,
    "isPrivate": false,
    "isPublic": false,
    "isLoopback": true
  },
  "success": true
}
```

### Example 4: Public IPv6 Address (Google DNS)
**Input:**
```
IP: "2001:4860:4860::8888"
```
**Output:**
```json
{
  "data": {
    "ip": "2001:4860:4860::8888",
    "version": 6,
    "isPrivate": false,
    "isPublic": true,
    "isLoopback": false
  },
  "success": true
}
```

### Example 5: IPv6 Loopback Address
**Input:**
```
IP: "::1"
```
**Output:**
```json
{
  "data": {
    "ip": "::1",
    "version": 6,
    "isPrivate": false,
    "isPublic": false,
    "isLoopback": true
  },
  "success": true
}
```

## IP Address Classifications

### IPv4 Address Types

#### Private IPv4 Ranges (RFC 1918)
- **10.0.0.0/8**: `10.0.0.0` to `10.255.255.255` (16,777,216 addresses)
- **172.16.0.0/12**: `172.16.0.0` to `172.31.255.255` (1,048,576 addresses)
- **192.168.0.0/16**: `192.168.0.0` to `192.168.255.255` (65,536 addresses)

#### Special IPv4 Addresses
- **Loopback**: `127.0.0.0/8` (`127.0.0.1` is most common)
- **Link-local**: `169.254.0.0/16` (APIPA addresses)
- **Multicast**: `224.0.0.0/4` to `239.255.255.255`
- **Reserved**: `240.0.0.0/4` to `255.255.255.255`

#### Public IPv4 Addresses
- All other IPv4 addresses not in private or special ranges
- Routable on the public internet
- Assigned by regional internet registries

### IPv6 Address Types

#### Private IPv6 Ranges
- **Unique Local**: `fc00::/7` (similar to IPv4 private addresses)
- **Link-local**: `fe80::/10` (not routable beyond local network)

#### Special IPv6 Addresses
- **Loopback**: `::1` (equivalent to IPv4 127.0.0.1)
- **Unspecified**: `::` (equivalent to IPv4 0.0.0.0)
- **Multicast**: `ff00::/8`

#### Public IPv6 Addresses
- Global unicast addresses (typically `2000::/3`)
- Routable on the public internet

## Use Cases

### Network Security
```javascript
// Validate IP addresses in security contexts
function isSecureIP(ip) {
  const analysis = analyzeIP(ip);
  
  // Block private IPs from external requests (SSRF protection)
  if (analysis.isPrivate) {
    throw new Error('Private IP addresses not allowed');
  }
  
  // Block loopback addresses
  if (analysis.isLoopback) {
    throw new Error('Loopback addresses not allowed');
  }
  
  return analysis.isPublic;
}
```

### Access Control
```javascript
// Allow different access levels based on IP type
function getAccessLevel(clientIP) {
  const analysis = analyzeIP(clientIP);
  
  if (analysis.isLoopback) {
    return 'admin'; // Full access for localhost
  } else if (analysis.isPrivate) {
    return 'internal'; // Internal network access
  } else if (analysis.isPublic) {
    return 'public'; // Limited public access
  }
  
  return 'denied';
}
```

### Load Balancer Configuration
```javascript
// Route traffic based on IP type
function routeRequest(clientIP, request) {
  const analysis = analyzeIP(clientIP);
  
  if (analysis.isPrivate) {
    // Route internal traffic to internal servers
    return routeToInternalServers(request);
  } else {
    // Route public traffic through CDN
    return routeToCDN(request);
  }
}
```

### Logging and Analytics
```javascript
// Categorize traffic in logs
function logRequest(clientIP, request) {
  const analysis = analyzeIP(clientIP);
  
  const logEntry = {
    timestamp: new Date().toISOString(),
    ip: clientIP,
    ipVersion: analysis.version,
    ipType: analysis.isPrivate ? 'private' : 
            analysis.isPublic ? 'public' : 
            analysis.isLoopback ? 'loopback' : 'unknown',
    request: request.url,
    userAgent: request.headers['user-agent']
  };
  
  console.log(JSON.stringify(logEntry));
}
```

### Geolocation Services
```javascript
// Only perform geolocation on public IPs
function getLocationInfo(ip) {
  const analysis = analyzeIP(ip);
  
  if (!analysis.isPublic) {
    return {
      country: 'Unknown',
      city: 'Unknown',
      reason: analysis.isPrivate ? 'Private IP' : 
              analysis.isLoopback ? 'Loopback IP' : 'Special IP'
    };
  }
  
  // Perform geolocation lookup for public IPs
  return performGeolocationLookup(ip);
}
```

## Common IP Address Examples

### IPv4 Examples
```javascript
// Private network examples
analyzeIP('192.168.1.1')    // Home router
analyzeIP('10.0.0.1')       // Corporate network
analyzeIP('172.16.0.1')     // Private subnet

// Public examples
analyzeIP('8.8.8.8')        // Google DNS
analyzeIP('1.1.1.1')        // Cloudflare DNS
analyzeIP('208.67.222.222') // OpenDNS

// Special addresses
analyzeIP('127.0.0.1')      // Localhost
analyzeIP('169.254.1.1')    // Link-local (APIPA)
```

### IPv6 Examples
```javascript
// Public examples
analyzeIP('2001:4860:4860::8888') // Google DNS
analyzeIP('2606:4700:4700::1111') // Cloudflare DNS

// Special addresses
analyzeIP('::1')                   // Localhost
analyzeIP('fe80::1')              // Link-local
analyzeIP('fc00::1')              // Unique local
```

## Security Considerations

### SSRF Protection
```javascript
// Prevent Server-Side Request Forgery
function validateTargetIP(ip) {
  const analysis = analyzeIP(ip);
  
  const blockedTypes = [
    analysis.isPrivate,
    analysis.isLoopback,
    // Add other checks as needed
  ];
  
  if (blockedTypes.some(blocked => blocked)) {
    throw new Error('IP address not allowed for external requests');
  }
  
  return true;
}
```

### Firewall Rules
```javascript
// Generate firewall rules based on IP analysis
function generateFirewallRule(ip, action) {
  const analysis = analyzeIP(ip);
  
  return {
    ip: ip,
    version: `IPv${analysis.version}`,
    type: analysis.isPrivate ? 'private' : 
          analysis.isPublic ? 'public' : 'special',
    action: action,
    rule: `${action.toUpperCase()} ${ip}/32`
  };
}
```

### Rate Limiting
```javascript
// Apply different rate limits based on IP type
function getRateLimit(clientIP) {
  const analysis = analyzeIP(clientIP);
  
  if (analysis.isLoopback) {
    return { requests: 1000, window: 60 }; // High limit for localhost
  } else if (analysis.isPrivate) {
    return { requests: 100, window: 60 };  // Medium limit for internal
  } else {
    return { requests: 10, window: 60 };   // Low limit for public
  }
}
```

## Best Practices

### Input Validation
```javascript
function safeAnalyzeIP(input) {
  // Validate input format
  if (typeof input !== 'string') {
    throw new Error('IP address must be a string');
  }
  
  // Basic format validation
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Regex = /^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$/;
  
  if (!ipv4Regex.test(input) && !ipv6Regex.test(input)) {
    throw new Error('Invalid IP address format');
  }
  
  return analyzeIP(input);
}
```

### Caching Results
```javascript
const ipAnalysisCache = new Map();

function cachedAnalyzeIP(ip) {
  if (ipAnalysisCache.has(ip)) {
    return ipAnalysisCache.get(ip);
  }
  
  const analysis = analyzeIP(ip);
  ipAnalysisCache.set(ip, analysis);
  
  return analysis;
}
```

### Configuration-Based Rules
```javascript
const ipRules = {
  allowPrivate: false,
  allowLoopback: true,
  allowPublic: true,
  blockedRanges: ['192.168.100.0/24', '10.0.1.0/24']
};

function isIPAllowed(ip) {
  const analysis = analyzeIP(ip);
  
  if (analysis.isPrivate && !ipRules.allowPrivate) return false;
  if (analysis.isLoopback && !ipRules.allowLoopback) return false;
  if (analysis.isPublic && !ipRules.allowPublic) return false;
  
  // Check against blocked ranges (would need additional logic)
  return true;
}
```

## Integration Examples

### Express.js Middleware
```javascript
function ipAnalysisMiddleware(req, res, next) {
  const clientIP = req.ip || req.connection.remoteAddress;
  const analysis = analyzeIP(clientIP);
  
  req.ipAnalysis = analysis;
  
  // Add security headers based on IP type
  if (analysis.isPublic) {
    res.set('X-Frame-Options', 'DENY');
    res.set('X-Content-Type-Options', 'nosniff');
  }
  
  next();
}
```

### API Response Enhancement
```javascript
function enhanceResponseWithIPInfo(req, res, data) {
  const analysis = req.ipAnalysis || analyzeIP(req.ip);
  
  return {
    ...data,
    client: {
      ip: analysis.ip,
      version: `IPv${analysis.version}`,
      type: analysis.isPrivate ? 'private' : 
            analysis.isPublic ? 'public' : 'special'
    }
  };
}
```