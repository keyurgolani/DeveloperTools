# Current Time Retrieval

Get the current time in various formats including Unix timestamps, ISO8601, and human-readable formats.

## Tool: `mcp_dev_utilities_mcp_time_now`

### Example 1: All Time Formats (Default)
**Input:**
```
(No parameters - returns all formats)
```
**Output:**
```json
{
  "data": {
    "unixSeconds": 1758433364,
    "unixMilliseconds": 1758433364963,
    "iso8601": "2025-09-21T05:42:44Z",
    "rfc3339": "2025-09-21T05:42:44Z",
    "humanReadable": "2025-09-21 05:42:44 UTC"
  },
  "success": true
}
```

### Example 2: Unix Format Only
**Input:**
```
Format: unix
```
**Output:**
```json
{
  "data": {
    "unixSeconds": 1758433368,
    "unixMilliseconds": 1758433368029,
    "iso8601": "2025-09-21T05:42:48Z",
    "rfc3339": "2025-09-21T05:42:48Z",
    "humanReadable": "2025-09-21 05:42:48 UTC"
  },
  "success": true
}
```

### Example 3: ISO8601 Format
**Input:**
```
Format: iso8601
```
**Output:**
```json
{
  "data": {
    "unixSeconds": 1758433371,
    "unixMilliseconds": 1758433371653,
    "iso8601": "2025-09-21T05:42:51Z",
    "rfc3339": "2025-09-21T05:42:51Z",
    "humanReadable": "2025-09-21 05:42:51 UTC"
  },
  "success": true
}
```

### Example 4: Human-Readable Format
**Input:**
```
Format: human
```
**Output:**
```json
{
  "data": {
    "unixSeconds": 1758433374,
    "unixMilliseconds": 1758433374701,
    "iso8601": "2025-09-21T05:42:54Z",
    "rfc3339": "2025-09-21T05:42:54Z",
    "humanReadable": "2025-09-21 05:42:54 UTC"
  },
  "success": true
}
```

### Example 5: All Formats Explicitly
**Input:**
```
Format: all
```
**Output:**
```json
{
  "data": {
    "unixSeconds": 1758433377,
    "unixMilliseconds": 1758433377793,
    "iso8601": "2025-09-21T05:42:57Z",
    "rfc3339": "2025-09-21T05:42:57Z",
    "humanReadable": "2025-09-21 05:42:57 UTC"
  },
  "success": true
}
```

## Time Formats Explained

### Unix Timestamp (Seconds)
- **Format**: Integer seconds since January 1, 1970, 00:00:00 UTC
- **Example**: `1758433364`
- **Use cases**: Database storage, API timestamps, caching
- **Range**: 1970 to 2038 (32-bit) or beyond (64-bit)

### Unix Timestamp (Milliseconds)
- **Format**: Integer milliseconds since January 1, 1970, 00:00:00 UTC
- **Example**: `1758433364963`
- **Use cases**: JavaScript timestamps, high-precision logging
- **Precision**: Millisecond accuracy

### ISO8601 Format
- **Format**: `YYYY-MM-DDTHH:mm:ssZ`
- **Example**: `2025-09-21T05:42:44Z`
- **Use cases**: JSON APIs, international data exchange
- **Standard**: ISO 8601 international standard
- **Timezone**: Always UTC (Z suffix)

### RFC3339 Format
- **Format**: `YYYY-MM-DDTHH:mm:ssZ`
- **Example**: `2025-09-21T05:42:44Z`
- **Use cases**: Internet protocols, web standards
- **Standard**: RFC 3339 specification
- **Compatibility**: Subset of ISO8601

### Human-Readable Format
- **Format**: `YYYY-MM-DD HH:mm:ss UTC`
- **Example**: `2025-09-21 05:42:44 UTC`
- **Use cases**: Logging, debugging, user interfaces
- **Timezone**: Explicitly shows UTC

## Use Cases

### API Development
```javascript
// Timestamp for API responses
{
  "data": {...},
  "timestamp": 1758433364,
  "iso_timestamp": "2025-09-21T05:42:44Z"
}

// Request logging
console.log(`[${getCurrentTime().humanReadable}] API request received`);
```

### Database Operations
```sql
-- Using Unix timestamp
INSERT INTO events (name, created_at) VALUES ('user_login', 1758433364);

-- Using ISO8601 format
INSERT INTO events (name, created_at) VALUES ('user_login', '2025-09-21T05:42:44Z');
```

### Caching and Expiration
```javascript
// Cache with TTL
const cacheKey = 'user_data_123';
const ttl = 3600; // 1 hour
const expiresAt = getCurrentTime().unixSeconds + ttl;

cache.set(cacheKey, data, expiresAt);
```

### Logging and Monitoring
```javascript
// Structured logging
const logEntry = {
  level: 'INFO',
  message: 'User authenticated',
  timestamp: getCurrentTime().iso8601,
  unix_time: getCurrentTime().unixSeconds
};
```

### Performance Measurement
```javascript
// Timing operations
const startTime = getCurrentTime().unixMilliseconds;
await performOperation();
const endTime = getCurrentTime().unixMilliseconds;
const duration = endTime - startTime;
```

## Format Selection Guidelines

### Use Unix Seconds When:
- Storing timestamps in databases
- Working with system-level operations
- Need compact representation
- Interfacing with Unix systems

### Use Unix Milliseconds When:
- Working with JavaScript
- Need high precision timing
- Measuring performance
- Real-time applications

### Use ISO8601 When:
- Building REST APIs
- Exchanging data between systems
- Need international compatibility
- Working with JSON

### Use Human-Readable When:
- Debugging applications
- Writing log files
- Displaying to developers
- Documentation and reports

## Best Practices

### API Design
- Use ISO8601 for public APIs
- Include both Unix and ISO8601 for flexibility
- Always use UTC timezone
- Document timestamp format in API docs

### Database Storage
- Store as Unix timestamp for efficiency
- Use appropriate data types (BIGINT for milliseconds)
- Index timestamp columns for queries
- Consider partitioning by time ranges

### Logging
- Use human-readable format for readability
- Include timezone information
- Use consistent format across application
- Consider structured logging with multiple formats

### Client-Side Handling
- Convert to local timezone for display
- Use Unix timestamps for calculations
- Cache current time for batch operations
- Handle timezone conversions properly

## Timezone Considerations

### UTC Only
- All timestamps are in UTC
- No timezone conversion needed
- Consistent across global systems
- Client responsible for local display

### Benefits of UTC
- No daylight saving time issues
- Consistent sorting and comparison
- Global system compatibility
- Simplified time calculations

### Client-Side Display
```javascript
// Convert UTC to local time for display
const utcTimestamp = 1758433364;
const localDate = new Date(utcTimestamp * 1000);
const localString = localDate.toLocaleString();
```

## Common Patterns

### Timestamp Comparison
```javascript
const now = getCurrentTime().unixSeconds;
const eventTime = 1758433364;
const isRecent = (now - eventTime) < 3600; // Within last hour
```

### Time-based Caching
```javascript
const cacheEntry = {
  data: userData,
  timestamp: getCurrentTime().unixSeconds,
  ttl: 3600
};

const isExpired = (getCurrentTime().unixSeconds - cacheEntry.timestamp) > cacheEntry.ttl;
```

### Rate Limiting
```javascript
const requests = [];
const now = getCurrentTime().unixSeconds;
const windowStart = now - 60; // 1 minute window

// Clean old requests
requests = requests.filter(time => time > windowStart);
requests.push(now);

const isRateLimited = requests.length > 100; // Max 100 requests per minute
```