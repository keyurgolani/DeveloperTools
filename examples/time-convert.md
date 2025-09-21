# Time Format Conversion

Convert time between different formats: Unix timestamps, ISO8601, and human-readable formats.

## Tool: `mcp_dev_utilities_mcp_time_convert`

### Example 1: Unix to ISO8601
**Input:**
```
Time: "1640995200"
From Format: unix
To Format: iso8601
```
**Output:**
```json
{
  "data": {
    "result": "2022-01-01T00:00:00Z"
  },
  "success": true
}
```

### Example 2: ISO8601 to Unix
**Input:**
```
Time: "2025-12-25T15:30:00Z"
From Format: iso8601
To Format: unix
```
**Output:**
```json
{
  "data": {
    "result": "1766676600"
  },
  "success": true
}
```

### Example 3: Unix to Human-Readable
**Input:**
```
Time: "1609459200"
From Format: unix
To Format: human
```
**Output:**
```json
{
  "data": {
    "result": "2021-01-01 00:00:00 UTC"
  },
  "success": true
}
```

### Example 4: ISO8601 to Human-Readable
**Input:**
```
Time: "2024-06-15T12:00:00Z"
From Format: iso8601
To Format: human
```
**Output:**
```json
{
  "data": {
    "result": "2024-06-15 12:00:00 UTC"
  },
  "success": true
}
```

### Example 5: Unix Epoch Conversion
**Input:**
```
Time: "0"
From Format: unix
To Format: iso8601
```
**Output:**
```json
{
  "data": {
    "result": "1970-01-01T00:00:00Z"
  },
  "success": true
}
```

## Supported Formats

### Unix Timestamp
- **Input format**: String or number representing seconds since epoch
- **Example**: `"1640995200"` or `1640995200`
- **Range**: 1970-01-01 to 2038-01-19 (32-bit) or beyond (64-bit)
- **Precision**: Seconds

### ISO8601
- **Input format**: `YYYY-MM-DDTHH:mm:ssZ`
- **Example**: `"2022-01-01T00:00:00Z"`
- **Timezone**: Must be UTC (Z suffix)
- **Standard**: ISO 8601 international standard

### Human-Readable
- **Output format**: `YYYY-MM-DD HH:mm:ss UTC`
- **Example**: `"2022-01-01 00:00:00 UTC"`
- **Timezone**: Always UTC
- **Use case**: Debugging and logging

## Conversion Matrix

| From → To | Unix | ISO8601 | Human |
|-----------|------|---------|-------|
| **Unix** | - | ✅ | ✅ |
| **ISO8601** | ✅ | - | ✅ |
| **Human** | ❌ | ❌ | - |

*Note: Human-readable format is output-only*

## Common Use Cases

### Database Migration
```javascript
// Convert stored Unix timestamps to ISO8601
const unixTimestamp = "1640995200";
const iso8601 = convertTime(unixTimestamp, 'unix', 'iso8601');
// Result: "2022-01-01T00:00:00Z"

// Update database
UPDATE events SET created_at_iso = '2022-01-01T00:00:00Z' 
WHERE created_at_unix = 1640995200;
```

### API Response Formatting
```javascript
// Convert internal Unix timestamp to API-friendly ISO8601
const apiResponse = {
  id: 123,
  created_at: convertTime(user.created_at, 'unix', 'iso8601'),
  updated_at: convertTime(user.updated_at, 'unix', 'iso8601')
};
```

### Log Analysis
```javascript
// Convert Unix timestamps in logs to human-readable format
const logEntry = {
  timestamp: "1640995200",
  message: "User login"
};

const readableLog = {
  timestamp: convertTime(logEntry.timestamp, 'unix', 'human'),
  message: logEntry.message
};
// Result: { timestamp: "2022-01-01 00:00:00 UTC", message: "User login" }
```

### Data Import/Export
```javascript
// Convert ISO8601 from external API to Unix for internal storage
const externalData = {
  event_time: "2024-06-15T12:00:00Z",
  event_type: "purchase"
};

const internalData = {
  event_time: convertTime(externalData.event_time, 'iso8601', 'unix'),
  event_type: externalData.event_type
};
// Result: { event_time: "1718452800", event_type: "purchase" }
```

### Time Range Queries
```javascript
// Convert human-readable dates to Unix for database queries
const startDate = "2024-01-01T00:00:00Z";
const endDate = "2024-12-31T23:59:59Z";

const startUnix = convertTime(startDate, 'iso8601', 'unix');
const endUnix = convertTime(endDate, 'iso8601', 'unix');

// Use in SQL query
SELECT * FROM events 
WHERE created_at BETWEEN ${startUnix} AND ${endUnix};
```

## Historical Timestamps

### Significant Dates
```javascript
// Unix Epoch
convertTime("0", 'unix', 'iso8601')
// Result: "1970-01-01T00:00:00Z"

// Y2K
convertTime("946684800", 'unix', 'iso8601')
// Result: "2000-01-01T00:00:00Z"

// Unix 32-bit overflow (Year 2038 problem)
convertTime("2147483647", 'unix', 'iso8601')
// Result: "2038-01-19T03:14:07Z"
```

### Common Milestones
```javascript
// New Year 2022
convertTime("2022-01-01T00:00:00Z", 'iso8601', 'unix')
// Result: "1640995200"

// Christmas 2025
convertTime("2025-12-25T15:30:00Z", 'iso8601', 'unix')
// Result: "1766676600"
```

## Best Practices

### Input Validation
- Always validate timestamp format before conversion
- Handle edge cases (epoch, far future dates)
- Check for reasonable date ranges
- Sanitize input to prevent injection

### Error Handling
```javascript
try {
  const converted = convertTime(userInput, 'unix', 'iso8601');
  return converted;
} catch (error) {
  console.error('Invalid timestamp:', userInput);
  return null;
}
```

### Performance Considerations
- Cache conversion results for repeated operations
- Use batch conversion for large datasets
- Consider timezone implications for user-facing data
- Validate input format before conversion

### Data Consistency
- Use consistent timestamp format within each system
- Document timestamp formats in API specifications
- Convert at system boundaries (input/output)
- Maintain audit trails with original timestamps

## Format-Specific Notes

### Unix Timestamps
- **Precision**: Seconds only (no milliseconds)
- **Range**: Limited by system architecture
- **Storage**: Efficient for databases
- **Calculation**: Easy arithmetic operations

### ISO8601
- **Standard**: Internationally recognized
- **Parsing**: Widely supported by libraries
- **Readability**: Human-readable but structured
- **Timezone**: Always UTC in this implementation

### Human-Readable
- **Purpose**: Debugging and logging only
- **Parsing**: Not supported as input format
- **Display**: Clear for human interpretation
- **Timezone**: Explicitly shows UTC

## Common Conversion Patterns

### API Gateway Pattern
```javascript
// Convert incoming ISO8601 to Unix for internal processing
const internalTimestamp = convertTime(request.timestamp, 'iso8601', 'unix');

// Process data...

// Convert back to ISO8601 for response
const responseTimestamp = convertTime(internalTimestamp, 'unix', 'iso8601');
```

### Logging Pattern
```javascript
// Convert Unix timestamp to human-readable for logs
const logTimestamp = convertTime(event.timestamp, 'unix', 'human');
console.log(`[${logTimestamp}] Event processed: ${event.type}`);
```

### Database Query Pattern
```javascript
// Convert ISO8601 date range to Unix for efficient querying
const startUnix = convertTime(filters.start_date, 'iso8601', 'unix');
const endUnix = convertTime(filters.end_date, 'iso8601', 'unix');

const results = await db.query(
  'SELECT * FROM events WHERE timestamp BETWEEN ? AND ?',
  [startUnix, endUnix]
);
```