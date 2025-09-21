# Data Compression and Decompression

Compress and decompress data using Gzip and Zlib algorithms for efficient data storage and transmission.

## Tools: `mcp_dev_utilities_mcp_transform_compress` & `mcp_dev_utilities_mcp_transform_decompress`

## Compression Examples

### Example 1: Basic Text Compression (Gzip)
**Input:**
```
Content: "Hello World! This is a test string for compression."
Algorithm: gzip
```
**Output:**
```json
{
  "success": true,
  "data": {
    "result": "H4sIAAAAAAAA/wTA0Q1AYAwE4FXOAuYwgMSzUDSp/+Su+8e3RBWxUXVOWJ800tjR4YZbOW5cFA6+n8JOjvkPAAD//+Ha8IczAAAA"
  }
}
```

### Example 2: Long Text Compression (Zlib)
**Input:**
```
Content: "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat."
Algorithm: zlib
```
**Output:**
```json
{
  "success": true,
  "data": {
    "result": "eJwkz8GJLEEMA9BUFMDQkfzbZwPwls0gKNvdVfYy4S+9fdNBPKF/uczBc7dDc+bCZkHc6oWRsW2UVS+I8uQejDdssg78N4UmjL09FWV+5gJjUKkdhS5M+c5lsHpog8s7BDJ5tRz4KljQIQrnHX4sKP7C1dyI3LVaYR9bgyXFDPSc4iMf+S5x8176I3nCPjDBSPfUfA5cLXX8BgAA//+Z2lVi"
  }
}
```

### Example 3: JSON Data Compression (Gzip)
**Input:**
```
Content: "{\"users\": [{\"id\": 1, \"name\": \"John\"}, {\"id\": 2, \"name\": \"Jane\"}]}"
Algorithm: gzip
```
**Output:**
```json
{
  "success": true,
  "data": {
    "result": "H4sIAAAAAAAA/6pWKi1OLSpWslKIrlbKTFGyUjDUUVDKS8xNVbJSUPLKz8hTqtVRgEoZIUsl5qUq1cbWAgIAAP//7APbvkEAAAA="
  }
}
```

### Example 4: Short Text Compression (Zlib)
**Input:**
```
Content: "Short text"
Algorithm: zlib
```
**Output:**
```json
{
  "success": true,
  "data": {
    "result": "eJwKzsgvKlEoSa0oAQQAAP//FUED9g=="
  }
}
```

### Example 5: Repeated Text Compression (Gzip)
**Input:**
```
Content: "Repeated text repeated text repeated text repeated text repeated text"
Algorithm: gzip
```
**Output:**
```json
{
  "success": true,
  "data": {
    "result": "H4sIAAAAAAAA/wpKLUhNLElNUShJrShRKCKPBwgAAP//wp+/N0UAAAA="
  }
}
```

## Decompression Examples

### Example 1: Basic Text Decompression (Gzip)
**Input:**
```
Content: "H4sIAAAAAAAA/wTA0Q1AYAwE4FXOAuYwgMSzUDSp/+Su+8e3RBWxUXVOWJ800tjR4YZbOW5cFA6+n8JOjvkPAAD//+Ha8IczAAAA"
Algorithm: gzip
```
**Output:**
```json
{
  "success": true,
  "data": {
    "result": "Hello World! This is a test string for compression."
  }
}
```

### Example 2: Long Text Decompression (Zlib)
**Input:**
```
Content: "eJwkz8GJLEEMA9BUFMDQkfzbZwPwls0gKNvdVfYy4S+9fdNBPKF/uczBc7dDc+bCZkHc6oWRsW2UVS+I8uQejDdssg78N4UmjL09FWV+5gJjUKkdhS5M+c5lsHpog8s7BDJ5tRz4KljQIQrnHX4sKP7C1dyI3LVaYR9bgyXFDPSc4iMf+S5x8176I3nCPjDBSPfUfA5cLXX8BgAA//+Z2lVi"
Algorithm: zlib
```
**Output:**
```json
{
  "success": true,
  "data": {
    "result": "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat."
  }
}
```

### Example 3: JSON Data Decompression (Gzip)
**Input:**
```
Content: "H4sIAAAAAAAA/6pWKi1OLSpWslKIrlbKTFGyUjDUUVDKS8xNVbJSUPLKz8hTqtVRgEoZIUsl5qUq1cbWAgIAAP//7APbvkEAAAA="
Algorithm: gzip
```
**Output:**
```json
{
  "success": true,
  "data": {
    "result": "{\"users\": [{\"id\": 1, \"name\": \"John\"}, {\"id\": 2, \"name\": \"Jane\"}]}"
  }
}
```

### Example 4: Short Text Decompression (Zlib)
**Input:**
```
Content: "eJwKzsgvKlEoSa0oAQQAAP//FUED9g=="
Algorithm: zlib
```
**Output:**
```json
{
  "success": true,
  "data": {
    "result": "Short text"
  }
}
```

### Example 5: Repeated Text Decompression (Gzip)
**Input:**
```
Content: "H4sIAAAAAAAA/wpKLUhNLElNUShJrShRKCKPBwgAAP//wp+/N0UAAAA="
Algorithm: gzip
```
**Output:**
```json
{
  "success": true,
  "data": {
    "result": "Repeated text repeated text repeated text repeated text repeated text"
  }
}
```

## Compression Algorithms

### Gzip
- **Format**: RFC 1952 standard
- **Header**: Contains metadata and checksums
- **Use case**: Web compression, file compression
- **Compatibility**: Widely supported across platforms
- **Output**: Base64-encoded compressed data

### Zlib
- **Format**: RFC 1950 standard
- **Header**: Minimal header with compression info
- **Use case**: Library-level compression, embedded systems
- **Compatibility**: Common in programming libraries
- **Output**: Base64-encoded compressed data

## Compression Effectiveness

### Best Compression Ratios
- **Repeated text**: High compression (up to 90%+ reduction)
- **Structured data**: Good compression (JSON, XML, CSV)
- **Natural language**: Moderate compression (30-60% reduction)
- **Code files**: Good compression due to patterns

### Poor Compression Ratios
- **Already compressed data**: Images, videos, archives
- **Random data**: Cryptographic keys, hashes
- **Short text**: Overhead may exceed savings
- **Binary data**: Often already optimized

## Use Cases

### Web Development
- HTTP response compression
- Asset optimization
- API payload reduction
- Static file serving

### Data Storage
- Database field compression
- Log file compression
- Backup optimization
- Archive creation

### Network Transmission
- Reducing bandwidth usage
- Faster data transfer
- Mobile app optimization
- API response optimization

### File Processing
- Temporary file compression
- Memory usage reduction
- Cache optimization
- Data pipeline efficiency

## Performance Considerations

### When to Compress
- Large text files (>1KB typically)
- Repetitive data structures
- Network transmission
- Long-term storage

### When Not to Compress
- Small data (<100 bytes)
- Already compressed data
- Real-time applications (CPU overhead)
- Frequently accessed data

### Algorithm Selection
- **Gzip**: Better for web standards, HTTP compression
- **Zlib**: Better for library integration, lower overhead

## Best Practices

### Compression
- Test compression ratios before implementing
- Consider CPU vs. bandwidth trade-offs
- Cache compressed data when possible
- Use appropriate compression levels

### Decompression
- Validate compressed data before processing
- Handle decompression errors gracefully
- Set reasonable size limits to prevent attacks
- Monitor memory usage during decompression

### Security
- Validate input size to prevent zip bombs
- Use timeouts for decompression operations
- Sanitize decompressed content
- Monitor resource usage