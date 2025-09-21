# MCP Bridge for Developer Utilities

This directory contains the Model Context Protocol (MCP) bridge that allows the Developer Utilities HTTP server to be used as an MCP server, enabling AI assistants and other MCP clients to access all utility functions.

## Overview

The MCP bridge acts as a translation layer between:
- **MCP Protocol**: Used by AI assistants (Claude, ChatGPT, etc.) and other MCP clients
- **HTTP API**: The main Developer Utilities server

This enables seamless integration with AI development workflows while maintaining the performance and security of the HTTP server.

## Architecture

```
AI Assistant/MCP Client
         ↓ (MCP Protocol)
    MCP Bridge (Node.js)
         ↓ (HTTP/REST)
Developer Utilities Server (Go)
```

## Files

- `mcp-bridge.js` - Main bridge server implementation with MCP protocol handling
- `package.json` - Node.js dependencies and configuration
- `package-lock.json` - Locked dependency versions
- `node_modules/` - Installed dependencies

## Features

The MCP bridge exposes all Developer Utilities functionality through MCP tools:

### Cryptography Tools
- `mcp_crypto_hash` - Calculate MD5, SHA1, SHA256, SHA512 hashes
- `mcp_crypto_hmac` - Generate HMAC with SHA256/SHA512
- `mcp_crypto_password_hash` - Hash passwords with Argon2id
- `mcp_crypto_password_verify` - Verify password hashes
- `mcp_crypto_cert_decode` - Decode X.509 certificates

### Text Processing Tools
- `mcp_text_case_convert` - Convert between case formats
- `mcp_text_analyze` - Analyze text statistics
- `mcp_text_regex_test` - Test regular expressions
- `mcp_text_sort` - Sort text lines

### Data Transformation Tools
- `mcp_transform_base64_encode/decode` - Base64 operations
- `mcp_transform_url_encode/decode` - URL encoding operations
- `mcp_transform_jwt_decode` - Decode JWT tokens
- `mcp_transform_compress/decompress` - Gzip/Zlib compression

### Identifier Generation Tools
- `mcp_id_uuid_generate` - Generate UUIDs (v1/v4)
- `mcp_id_nanoid_generate` - Generate Nano IDs

### Time Utilities Tools
- `mcp_time_convert` - Convert between time formats
- `mcp_time_now` - Get current time in multiple formats

### Network Tools
- `mcp_network_url_parse/build` - URL operations
- `mcp_network_headers_inspect` - HTTP header inspection
- `mcp_network_dns_lookup` - DNS lookups
- `mcp_network_ip_analyze` - IP address analysis

## Usage

### Prerequisites
- Node.js 18+ 
- The main Developer Utilities server running on port 8080 (or configured port)

### Installation
```bash
cd mcp-bridge
npm install
```

### Running the Bridge

#### Development Mode
```bash
# Start the bridge (connects to server on localhost:8080)
npm start

# Or run directly
node mcp-bridge.js

# With custom server URL
DEV_UTILS_BASE_URL=http://localhost:9000/api/v1 node mcp-bridge.js
```

#### Production Mode
```bash
# With full configuration
DEV_UTILS_BASE_URL=https://api.example.com/api/v1 \
API_KEY=your-api-key \
NODE_ENV=production \
node mcp-bridge.js
```

### Configuration

Environment variables:
- `DEV_UTILS_BASE_URL` - Base URL of the HTTP server (default: `http://localhost:8080/api/v1`)
- `SERVER_PORT` - Port the HTTP server is running on (default: `8080`)
- `API_KEY` - API key for authentication (if server requires it)
- `NODE_ENV` - Environment mode (`development`, `production`)
- `MCP_SERVER_NAME` - Name for the MCP server (default: `dev-utilities`)

### MCP Client Configuration

To use this bridge with MCP clients, configure your client to connect to the bridge:

#### Claude Desktop Configuration
Add to your `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "dev-utilities": {
      "command": "node",
      "args": ["/path/to/mcp-bridge/mcp-bridge.js"],
      "env": {
        "DEV_UTILS_BASE_URL": "http://localhost:8080/api/v1"
      }
    }
  }
}
```

#### Generic MCP Client
```bash
# Connect via stdio
node mcp-bridge.js

# Connect via server mode (if supported)
node mcp-bridge.js --server --port 3000
```

## Integration Examples

### Hash Calculation
```javascript
// MCP client call
const result = await mcpClient.callTool('mcp_crypto_hash', {
  content: 'hello world',
  algorithm: 'sha256'
});
// Returns: { hash: 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9' }
```

### Text Processing
```javascript
// Convert text case
const result = await mcpClient.callTool('mcp_text_case_convert', {
  content: 'hello world',
  case_type: 'camelCase'
});
// Returns: { result: 'helloWorld' }
```

### UUID Generation
```javascript
// Generate UUIDs
const result = await mcpClient.callTool('mcp_id_uuid_generate', {
  version: 'v4',
  count: 3
});
// Returns: { uuids: ['uuid1', 'uuid2', 'uuid3'] }
```

## Error Handling

The bridge provides comprehensive error handling:
- HTTP server connection errors
- Authentication failures
- Invalid request formats
- Rate limiting responses
- Network timeouts

All errors are properly formatted for MCP protocol compliance.

## Security Considerations

- The bridge inherits all security features from the HTTP server
- API key authentication is supported
- SSRF protection is maintained
- Rate limiting is preserved
- No sensitive data is logged

## Development

### Testing the Bridge
```bash
# Test connection to HTTP server
npm run test-connection

# Test MCP protocol compliance
npm run test-mcp

# Run all tests
npm test
```

### Debugging
```bash
# Enable debug logging
DEBUG=mcp-bridge node mcp-bridge.js

# Verbose MCP protocol logging
MCP_DEBUG=true node mcp-bridge.js
```

## Troubleshooting

### Common Issues

#### Bridge Won't Start
- Ensure Node.js 18+ is installed
- Check that the HTTP server is running
- Verify network connectivity

#### MCP Client Connection Issues
- Check MCP client configuration
- Verify bridge is running and accessible
- Review error logs for authentication issues

#### Performance Issues
- Monitor HTTP server performance
- Check network latency between bridge and server
- Consider running bridge closer to HTTP server

### Support

For issues specific to the MCP bridge:
1. Check bridge logs for error messages
2. Verify HTTP server connectivity
3. Test individual tool calls
4. Review MCP client configuration

For HTTP server issues, see the main project documentation.