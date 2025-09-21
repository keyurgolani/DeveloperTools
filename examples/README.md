# Developer Utilities MCP Server Examples

This directory contains comprehensive examples showcasing all the capabilities of the Developer Utilities MCP Server. Each tool has been tested with 5 different variations to demonstrate its functionality and use cases.

## Tool Categories

### 🔐 Cryptographic Tools
- [Hash Generation](crypto-hash.md) - MD5, SHA1, SHA256, SHA512 hashing
- [HMAC Generation](crypto-hmac.md) - SHA256, SHA512 HMAC signatures
- [Password Hashing](crypto-password.md) - Argon2id password hashing and verification
- [Certificate Decoding](crypto-cert.md) - X.509 certificate parsing

### 📝 Text Processing Tools
- [Case Conversion](text-case.md) - Convert between different text cases
- [Text Analysis](text-analyze.md) - Character, word, line, and sentence counting
- [Regex Testing](text-regex.md) - Pattern matching and extraction
- [Text Sorting](text-sort.md) - Alphabetical and numerical sorting

### 🔄 Transform Tools
- [Base64 Encoding/Decoding](transform-base64.md) - Standard and URL-safe Base64
- [URL Encoding/Decoding](transform-url.md) - URL percent encoding
- [JWT Decoding](transform-jwt.md) - JSON Web Token parsing
- [Compression](transform-compress.md) - Gzip and Zlib compression/decompression

### 🆔 ID Generation Tools
- [UUID Generation](id-uuid.md) - Version 1 and 4 UUID generation
- [Nano ID Generation](id-nanoid.md) - Compact URL-safe unique IDs

### ⏰ Time Tools
- [Current Time](time-now.md) - Get current time in various formats
- [Time Conversion](time-convert.md) - Convert between Unix, ISO8601, and human-readable formats

### 🌐 Network Tools
- [URL Parsing](network-url-parse.md) - Parse URLs into components
- [URL Building](network-url-build.md) - Build URLs from components
- [IP Analysis](network-ip.md) - Analyze IP addresses
- [DNS Lookup](network-dns.md) - DNS record queries
- [Header Inspection](network-headers.md) - HTTP header analysis

### 📊 Data Tools
- [JSON Formatting](data-json.md) - Format and minify JSON

## Usage

Each example file contains:
- Tool description and purpose
- 5 different usage examples with actual inputs and outputs
- Common use cases and best practices
- Error handling examples where applicable

## Direct API Access

In addition to MCP tool examples, this directory includes:
- [API Examples](api-examples.md) - Direct HTTP API call examples for all tools
- [Sample Certificate](sample-certificate.pem) - Valid X.509 certificate for testing
- Complete cURL, JavaScript, and Python examples for each endpoint

## Server Configuration

This MCP server is configured locally with the following tools auto-approved:
- All crypto tools (hash, hmac, password operations)
- All text processing tools
- All transform tools
- All ID generation tools
- All time tools
- All network tools
- All data tools

The server runs on `http://localhost:8080/api/v1` and is accessible via the Node.js bridge.