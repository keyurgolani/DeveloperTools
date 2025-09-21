# Direct API Call Examples

This document provides examples of calling the Developer Utilities API directly using HTTP requests. The API is available at `http://localhost:8080/api/v1`.

## API Base URL
```
http://localhost:8080/api/v1
```

## Authentication
No authentication is required for this local development server.

## Available Endpoints
**Note:** Not all MCP tools have corresponding HTTP endpoints. The following endpoints are currently available:

✅ **Working Endpoints:**
- `POST /crypto/hash` - Hash generation
- `POST /crypto/hmac` - HMAC generation  
- `POST /crypto/password/hash` - Password hashing
- `POST /crypto/password/verify` - Password verification
- `POST /text/case` - Text case conversion
- `GET /time/now` - Current time
- `POST /time/convert` - Time format conversion
- `POST /id/uuid` - UUID generation

❌ **Not Available via HTTP API:**
- Text analysis, regex testing, sorting
- Base64, URL, JWT, compression transforms
- Nano ID generation
- Network tools (URL parsing, IP analysis, DNS, headers)
- JSON formatting
- Certificate decoding

For tools not available via HTTP API, use the MCP tool calls directly.

## Response Format
All API responses follow this format:
```json
{
  "success": true,
  "data": {
    // Tool-specific response data
  }
}
```

Error responses:
```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "Error message",
    "details": "Additional details"
  }
}
```

---

## 🔐 Cryptographic Tools

### Hash Generation
**Endpoint:** `POST /crypto/hash`

**cURL Example:**
```bash
curl -X POST http://localhost:8080/api/v1/crypto/hash \
  -H "Content-Type: application/json" \
  -d '{
    "content": "Hello World",
    "algorithm": "sha256"
  }'
```

**JavaScript Example:**
```javascript
const response = await fetch('http://localhost:8080/api/v1/crypto/hash', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    content: 'Hello World',
    algorithm: 'sha256'
  })
});
const result = await response.json();
```

**Python Example:**
```python
import requests

response = requests.post('http://localhost:8080/api/v1/crypto/hash', json={
    'content': 'Hello World',
    'algorithm': 'sha256'
})
result = response.json()
```

### HMAC Generation
**Endpoint:** `POST /crypto/hmac`

**cURL Example:**
```bash
curl -X POST http://localhost:8080/api/v1/crypto/hmac \
  -H "Content-Type: application/json" \
  -d '{
    "content": "Hello World",
    "key": "my-secret-key",
    "algorithm": "sha256"
  }'
```

**Response:**
```json
{
  "success": true,
  "data": {
    "hmac": "820254804a971bc380e5f4d44177fdf729c70386997e8b901b7a83054d4043b9",
    "algorithm": "sha256"
  }
}
```

### Password Hashing
**Endpoint:** `POST /crypto/password/hash`

**cURL Example:**
```bash
curl -X POST http://localhost:8080/api/v1/crypto/password/hash \
  -H "Content-Type: application/json" \
  -d '{
    "password": "mySecurePassword123"
  }'
```

### Password Verification
**Endpoint:** `POST /crypto/password/verify`

**cURL Example:**
```bash
curl -X POST http://localhost:8080/api/v1/crypto/password/verify \
  -H "Content-Type: application/json" \
  -d '{
    "password": "mySecurePassword123",
    "hash": "$argon2id$v=19$m=65536,t=3,p=4$..."
  }'
```

### Certificate Decoding
**Endpoint:** `POST /crypto/cert/decode`

**cURL Example:**
```bash
curl -X POST http://localhost:8080/api/v1/crypto/cert/decode \
  -H "Content-Type: application/json" \
  -d '{
    "certificate": "-----BEGIN CERTIFICATE-----\nMIIDSjCCAjICCQCZNYufeYkJETANBgkqhkiG9w0BAQsFADBnMQswCQYDVQQGEwJV...\n-----END CERTIFICATE-----"
  }'
```

---

## 📝 Text Processing Tools

### Case Conversion
**Endpoint:** `POST /text/case`

**cURL Example:**
```bash
curl -X POST http://localhost:8080/api/v1/text/case \
  -H "Content-Type: application/json" \
  -d '{
    "content": "hello world",
    "CaseType": "camelCase"
  }'
```

**Response:**
```json
{
  "success": true,
  "data": {
    "result": "helloWorld",
    "caseType": "camelCase"
  }
}
```

**JavaScript Example:**
```javascript
const response = await fetch('http://localhost:8080/api/v1/text/case', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    content: 'hello world',
    CaseType: 'camelCase'
  })
});
```

### Text Analysis
**Endpoint:** `POST /text/analyze` *(Currently not available via direct API)*

**Note:** This functionality is available through the MCP tool `mcp_dev_utilities_mcp_text_analyze` but not as a direct HTTP endpoint.

### Regex Testing
**Endpoint:** `POST /text/regex/test` *(Currently not available via direct API)*

**Note:** This functionality is available through the MCP tool `mcp_dev_utilities_mcp_text_regex_test` but not as a direct HTTP endpoint.

### Text Sorting
**Endpoint:** `POST /text/sort` *(Currently not available via direct API)*

**Note:** This functionality is available through the MCP tool `mcp_dev_utilities_mcp_text_sort` but not as a direct HTTP endpoint.

---

## 🔄 Transform Tools

**Note:** Transform tools are currently not available via direct HTTP API. Use the corresponding MCP tools:

- **Base64 Encoding/Decoding:** `mcp_dev_utilities_mcp_transform_base64_encode` / `mcp_dev_utilities_mcp_transform_base64_decode`
- **URL Encoding/Decoding:** `mcp_dev_utilities_mcp_transform_url_encode` / `mcp_dev_utilities_mcp_transform_url_decode`
- **JWT Decoding:** `mcp_dev_utilities_mcp_transform_jwt_decode`
- **Data Compression/Decompression:** `mcp_dev_utilities_mcp_transform_compress` / `mcp_dev_utilities_mcp_transform_decompress`

---

## 🆔 ID Generation Tools

### UUID Generation
**Endpoint:** `POST /id/uuid`

**cURL Example:**
```bash
curl -X POST http://localhost:8080/api/v1/id/uuid \
  -H "Content-Type: application/json" \
  -d '{
    "version": 4,
    "count": 5
  }'
```

**Response:**
```json
{
  "success": true,
  "data": {
    "uuids": [
      "92fae556-51c9-4651-b1a7-b0fd3079c5eb"
    ]
  }
}
```

**JavaScript Example:**
```javascript
const response = await fetch('http://localhost:8080/api/v1/id/uuid', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    version: 4,
    count: 1
  })
});
```

### Nano ID Generation
**Endpoint:** `POST /id/nanoid` *(Currently not available via direct API)*

**Note:** This functionality is available through the MCP tool `mcp_dev_utilities_mcp_id_nanoid_generate` but not as a direct HTTP endpoint.

---

## ⏰ Time Tools

### Current Time
**Endpoint:** `GET /time/now`

**cURL Example:**
```bash
curl -X GET "http://localhost:8080/api/v1/time/now"
```

**Response:**
```json
{
  "success": true,
  "data": {
    "unixSeconds": 1758434704,
    "unixMilliseconds": 1758434704571,
    "iso8601": "2025-09-21T06:05:04Z",
    "rfc3339": "2025-09-21T06:05:04Z",
    "humanReadable": "2025-09-21 06:05:04 UTC"
  }
}
```

**JavaScript Example:**
```javascript
const response = await fetch('http://localhost:8080/api/v1/time/now');
const result = await response.json();
console.log(result.data.iso8601); // "2025-09-21T06:05:04Z"
```

### Time Conversion
**Endpoint:** `POST /time/convert`

**cURL Example:**
```bash
curl -X POST http://localhost:8080/api/v1/time/convert \
  -H "Content-Type: application/json" \
  -d '{
    "Input": "1640995200",
    "InputFormat": "unix",
    "OutputFormat": "iso8601"
  }'
```

**Response:**
```json
{
  "success": true,
  "data": {
    "result": "2022-01-01T00:00:00Z"
  }
}
```

---

## 🌐 Network Tools

**Note:** Network tools are currently not available via direct HTTP API. Use the corresponding MCP tools:

- **URL Parsing:** `mcp_dev_utilities_mcp_network_url_parse`
- **URL Building:** `mcp_dev_utilities_mcp_network_url_build`
- **IP Analysis:** `mcp_dev_utilities_mcp_network_ip_analyze`
- **DNS Lookup:** `mcp_dev_utilities_mcp_network_dns_lookup`
- **Headers Inspection:** `mcp_dev_utilities_mcp_network_headers_inspect`

---

## 📊 Data Tools

**Note:** Data tools are currently not available via direct HTTP API. Use the corresponding MCP tools:

- **JSON Formatting:** `mcp_dev_utilities_mcp_data_json_format`

---

## 🔧 Working Examples

### Complete Hash Generation Example
**JavaScript Example:**
```javascript
async function generateMultipleHashes(contents, algorithm) {
  const promises = contents.map(content => 
    fetch('http://localhost:8080/api/v1/crypto/hash', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content, algorithm })
    }).then(r => r.json())
  );
  
  return await Promise.all(promises);
}

// Usage
const results = await generateMultipleHashes([
  'Hello World',
  'Another string',
  'Third string'
], 'sha256');

console.log(results);
// Output: Array of hash results
```

### Password Management Example
**JavaScript Example:**
```javascript
async function hashAndVerifyPassword(password) {
  // Hash the password
  const hashResponse = await fetch('http://localhost:8080/api/v1/crypto/password/hash', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password })
  });
  
  const hashResult = await hashResponse.json();
  const hash = hashResult.data.hash;
  
  // Verify the password
  const verifyResponse = await fetch('http://localhost:8080/api/v1/crypto/password/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password, hash })
  });
  
  const verifyResult = await verifyResponse.json();
  
  return {
    hash,
    verified: verifyResult.data.valid
  };
}

// Usage
const result = await hashAndVerifyPassword('mySecurePassword123');
console.log(result);
// Output: { hash: "$argon2id$v=19$m=65536...", verified: true }
```

### Text Case Conversion Batch
**JavaScript Example:**
```javascript
async function batchCaseConversion(texts, caseType) {
  const promises = texts.map(text => 
    fetch('http://localhost:8080/api/v1/text/case', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: text, CaseType: caseType })
    }).then(r => r.json())
  );
  
  return await Promise.all(promises);
}

// Usage
const results = await batchCaseConversion([
  'hello world',
  'api endpoint name',
  'user authentication service'
], 'camelCase');

console.log(results.map(r => r.data.result));
// Output: ["helloWorld", "apiEndpointName", "userAuthenticationService"]
```

---

## 🚀 Performance Tips

### Connection Reuse
```javascript
// Use HTTP/1.1 keep-alive or HTTP/2 for better performance
const agent = new https.Agent({
  keepAlive: true,
  maxSockets: 10
});

const response = await fetch('http://localhost:8080/api/v1/crypto/hash', {
  method: 'POST',
  agent: agent, // Node.js only
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ content: 'Hello', algorithm: 'sha256' })
});
```

### Parallel Processing
```javascript
// Process multiple requests in parallel
const requests = [
  { content: 'Text 1', algorithm: 'sha256' },
  { content: 'Text 2', algorithm: 'sha256' },
  { content: 'Text 3', algorithm: 'sha256' }
];

const results = await Promise.all(
  requests.map(req => 
    fetch('http://localhost:8080/api/v1/crypto/hash', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req)
    }).then(r => r.json())
  )
);
```

---

## 🛠️ Error Handling

### JavaScript Error Handling
```javascript
async function safeApiCall(endpoint, data) {
  try {
    const response = await fetch(`http://localhost:8080/api/v1${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    
    const result = await response.json();
    
    if (!result.success) {
      throw new Error(result.error || 'API call failed');
    }
    
    return result.data;
  } catch (error) {
    console.error('API call failed:', error);
    throw error;
  }
}
```

### Python Error Handling
```python
import requests
from typing import Dict, Any

def safe_api_call(endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
    try:
        response = requests.post(
            f'http://localhost:8080/api/v1{endpoint}',
            json=data,
            timeout=30
        )
        response.raise_for_status()
        
        result = response.json()
        
        if not result.get('success', False):
            raise Exception(result.get('error', 'API call failed'))
        
        return result['data']
    except requests.exceptions.RequestException as e:
        print(f'API call failed: {e}')
        raise
```

---

## 📋 Testing Examples

### Unit Test Example (JavaScript/Jest)
```javascript
describe('Developer Utilities API', () => {
  const API_BASE = 'http://localhost:8080/api/v1';
  
  test('should hash text with SHA256', async () => {
    const response = await fetch(`${API_BASE}/crypto/hash`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        content: 'Hello World',
        algorithm: 'sha256'
      })
    });
    
    const result = await response.json();
    
    expect(result.success).toBe(true);
    expect(result.data.hash).toBe('a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e');
    expect(result.data.algorithm).toBe('sha256');
  });
  
  test('should convert text case', async () => {
    const response = await fetch(`${API_BASE}/text/case/convert`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        content: 'hello world',
        caseType: 'camel'
      })
    });
    
    const result = await response.json();
    
    expect(result.success).toBe(true);
    expect(result.data.result).toBe('helloWorld');
  });
});
```

### Integration Test Example (Python)
```python
import unittest
import requests

class TestDeveloperUtilitiesAPI(unittest.TestCase):
    API_BASE = 'http://localhost:8080/api/v1'
    
    def test_hash_generation(self):
        response = requests.post(f'{self.API_BASE}/crypto/hash', json={
            'content': 'Hello World',
            'algorithm': 'sha256'
        })
        
        self.assertEqual(response.status_code, 200)
        
        result = response.json()
        self.assertTrue(result['success'])
        self.assertEqual(
            result['data']['hash'],
            'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e'
        )
    
    def test_uuid_generation(self):
        response = requests.post(f'{self.API_BASE}/id/uuid/generate', json={
            'version': 'v4',
            'count': 1
        })
        
        self.assertEqual(response.status_code, 200)
        
        result = response.json()
        self.assertTrue(result['success'])
        self.assertEqual(len(result['data']['uuids']), 1)
        
        # UUID v4 format check
        uuid = result['data']['uuids'][0]
        self.assertRegex(uuid, r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')

if __name__ == '__main__':
    unittest.main()
```