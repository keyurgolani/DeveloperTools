# HMAC Generation

Generate Hash-based Message Authentication Codes (HMAC) for message authentication and integrity verification.

## Tool: `mcp_dev_utilities_mcp_crypto_hmac`

### Example 1: Basic HMAC-SHA256
**Input:**
```
Content: "Hello World"
Secret: "my-secret-key"
Algorithm: sha256
```
**Output:**
```json
{
  "success": true,
  "data": {
    "hmac": "2cd7c25025198d4458002ceb064ad37ccfbbe46650876d693f5e080bd954e449",
    "algorithm": "sha256"
  }
}
```

### Example 2: HMAC for JSON Payload
**Input:**
```
Content: "{\"user_id\": 123, \"timestamp\": 1640995200}"
Secret: "webhook-secret-2024"
Algorithm: sha256
```
**Output:**
```json
{
  "success": true,
  "data": {
    "hmac": "1910ad22945ac89cf8e01d189ccc1bfd2a4028e1730df3cf0acbad787ba9ad79",
    "algorithm": "sha256"
  }
}
```

### Example 3: HMAC-SHA512 with Long Secret
**Input:**
```
Content: "API request payload"
Secret: "super-long-secret-key-for-production-use-only"
Algorithm: sha512
```
**Output:**
```json
{
  "success": true,
  "data": {
    "hmac": "ec1680e37d7c7f9f7034a9e4ca9c485c09e3da4da4d7306d36495afeaa62a2d8ab03b543cb9ef0a6783306834df96f2207d04bb171611e37aa28faadc46e0702",
    "algorithm": "sha512"
  }
}
```

### Example 4: Short Message and Key
**Input:**
```
Content: "Short msg"
Secret: "key"
Algorithm: sha256
```
**Output:**
```json
{
  "success": true,
  "data": {
    "hmac": "0590299c967d869637d765e991d1450ef96382707494c06f9a692f0abf28b578",
    "algorithm": "sha256"
  }
}
```

### Example 5: Multi-line Content with Special Characters
**Input:**
```
Content: "Multi-line content\nwith newlines\nand special chars: !@#$%^&*()"
Secret: "complex-key-123"
Algorithm: sha512
```
**Output:**
```json
{
  "success": true,
  "data": {
    "hmac": "578c39c493adb07046dcc0ed15464fb4f62e040cf11a0fa397ea2c5764b3a1054fffa2786a341f3a825c708c1cd6b21fbd94c54e1571dbf3b3c8339d9ac74925",
    "algorithm": "sha512"
  }
}
```

## Use Cases
- Webhook signature verification
- API request authentication
- Message integrity verification
- JWT signing
- Secure token generation

## Supported Algorithms
- `sha256` - Most commonly used, good balance of security and performance
- `sha512` - Higher security, larger output size

## Security Notes
- Keep secret keys secure and rotate them regularly
- Use sufficiently long and random secret keys
- Never expose secret keys in client-side code
- Consider using environment variables for secret storage