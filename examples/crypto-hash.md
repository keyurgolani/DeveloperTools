# Cryptographic Hash Generation

Generate cryptographic hashes using MD5, SHA1, SHA256, and SHA512 algorithms.

## Tool: `mcp_dev_utilities_mcp_crypto_hash`

### Example 1: Basic MD5 Hash
**Input:**
```
Content: "Hello World"
Algorithm: md5
```
**Output:**
```json
{
  "success": true,
  "data": {
    "hash": "b10a8db164e0754105b7a99be72e3fe5",
    "algorithm": "md5"
  }
}
```

### Example 2: SHA256 Hash of Common Text
**Input:**
```
Content: "The quick brown fox jumps over the lazy dog"
Algorithm: sha256
```
**Output:**
```json
{
  "success": true,
  "data": {
    "hash": "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
    "algorithm": "sha256"
  }
}
```

### Example 3: SHA1 Hash of JSON Data
**Input:**
```
Content: "{\"user\": \"john\", \"action\": \"login\"}"
Algorithm: sha1
```
**Output:**
```json
{
  "success": true,
  "data": {
    "hash": "348f429a7dc59a1bc3b58736430bb52acf51ecd2",
    "algorithm": "sha1"
  }
}
```

### Example 4: SHA512 Hash of Long Text
**Input:**
```
Content: "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
Algorithm: sha512
```
**Output:**
```json
{
  "success": true,
  "data": {
    "hash": "4fca275dc41488a2a11eaea8eee568653cde5bfdf4029dcb2872dbcb6a128dae4455da0717c7137504f8ab53c48660dfbaab996ba01b831265ddc487761dfb83",
    "algorithm": "sha512"
  }
}
```

### Example 5: Empty String Hash
**Input:**
```
Content: ""
Algorithm: md5
```
**Output:**
```json
{
  "success": true,
  "data": {
    "hash": "d41d8cd98f00b204e9800998ecf8427e",
    "algorithm": "md5"
  }
}
```

## Use Cases
- File integrity verification
- Password storage (though Argon2 is recommended)
- Data deduplication
- Digital signatures
- Checksums for data validation

## Supported Algorithms
- `md5` - Fast but cryptographically broken, use only for non-security purposes
- `sha1` - Deprecated for security, use only for legacy compatibility
- `sha256` - Recommended for most security applications
- `sha512` - Higher security, larger output size