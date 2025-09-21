# Nano ID Generation

Generate compact, URL-safe, unique identifiers that are smaller and more user-friendly than UUIDs.

## Tool: `mcp_dev_utilities_mcp_id_nanoid_generate`

### Example 1: Default Nano ID
**Input:**
```
(No parameters - uses defaults)
```
**Output:**
```json
{
  "data": {
    "ids": [
      "-sAqNUWdNo2hs38Jpweg-"
    ]
  },
  "success": true
}
```

### Example 2: Short Nano ID
**Input:**
```
Size: 10
```
**Output:**
```json
{
  "data": {
    "ids": [
      "nGoRJUXsXg"
    ]
  },
  "success": true
}
```

### Example 3: Multiple Short Nano IDs
**Input:**
```
Count: 5
Size: 8
```
**Output:**
```json
{
  "data": {
    "ids": [
      "5fvt7A0I",
      "XQQSs4Nh",
      "szfgj56p",
      "-0RDzXQO",
      "Zhlf5LP0"
    ]
  },
  "success": true
}
```

### Example 4: Long Nano IDs for High Security
**Input:**
```
Count: 3
Size: 25
```
**Output:**
```json
{
  "data": {
    "ids": [
      "cElae-wPQK0u8sxuQFGqCowBA",
      "RpqIZKglvT4TT7NjDCcFdrXeb",
      "eH1Bjg5hLSJQ7ETjxYE1vZWFc"
    ]
  },
  "success": true
}
```

### Example 5: Extra Long Nano ID
**Input:**
```
Count: 1
Size: 50
```
**Output:**
```json
{
  "data": {
    "ids": [
      "tmnNxF5gECh0lT_oMS3YqxzHMcipl_5pL5SMhdswYxWVCBV9N-"
    ]
  },
  "success": true
}
```

## Nano ID Characteristics

### Alphabet
Nano IDs use a URL-safe alphabet of 64 characters:
```
A-Z a-z 0-9 _ -
```

### Default Size
- **Default length**: 21 characters
- **Entropy**: ~126 bits (similar to UUID)
- **Collision probability**: Extremely low

### Customizable Size
- **Minimum**: 1 character
- **Maximum**: 100 characters (tool limit)
- **Recommended**: 8-25 characters for most use cases

## Size vs. Collision Probability

| Size | Entropy | Collision Probability | Use Case |
|------|---------|----------------------|----------|
| 8    | ~48 bits | 1 in 281 trillion | Short-term IDs |
| 10   | ~60 bits | 1 in 1.15 quintillion | Session IDs |
| 12   | ~72 bits | 1 in 4.7 sextillion | File names |
| 16   | ~96 bits | 1 in 79 octillion | Database IDs |
| 21   | ~126 bits | 1 in 5.3 undecillion | UUID replacement |
| 25   | ~150 bits | 1 in 1.4 duodecillion | High security |

## Advantages Over UUIDs

### Size Comparison
- **UUID**: 36 characters (`550e8400-e29b-41d4-a716-446655440000`)
- **Nano ID**: 21 characters (`V1StGXR8_Z5jdHi6B-myT`)
- **Space savings**: ~42% smaller

### URL Friendliness
- No special characters that need encoding
- Safe for use in URLs, file names, and HTML IDs
- No hyphens to break on word boundaries

### Performance
- Faster generation than UUIDs
- Smaller memory footprint
- Better for databases and indexes

## Use Cases

### Web Development
```javascript
// URL slugs
const postId = generateNanoId(10); // "nGoRJUXsXg"
const url = `https://blog.com/posts/${postId}`;

// CSS class names
const className = `component-${generateNanoId(8)}`; // "component-5fvt7A0I"
```

### Database Primary Keys
```sql
-- More compact than UUIDs
CREATE TABLE posts (
    id VARCHAR(21) PRIMARY KEY DEFAULT nanoid(),
    title VARCHAR(255),
    content TEXT
);
```

### API Development
```json
{
  "requestId": "XQQSs4Nh",
  "userId": "szfgj56p",
  "sessionId": "-0RDzXQO"
}
```

### File Management
```bash
# Temporary files
temp_file_5fvt7A0I.json
upload_XQQSs4Nh.tmp
cache_szfgj56p.dat
```

### Security Tokens
```javascript
// Password reset tokens (use longer IDs for security)
const resetToken = generateNanoId(25); // "cElae-wPQK0u8sxuQFGqCowBA"

// API keys (combine with other data)
const apiKey = `nid_${generateNanoId(32)}`;
```

## Size Recommendations

### 8 Characters
- **Use for**: Temporary IDs, short-lived sessions
- **Collision risk**: Acceptable for small datasets
- **Example**: `5fvt7A0I`

### 10-12 Characters
- **Use for**: User-facing IDs, URL slugs
- **Collision risk**: Very low for most applications
- **Example**: `nGoRJUXsXg`

### 16-21 Characters
- **Use for**: Database primary keys, permanent IDs
- **Collision risk**: Negligible
- **Example**: `V1StGXR8_Z5jdHi6B-myT`

### 25+ Characters
- **Use for**: Security tokens, cryptographic applications
- **Collision risk**: Astronomically low
- **Example**: `cElae-wPQK0u8sxuQFGqCowBA`

## Best Practices

### Choosing Size
- Consider the lifetime and scope of the ID
- Balance between size and collision probability
- Use longer IDs for security-sensitive applications
- Use shorter IDs for user-facing identifiers

### Implementation
- Store as VARCHAR in databases
- Use consistent size across your application
- Consider indexing performance for database keys
- Document the ID format in your API

### Security
- Use longer IDs (20+ characters) for security tokens
- Don't rely on Nano IDs alone for authentication
- Combine with other security measures
- Rotate security-related IDs regularly

## Comparison with Other ID Systems

### vs. UUID
- **Nano ID**: Smaller, URL-safe, customizable length
- **UUID**: Standardized, more entropy by default, time-based options

### vs. Auto-incrementing IDs
- **Nano ID**: Unpredictable, distributed-system friendly
- **Auto-increment**: Predictable, reveals record count, database-dependent

### vs. Base64 Random
- **Nano ID**: URL-safe alphabet, no padding
- **Base64**: May contain URL-unsafe characters, padding issues

## Performance Characteristics

### Generation Speed
- Very fast generation (microseconds)
- No system calls required
- Suitable for high-throughput applications

### Memory Usage
- Minimal memory footprint
- No persistent state required
- Efficient for batch generation

### Database Performance
- Smaller index size than UUIDs
- Better cache utilization
- Faster string comparisons