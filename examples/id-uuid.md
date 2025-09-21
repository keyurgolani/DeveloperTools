# UUID Generation

Generate Universally Unique Identifiers (UUIDs) in version 1 and version 4 formats.

## Tool: `mcp_dev_utilities_mcp_id_uuid_generate`

### Example 1: Single UUID v4 Generation
**Input:**
```
Version: v4
```
**Output:**
```json
{
  "data": {
    "uuids": [
      "3bcd658f-2653-4c39-98c0-f3c206453dfd"
    ]
  },
  "success": true
}
```

### Example 2: Single UUID v1 Generation
**Input:**
```
Version: v1
```
**Output:**
```json
{
  "data": {
    "uuids": [
      "b9f499ae-96ad-11f0-8bd5-d64af22f884b"
    ]
  },
  "success": true
}
```

### Example 3: Multiple UUID v4 Generation
**Input:**
```
Version: v4
Count: 5
```
**Output:**
```json
{
  "data": {
    "uuids": [
      "0f19c9f8-8c8e-4d33-b90f-5cf25600f796",
      "ca4433d7-a8bc-4efb-a2e1-7102d8815dd7",
      "a649ce80-8b16-4d5c-8fa2-53250414f9df",
      "d8d9fec6-4457-4cac-8a3f-e94b4bd49e50",
      "550d5e78-4be0-4678-b896-dc1595270854"
    ]
  },
  "success": true
}
```

### Example 4: Multiple UUID v1 Generation
**Input:**
```
Version: v1
Count: 10
```
**Output:**
```json
{
  "data": {
    "uuids": [
      "be644688-96ad-11f0-8bd5-d64af22f884b",
      "be644692-96ad-11f0-8bd5-d64af22f884b",
      "be644692-96ad-11f0-8bd6-d64af22f884b",
      "be64469c-96ad-11f0-8bd6-d64af22f884b",
      "be64469c-96ad-11f0-8bd7-d64af22f884b",
      "be64469c-96ad-11f0-8bd8-d64af22f884b",
      "be64469c-96ad-11f0-8bd9-d64af22f884b",
      "be64469c-96ad-11f0-8bda-d64af22f884b",
      "be6446a6-96ad-11f0-8bda-d64af22f884b",
      "be6446a6-96ad-11f0-8bdb-d64af22f884b"
    ]
  },
  "success": true
}
```

### Example 5: Single UUID v4 for Testing
**Input:**
```
Version: v4
Count: 1
```
**Output:**
```json
{
  "data": {
    "uuids": [
      "01cf79e2-827a-4555-b544-0a52f2594364"
    ]
  },
  "success": true
}
```

## UUID Versions

### UUID Version 1 (Time-based)
- **Structure**: timestamp + clock sequence + MAC address
- **Uniqueness**: Based on time and network card MAC address
- **Sortability**: Chronologically sortable
- **Privacy**: May reveal MAC address and timestamp
- **Use cases**: When temporal ordering is important

**Format**: `xxxxxxxx-xxxx-1xxx-xxxx-xxxxxxxxxxxx`

### UUID Version 4 (Random)
- **Structure**: 122 random bits + 6 fixed bits
- **Uniqueness**: Based on random/pseudo-random numbers
- **Sortability**: Not sortable
- **Privacy**: No personal information revealed
- **Use cases**: General purpose unique identifiers

**Format**: `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`

## UUID Structure

A UUID is a 128-bit value typically represented as 32 hexadecimal digits:

```
xxxxxxxx-xxxx-Mxxx-Nxxx-xxxxxxxxxxxx
```

- **M**: Version number (1 or 4)
- **N**: Variant bits (8, 9, A, or B)
- **x**: Random or time-based hexadecimal digits

## Use Cases

### Database Primary Keys
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255)
);
```

### API Resource Identifiers
```json
{
  "id": "550d5e78-4be0-4678-b896-dc1595270854",
  "name": "John Doe",
  "email": "john@example.com"
}
```

### File and Session Management
```javascript
const sessionId = generateUUID(); // "3bcd658f-2653-4c39-98c0-f3c206453dfd"
const fileName = `upload_${generateUUID()}.tmp`;
```

### Distributed Systems
- Microservice request tracing
- Event sourcing event IDs
- Message queue correlation IDs
- Cache keys

### Security Tokens
- Password reset tokens
- API keys (combined with other data)
- Session identifiers
- CSRF tokens

## Advantages

### UUID v1
- **Temporal ordering**: Can be sorted by creation time
- **Uniqueness guarantee**: MAC address ensures global uniqueness
- **Debugging**: Timestamp can help with troubleshooting

### UUID v4
- **Privacy**: No personal information exposed
- **Simplicity**: Pure random generation
- **Security**: Harder to predict or enumerate
- **Portability**: No dependency on MAC address

## Disadvantages

### UUID v1
- **Privacy concerns**: MAC address may be exposed
- **Predictability**: Somewhat predictable due to timestamp
- **Clock dependency**: Requires accurate system clock

### UUID v4
- **No ordering**: Cannot be sorted chronologically
- **Collision risk**: Extremely low but theoretically possible
- **Randomness dependency**: Requires good random number generator

## Best Practices

### When to Use UUID v1
- When chronological ordering is important
- In systems where MAC address exposure is acceptable
- For debugging and audit trails
- When you need to extract timestamp information

### When to Use UUID v4
- For general-purpose unique identifiers
- When privacy is a concern
- For public-facing APIs
- When randomness is preferred over ordering

### General Guidelines
- Use UUID v4 as the default choice
- Store UUIDs in binary format in databases for efficiency
- Use lowercase representation for consistency
- Consider shorter alternatives (like Nano IDs) for URL-friendly identifiers

## Performance Considerations

### Storage
- UUIDs are 128 bits (16 bytes) in binary format
- String representation is 36 characters (32 hex + 4 hyphens)
- Consider binary storage in databases for space efficiency

### Generation Speed
- UUID v4 is generally faster to generate
- UUID v1 requires system calls for MAC address and timestamp
- Batch generation can be more efficient for multiple UUIDs

### Indexing
- UUIDs are not sequential, which can impact database index performance
- Consider using UUID v1 or ordered UUIDs for better database performance
- Some databases have optimizations for UUID storage and indexing