# JWT Token Decoding

Decode JSON Web Tokens (JWT) to extract header and payload information without signature verification.

## Tool: `mcp_dev_utilities_mcp_transform_jwt_decode`

### Example 1: Basic JWT Token
**Input:**
```
Token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
```
**Output:**
```json
{
  "success": true,
  "data": {
    "header": {
      "alg": "HS256",
      "typ": "JWT"
    },
    "payload": {
      "iat": 1516239022,
      "name": "John Doe",
      "sub": "1234567890"
    },
    "signatureVerified": false
  }
}
```

### Example 2: JWT with User Information and Roles
**Input:**
```
Token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwiZW1haWwiOiJ1c2VyQGV4YW1wbGUuY29tIiwicm9sZSI6ImFkbWluIiwiZXhwIjoxNjQwOTk1MjAwLCJpYXQiOjE2NDA5OTE2MDB9.invalid-signature"
```
**Output:**
```json
{
  "success": true,
  "data": {
    "header": {
      "alg": "RS256",
      "typ": "JWT"
    },
    "payload": {
      "email": "user@example.com",
      "exp": 1640995200,
      "iat": 1640991600,
      "role": "admin",
      "sub": "user123"
    },
    "signatureVerified": false
  }
}
```

### Example 3: Unsigned JWT (Algorithm: none)
**Input:**
```
Token: "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0IiwibmFtZSI6IlRlc3QgVXNlciIsImFkbWluIjp0cnVlfQ."
```
**Output:**
```json
{
  "success": true,
  "data": {
    "header": {
      "alg": "none",
      "typ": "JWT"
    },
    "payload": {
      "admin": true,
      "name": "Test User",
      "sub": "test"
    },
    "signatureVerified": false
  }
}
```

### Example 4: JWT with Standard Claims
**Input:**
```
Token: "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJteS1hcHAiLCJhdWQiOiJteS1hcGktdXNlcnMiLCJzdWIiOiJ1c2VyNDU2IiwiZXhwIjoxNzAwMDAwMDAwLCJuYmYiOjE2OTk5OTk5OTksImlhdCI6MTY5OTk5OTk5OSwianRpIjoiYWJjZGVmZ2gifQ.invalid"
```
**Output:**
```json
{
  "success": true,
  "data": {
    "header": {
      "alg": "HS256"
    },
    "payload": {
      "aud": "my-api-users",
      "exp": 1700000000,
      "iat": 1699999999,
      "iss": "my-app",
      "jti": "abcdefgh",
      "nbf": 1699999999,
      "sub": "user456"
    },
    "signatureVerified": false
  }
}
```

## JWT Structure

A JWT consists of three parts separated by dots (`.`):

```
header.payload.signature
```

### Header
Contains metadata about the token:
- `alg`: Algorithm used for signing
- `typ`: Token type (usually "JWT")
- `kid`: Key ID (optional)

### Payload
Contains the claims (data):
- **Registered claims**: Standard claims like `iss`, `exp`, `sub`
- **Public claims**: Custom claims with public names
- **Private claims**: Custom claims for specific use

### Signature
Used to verify the token's authenticity (not decoded by this tool)

## Standard Claims

### Registered Claims
- `iss` (Issuer): Who issued the token
- `sub` (Subject): Who the token is about
- `aud` (Audience): Who the token is intended for
- `exp` (Expiration): When the token expires (Unix timestamp)
- `nbf` (Not Before): When the token becomes valid (Unix timestamp)
- `iat` (Issued At): When the token was issued (Unix timestamp)
- `jti` (JWT ID): Unique identifier for the token

### Common Custom Claims
- `name`: User's full name
- `email`: User's email address
- `role`: User's role or permissions
- `admin`: Boolean indicating admin status
- `scope`: OAuth scopes

## Common Algorithms

### HMAC-based
- `HS256`: HMAC using SHA-256
- `HS384`: HMAC using SHA-384
- `HS512`: HMAC using SHA-512

### RSA-based
- `RS256`: RSA using SHA-256
- `RS384`: RSA using SHA-384
- `RS512`: RSA using SHA-512

### ECDSA-based
- `ES256`: ECDSA using P-256 and SHA-256
- `ES384`: ECDSA using P-384 and SHA-384
- `ES512`: ECDSA using P-521 and SHA-512

### No Signature
- `none`: No signature (not recommended for production)

## Use Cases

### Development and Debugging
- Inspecting JWT contents during development
- Debugging authentication issues
- Understanding token structure
- Validating claim contents

### Security Analysis
- Analyzing suspicious tokens
- Checking token expiration
- Verifying claim structure
- Security auditing

### Integration Testing
- Validating token generation
- Testing token parsing
- Checking claim values
- API testing

### Token Management
- Understanding token contents before processing
- Extracting user information
- Checking permissions and roles
- Token lifecycle management

## Important Security Notes

### This Tool Does NOT:
- Verify token signatures
- Validate token expiration
- Check token authenticity
- Provide security guarantees

### Security Considerations:
- Never trust decoded JWT data without signature verification
- Always verify tokens on the server side
- Check expiration times (`exp` claim)
- Validate issuer (`iss`) and audience (`aud`) claims
- Use proper signature verification in production

### Best Practices:
- Use this tool only for development and debugging
- Always implement proper JWT verification in applications
- Never expose sensitive data in JWT payloads
- Use short expiration times for security tokens
- Rotate signing keys regularly