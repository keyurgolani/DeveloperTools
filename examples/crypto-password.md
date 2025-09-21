# Password Hashing and Verification

Secure password hashing using Argon2id algorithm and verification of hashed passwords.

## Tools: `mcp_dev_utilities_mcp_crypto_password_hash` & `mcp_dev_utilities_mcp_crypto_password_verify`

## Password Hashing Examples

### Example 1: Basic Password Hash
**Input:**
```
Password: "password123"
```
**Output:**
```json
{
  "success": true,
  "data": {
    "hash": "$argon2id$v=19$m=65536,t=3,p=4$vYIf7t4+1iJ04olWMh33Dw$fPkXpfwAf4U6Tuk94Cu2v5CoBd8Ffjfa9IE3/IYVS5A"
  }
}
```

### Example 2: Strong Password Hash
**Input:**
```
Password: "MySecureP@ssw0rd!"
```
**Output:**
```json
{
  "success": true,
  "data": {
    "hash": "$argon2id$v=19$m=65536,t=3,p=4$7XLx8P5WoIYVqRnhuQaeWA$80hmsCpZQGcUbwKUFtUJaEQOFif7ckrYgypw+sY+C88"
  }
}
```

### Example 3: Simple Password Hash
**Input:**
```
Password: "simple"
```
**Output:**
```json
{
  "success": true,
  "data": {
    "hash": "$argon2id$v=19$m=65536,t=3,p=4$NwW+1QdBtnu89CbhuQh9jQ$H3IT2YwI6z4H3G5YYEe8O4/shGtMg0BJ3uQ4teT2sy0"
  }
}
```

### Example 4: Very Long Password Hash
**Input:**
```
Password: "very-long-password-with-many-characters-and-symbols-!@#$%^&*()_+-=[]{}|;:,.<>?"
```
**Output:**
```json
{
  "success": true,
  "data": {
    "hash": "$argon2id$v=19$m=65536,t=3,p=4$S6TMEFCJEPN8rHCa3/bWlw$YAmEK4bou91PveXridHT6VefD9q9mqV9/4Y59TvYaEU"
  }
}
```

### Example 5: Numeric Password Hash
**Input:**
```
Password: "123456"
```
**Output:**
```json
{
  "success": true,
  "data": {
    "hash": "$argon2id$v=19$m=65536,t=3,p=4$8PChhZvm6rD5afpt2Wddvg$WP7KRar7LoVW+AQFlLRf+8rsrgmSWGlfr08bxcpoFcc"
  }
}
```

## Password Verification Examples

### Example 1: Valid Password Verification
**Input:**
```
Password: "password123"
Hash: "$argon2id$v=19$m=65536,t=3,p=4$vYIf7t4+1iJ04olWMh33Dw$fPkXpfwAf4U6Tuk94Cu2v5CoBd8Ffjfa9IE3/IYVS5A"
```
**Output:**
```json
{
  "success": true,
  "data": {
    "valid": true
  }
}
```

### Example 2: Invalid Password Verification
**Input:**
```
Password: "wrongpassword"
Hash: "$argon2id$v=19$m=65536,t=3,p=4$vYIf7t4+1iJ04olWMh33Dw$fPkXpfwAf4U6Tuk94Cu2v5CoBd8Ffjfa9IE3/IYVS5A"
```
**Output:**
```json
{
  "success": true,
  "data": {
    "valid": false
  }
}
```

### Example 3: Strong Password Verification
**Input:**
```
Password: "MySecureP@ssw0rd!"
Hash: "$argon2id$v=19$m=65536,t=3,p=4$7XLx8P5WoIYVqRnhuQaeWA$80hmsCpZQGcUbwKUFtUJaEQOFif7ckrYgypw+sY+C88"
```
**Output:**
```json
{
  "success": true,
  "data": {
    "valid": true
  }
}
```

### Example 4: Simple Password Verification
**Input:**
```
Password: "simple"
Hash: "$argon2id$v=19$m=65536,t=3,p=4$NwW+1QdBtnu89CbhuQh9jQ$H3IT2YwI6z4H3G5YYEe8O4/shGtMg0BJ3uQ4teT2sy0"
```
**Output:**
```json
{
  "success": true,
  "data": {
    "valid": true
  }
}
```

### Example 5: Numeric Password Verification
**Input:**
```
Password: "123456"
Hash: "$argon2id$v=19$m=65536,t=3,p=4$8PChhZvm6rD5afpt2Wddvg$WP7KRar7LoVW+AQFlLRf+8rsrgmSWGlfr08bxcpoFcc"
```
**Output:**
```json
{
  "success": true,
  "data": {
    "valid": true
  }
}
```

## Use Cases
- User authentication systems
- Secure password storage
- Login verification
- Password change validation
- Multi-factor authentication systems

## Argon2id Parameters
- **Memory cost (m)**: 65536 KB (64 MB)
- **Time cost (t)**: 3 iterations
- **Parallelism (p)**: 4 threads
- **Version**: 19 (latest)

## Security Benefits
- **Memory-hard**: Resistant to ASIC and GPU attacks
- **Side-channel resistant**: Protects against timing attacks
- **Configurable**: Adjustable memory, time, and parallelism costs
- **Winner of PHC**: Password Hashing Competition winner
- **Future-proof**: Can increase parameters as hardware improves