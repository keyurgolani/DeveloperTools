# X.509 Certificate Decoding

Decode PEM-encoded X.509 certificates to extract certificate information including subject, issuer, validity dates, and other metadata.

## Tool: `mcp_dev_utilities_mcp_crypto_cert_decode`

### Example 1: Self-Signed Certificate
**Input:**
```
Certificate: "-----BEGIN CERTIFICATE-----
MIIDSjCCAjICCQCZNYufeYkJETANBgkqhkiG9w0BAQsFADBnMQswCQYDVQQGEwJV
UzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzEV
MBMGA1UECgwMRXhhbXBsZSBDb3JwMRQwEgYDVQQDDAtleGFtcGxlLmNvbTAeFw0y
NTA5MjEwNTU5MTJaFw0yNjA5MjEwNTU5MTJaMGcxCzAJBgNVBAYTAlVTMRMwEQYD
VQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMRUwEwYDVQQK
DAxFeGFtcGxlIENvcnAxFDASBgNVBAMMC2V4YW1wbGUuY29tMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxBmsMswO9IHuZuEDNw4u/ryFVE60gpgw5uDH
8X7aTSgWwoCjieqS9Wyg+lxRzq9Nf1cOGskSM/K56EJTbKtsIHVTcKVcKaod23Ay
yLxornVeb/CfipkVw+f3ED2burk8r2ObuVd81l13jkUhauFtGlig4KrDuo7wRTHT
GtwHvYq7JEC4QLVqF6VXF7GiMGprwuMBHt4R1RZ2YT1H8Xz6i3T7nozjNAO+C3K9
a6AjqsRo4HvCXemCVgWnNyN7EIvUaWEjFwZxp5TnEqoG9+ZbovS7fPe7LpZO/DQ6
9XfyOqnbl543g++YPOVQB2LoCxwAR0IUg/AmR8STytj9lyUTrwIDAQABMA0GCSqG
SIb3DQEBCwUAA4IBAQAzcGs6OjGPjEzloshNY1sgca6FU+4TltwloWwM6akLZToY
buVl3rHUM31ZW4F4MY/yQ8B6G3i+SF7MFjFCrD+m2IrcBBL+tlQ2ItBfLRSaVKgz
O51hfKrf8oqhVvXd71nNwLqaRj78RvMc9tb9QH2gRKo0qLrOqxEcRuQUQfsLheDd
afehMeNf3xHgUSO6YLmaGd5yz1v3bIWak8wrggoGDT1Z6UGSMMeVU0ofkIjWp55O
dVWCB+tTQ1DPOMZGPRJsgsgV5EH+iYIa08ElNIbBpFOLc5R9hlZAtVeq9OvD9Cvu
xjDYtBoxgRCU/DNkb+WIYf7YSX2nT/F4So2T2/yh
-----END CERTIFICATE-----"
```
**Output:**
```json
{
  "success": true,
  "data": {
    "certificate": {
      "subject": "CN=example.com,O=Example Corp,L=San Francisco,ST=California,C=US",
      "issuer": "CN=example.com,O=Example Corp,L=San Francisco,ST=California,C=US",
      "notBefore": "2025-09-21T05:59:12Z",
      "notAfter": "2026-09-21T05:59:12Z",
      "serialNumber": "11039883578623723793",
      "version": 1,
      "keyUsage": []
    }
  }
}
```

## Certificate Components Explained

### Subject
- **Description**: The entity the certificate is issued to
- **Format**: Distinguished Name (DN) with components like CN, O, L, ST, C
- **Example**: `CN=example.com,O=Example Corp,L=San Francisco,ST=California,C=US`

### Issuer
- **Description**: The entity that issued the certificate
- **Format**: Distinguished Name (DN)
- **Self-signed**: Subject and issuer are the same

### Validity Period
- **notBefore**: Certificate is not valid before this date
- **notAfter**: Certificate expires after this date
- **Format**: ISO 8601 UTC timestamp

### Serial Number
- **Description**: Unique identifier assigned by the issuer
- **Format**: Large integer
- **Purpose**: Certificate revocation and identification

### Version
- **Description**: X.509 certificate version
- **Values**: 1, 2, or 3 (most common)
- **Features**: Higher versions support more extensions

## Use Cases

### SSL/TLS Certificate Validation
```javascript
// Validate certificate expiration
function validateCertificateExpiry(certPem) {
  const decoded = decodeCertificate(certPem);
  const now = new Date();
  const notAfter = new Date(decoded.certificate.notAfter);
  const notBefore = new Date(decoded.certificate.notBefore);
  
  return {
    isValid: now >= notBefore && now <= notAfter,
    daysUntilExpiry: Math.ceil((notAfter - now) / (1000 * 60 * 60 * 24)),
    expired: now > notAfter,
    notYetValid: now < notBefore
  };
}
```

### Certificate Chain Analysis
```javascript
// Analyze certificate chain
function analyzeCertificateChain(certChain) {
  const certificates = certChain.map(cert => decodeCertificate(cert));
  
  return certificates.map((cert, index) => ({
    position: index,
    subject: cert.certificate.subject,
    issuer: cert.certificate.issuer,
    isSelfSigned: cert.certificate.subject === cert.certificate.issuer,
    isRoot: index === certificates.length - 1,
    serialNumber: cert.certificate.serialNumber
  }));
}
```

### Domain Validation
```javascript
// Extract domain from certificate
function extractDomainFromCert(certPem) {
  const decoded = decodeCertificate(certPem);
  const subject = decoded.certificate.subject;
  
  // Extract CN (Common Name)
  const cnMatch = subject.match(/CN=([^,]+)/);
  const commonName = cnMatch ? cnMatch[1] : null;
  
  return {
    commonName,
    subject: subject,
    isWildcard: commonName?.startsWith('*.') || false
  };
}
```

### Certificate Monitoring
```javascript
// Monitor certificate expiration
function monitorCertificateExpiration(certPem, warningDays = 30) {
  const decoded = decodeCertificate(certPem);
  const expiryDate = new Date(decoded.certificate.notAfter);
  const now = new Date();
  const daysUntilExpiry = Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24));
  
  return {
    status: daysUntilExpiry <= 0 ? 'expired' :
            daysUntilExpiry <= warningDays ? 'warning' : 'valid',
    daysUntilExpiry,
    expiryDate: decoded.certificate.notAfter,
    needsRenewal: daysUntilExpiry <= warningDays
  };
}
```

### Security Audit
```javascript
// Audit certificate security
function auditCertificateSecurity(certPem) {
  const decoded = decodeCertificate(certPem);
  const cert = decoded.certificate;
  
  const now = new Date();
  const validityPeriod = new Date(cert.notAfter) - new Date(cert.notBefore);
  const validityYears = validityPeriod / (1000 * 60 * 60 * 24 * 365);
  
  return {
    isSelfSigned: cert.subject === cert.issuer,
    validityPeriodYears: Math.round(validityYears * 10) / 10,
    isExpired: new Date(cert.notAfter) < now,
    serialNumber: cert.serialNumber,
    version: cert.version,
    keyUsage: cert.keyUsage
  };
}
```

## Common Certificate Types

### Self-Signed Certificates
- **Issuer**: Same as subject
- **Trust**: Not trusted by browsers by default
- **Use cases**: Development, internal services, testing

### Domain Validated (DV) Certificates
- **Validation**: Domain ownership only
- **Issuer**: Certificate Authority (CA)
- **Use cases**: Basic HTTPS for websites

### Organization Validated (OV) Certificates
- **Validation**: Domain + organization identity
- **Issuer**: Certificate Authority (CA)
- **Use cases**: Business websites, higher trust

### Extended Validation (EV) Certificates
- **Validation**: Extensive organization verification
- **Issuer**: Certificate Authority (CA)
- **Use cases**: High-security websites, e-commerce

## Best Practices

### Certificate Validation
```javascript
function validateCertificate(certPem) {
  try {
    const decoded = decodeCertificate(certPem);
    const cert = decoded.certificate;
    
    // Basic validation checks
    const now = new Date();
    const notBefore = new Date(cert.notBefore);
    const notAfter = new Date(cert.notAfter);
    
    return {
      valid: true,
      checks: {
        notExpired: now <= notAfter,
        notYetValid: now >= notBefore,
        hasSubject: !!cert.subject,
        hasIssuer: !!cert.issuer,
        hasSerialNumber: !!cert.serialNumber
      }
    };
  } catch (error) {
    return {
      valid: false,
      error: error.message
    };
  }
}
```

### Certificate Comparison
```javascript
function compareCertificates(cert1Pem, cert2Pem) {
  const cert1 = decodeCertificate(cert1Pem);
  const cert2 = decodeCertificate(cert2Pem);
  
  return {
    sameSubject: cert1.certificate.subject === cert2.certificate.subject,
    sameIssuer: cert1.certificate.issuer === cert2.certificate.issuer,
    sameSerial: cert1.certificate.serialNumber === cert2.certificate.serialNumber,
    sameValidity: cert1.certificate.notBefore === cert2.certificate.notBefore &&
                  cert1.certificate.notAfter === cert2.certificate.notAfter
  };
}
```

### Error Handling
```javascript
function safeCertificateDecode(certPem) {
  try {
    return {
      success: true,
      data: decodeCertificate(certPem)
    };
  } catch (error) {
    return {
      success: false,
      error: error.message,
      type: 'decode_error'
    };
  }
}
```

## Integration Examples

### Express.js Certificate Middleware
```javascript
function certificateValidationMiddleware(req, res, next) {
  const clientCert = req.connection.getPeerCertificate();
  
  if (clientCert && Object.keys(clientCert).length > 0) {
    const certPem = `-----BEGIN CERTIFICATE-----\n${clientCert.raw.toString('base64')}\n-----END CERTIFICATE-----`;
    const decoded = decodeCertificate(certPem);
    
    req.clientCertificate = decoded.certificate;
    req.certificateValid = validateCertificate(certPem);
  }
  
  next();
}
```

### Certificate Renewal Checker
```javascript
async function checkCertificateRenewal(domain) {
  // This would typically fetch the certificate from the domain
  // For this example, assume we have the certificate PEM
  const certPem = await fetchCertificateFromDomain(domain);
  const decoded = decodeCertificate(certPem);
  
  const expiryDate = new Date(decoded.certificate.notAfter);
  const now = new Date();
  const daysUntilExpiry = Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24));
  
  if (daysUntilExpiry <= 30) {
    await sendRenewalAlert(domain, daysUntilExpiry);
  }
  
  return {
    domain,
    expiryDate: decoded.certificate.notAfter,
    daysUntilExpiry,
    needsRenewal: daysUntilExpiry <= 30
  };
}
```

## Sample Certificate

A sample certificate is available in the examples directory:
- **File**: `examples/sample-certificate.pem`
- **Type**: Self-signed certificate
- **Subject**: CN=example.com,O=Example Corp,L=San Francisco,ST=California,C=US
- **Valid**: 1 year from generation date
- **Use**: Testing and development purposes only

## Security Notes

### Certificate Validation
- Always validate certificate chains in production
- Check certificate revocation status (CRL/OCSP)
- Verify certificate matches the expected domain
- Implement proper certificate pinning for critical applications

### Trust Considerations
- Self-signed certificates should not be trusted in production
- Always validate against trusted Certificate Authorities
- Implement certificate transparency monitoring
- Regular certificate rotation and renewal