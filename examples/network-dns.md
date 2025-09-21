# DNS Lookup

Perform DNS lookups for various record types including A, AAAA, MX, TXT, NS, and CNAME records.

## Tool: `mcp_dev_utilities_mcp_network_dns_lookup`

### Example 1: A Record Lookup (IPv4)
**Input:**
```
Domain: "google.com"
Record Type: A
```
**Output:**
```json
{
  "data": {
    "domain": "google.com",
    "recordType": "A",
    "records": [
      "142.250.217.78"
    ]
  },
  "success": true
}
```

### Example 2: MX Record Lookup (Mail Exchange)
**Input:**
```
Domain: "gmail.com"
Record Type: MX
```
**Output:**
```json
{
  "data": {
    "domain": "gmail.com",
    "recordType": "MX",
    "records": [
      "5 gmail-smtp-in.l.google.com.",
      "10 alt1.gmail-smtp-in.l.google.com.",
      "20 alt2.gmail-smtp-in.l.google.com.",
      "30 alt3.gmail-smtp-in.l.google.com.",
      "40 alt4.gmail-smtp-in.l.google.com."
    ]
  },
  "success": true
}
```

### Example 3: AAAA Record Lookup (IPv6)
**Input:**
```
Domain: "google.com"
Record Type: AAAA
```
**Output:**
```json
{
  "data": {
    "domain": "google.com",
    "recordType": "AAAA",
    "records": [
      "2607:f8b0:400a:80a::200e"
    ]
  },
  "success": true
}
```

### Example 4: NS Record Lookup (Name Servers)
**Input:**
```
Domain: "example.com"
Record Type: NS
```
**Output:**
```json
{
  "data": {
    "domain": "example.com",
    "recordType": "NS",
    "records": [
      "b.iana-servers.net.",
      "a.iana-servers.net."
    ]
  },
  "success": true
}
```

### Example 5: TXT Record Lookup
**Input:**
```
Domain: "google.com"
Record Type: TXT
```
**Output:**
```json
{
  "data": {
    "domain": "google.com",
    "recordType": "TXT",
    "records": [
      "docusign=05958488-4752-4ef2-95eb-aa7ba8a3bd0e",
      "google-site-verification=TV9-DBe4R80X4v0M4U_bd_J9cpOJM0nikft0jAgjmsQ",
      "onetrust-domain-verification=de01ed21f2fa4d8781cbc3ffb89cf4ef",
      "google-site-verification=4ibFUgB-wXLQ_S7vsXVomSTVamuOXBiVAzpR5IZ87D0",
      "docusign=1b0a6754-49b1-4db5-8540-d2c12664b289",
      "MS=E4A68B9AB2BB9670BCE15412F62916164C0B20BB",
      "cisco-ci-domain-verification=47c38bc8c4b74b7233e9053220c1bbe76bcc1cd33c7acf7acd36cd6a5332004b",
      "v=spf1 include:_spf.google.com ~all",
      "facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95",
      "globalsign-smime-dv=CDYX+XFHUw2wml6/Gb8+59BsH31KzUr6c1l2BPvqKX8=",
      "apple-domain-verification=30afIBcvSuDV2PLX",
      "google-site-verification=wD8N7i1JTNTkezJ49swvWW48f8_9xveREV4oB-0Hf5o"
    ]
  },
  "success": true
}
```

## DNS Record Types

### A Record (Address)
- **Purpose**: Maps domain name to IPv4 address
- **Format**: `domain.com -> 192.0.2.1`
- **Use cases**: Website hosting, service endpoints
- **TTL**: Typically 300-3600 seconds

### AAAA Record (IPv6 Address)
- **Purpose**: Maps domain name to IPv6 address
- **Format**: `domain.com -> 2001:db8::1`
- **Use cases**: IPv6-enabled services
- **Modern requirement**: Essential for IPv6 connectivity

### MX Record (Mail Exchange)
- **Purpose**: Specifies mail servers for domain
- **Format**: `priority hostname` (e.g., `10 mail.example.com.`)
- **Priority**: Lower numbers = higher priority
- **Use cases**: Email routing, spam filtering

### TXT Record (Text)
- **Purpose**: Stores arbitrary text data
- **Format**: Free-form text strings
- **Use cases**: Domain verification, SPF, DKIM, DMARC
- **Common prefixes**: `v=spf1`, `v=DKIM1`, `v=DMARC1`

### NS Record (Name Server)
- **Purpose**: Delegates DNS zone to authoritative servers
- **Format**: `domain.com -> ns1.provider.com.`
- **Use cases**: DNS delegation, zone management
- **Critical**: Required for domain resolution

### CNAME Record (Canonical Name)
- **Purpose**: Creates alias from one domain to another
- **Format**: `alias.com -> canonical.com.`
- **Limitation**: Cannot coexist with other record types
- **Use cases**: CDN aliases, service endpoints

## Use Cases

### Domain Verification
```javascript
// Verify domain ownership via TXT records
async function verifyDomainOwnership(domain, expectedToken) {
  const txtRecords = await dnsLookup(domain, 'TXT');
  
  const verificationRecord = txtRecords.records.find(record => 
    record.includes(`verification-token=${expectedToken}`)
  );
  
  return !!verificationRecord;
}
```

### Email Configuration Validation
```javascript
// Check email server configuration
async function validateEmailConfig(domain) {
  const mxRecords = await dnsLookup(domain, 'MX');
  const txtRecords = await dnsLookup(domain, 'TXT');
  
  const spfRecord = txtRecords.records.find(record => 
    record.startsWith('v=spf1')
  );
  
  const dmarcRecord = txtRecords.records.find(record => 
    record.startsWith('v=DMARC1')
  );
  
  return {
    hasMX: mxRecords.records.length > 0,
    hasSPF: !!spfRecord,
    hasDMARC: !!dmarcRecord,
    mxCount: mxRecords.records.length
  };
}
```

### Load Balancer Health Check
```javascript
// Check if domain resolves to expected IPs
async function validateLoadBalancer(domain, expectedIPs) {
  const aRecords = await dnsLookup(domain, 'A');
  const actualIPs = aRecords.records;
  
  const missingIPs = expectedIPs.filter(ip => !actualIPs.includes(ip));
  const unexpectedIPs = actualIPs.filter(ip => !expectedIPs.includes(ip));
  
  return {
    isHealthy: missingIPs.length === 0 && unexpectedIPs.length === 0,
    missingIPs,
    unexpectedIPs,
    actualIPs
  };
}
```

### CDN Configuration Check
```javascript
// Verify CDN setup
async function verifyCDNSetup(domain, cdnProvider) {
  const aRecords = await dnsLookup(domain, 'A');
  const cnameRecords = await dnsLookup(domain, 'CNAME');
  
  const cdnPatterns = {
    cloudflare: /cloudflare/i,
    fastly: /fastly/i,
    cloudfront: /cloudfront/i
  };
  
  const pattern = cdnPatterns[cdnProvider.toLowerCase()];
  const usesCDN = cnameRecords.records.some(record => pattern.test(record));
  
  return {
    usesCDN,
    records: [...aRecords.records, ...cnameRecords.records]
  };
}
```

### Security Analysis
```javascript
// Analyze domain security configuration
async function analyzeDomainSecurity(domain) {
  const txtRecords = await dnsLookup(domain, 'TXT');
  
  const spfRecord = txtRecords.records.find(r => r.startsWith('v=spf1'));
  const dmarcRecord = txtRecords.records.find(r => r.startsWith('v=DMARC1'));
  const dkimRecords = txtRecords.records.filter(r => r.includes('v=DKIM1'));
  
  return {
    emailSecurity: {
      spf: {
        present: !!spfRecord,
        record: spfRecord,
        strict: spfRecord?.includes('-all') || false
      },
      dmarc: {
        present: !!dmarcRecord,
        record: dmarcRecord,
        policy: dmarcRecord?.match(/p=(\w+)/)?.[1] || 'none'
      },
      dkim: {
        present: dkimRecords.length > 0,
        count: dkimRecords.length
      }
    }
  };
}
```

## Common DNS Patterns

### Multi-CDN Setup
```javascript
// Check for multiple CDN providers
async function analyzeMultiCDN(domain) {
  const aRecords = await dnsLookup(domain, 'A');
  
  const cdnProviders = [];
  for (const ip of aRecords.records) {
    const provider = await identifyCDNProvider(ip);
    if (provider) cdnProviders.push(provider);
  }
  
  return {
    providers: [...new Set(cdnProviders)],
    isMultiCDN: new Set(cdnProviders).size > 1
  };
}
```

### Subdomain Discovery
```javascript
// Discover common subdomains
async function discoverSubdomains(domain) {
  const commonSubdomains = ['www', 'api', 'mail', 'ftp', 'admin', 'blog'];
  const results = {};
  
  for (const subdomain of commonSubdomains) {
    try {
      const fullDomain = `${subdomain}.${domain}`;
      const aRecords = await dnsLookup(fullDomain, 'A');
      if (aRecords.records.length > 0) {
        results[subdomain] = aRecords.records;
      }
    } catch (error) {
      // Subdomain doesn't exist
    }
  }
  
  return results;
}
```

### DNS Propagation Check
```javascript
// Check DNS propagation across multiple servers
async function checkDNSPropagation(domain, recordType) {
  const dnsServers = [
    '8.8.8.8',      // Google
    '1.1.1.1',      // Cloudflare
    '208.67.222.222' // OpenDNS
  ];
  
  const results = {};
  
  for (const server of dnsServers) {
    try {
      // Note: This tool doesn't support specifying DNS server
      // This is a conceptual example
      const records = await dnsLookup(domain, recordType);
      results[server] = records.records;
    } catch (error) {
      results[server] = { error: error.message };
    }
  }
  
  return results;
}
```

## Best Practices

### Error Handling
```javascript
async function safeDNSLookup(domain, recordType) {
  try {
    const result = await dnsLookup(domain, recordType);
    return {
      success: true,
      data: result
    };
  } catch (error) {
    return {
      success: false,
      error: error.message,
      domain,
      recordType
    };
  }
}
```

### Caching DNS Results
```javascript
const dnsCache = new Map();
const CACHE_TTL = 300000; // 5 minutes

async function cachedDNSLookup(domain, recordType) {
  const cacheKey = `${domain}:${recordType}`;
  const cached = dnsCache.get(cacheKey);
  
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.data;
  }
  
  const result = await dnsLookup(domain, recordType);
  dnsCache.set(cacheKey, {
    data: result,
    timestamp: Date.now()
  });
  
  return result;
}
```

### Batch DNS Lookups
```javascript
async function batchDNSLookup(domains, recordType) {
  const promises = domains.map(domain => 
    safeDNSLookup(domain, recordType)
  );
  
  const results = await Promise.all(promises);
  
  return domains.reduce((acc, domain, index) => {
    acc[domain] = results[index];
    return acc;
  }, {});
}
```

### Domain Validation
```javascript
function isValidDomain(domain) {
  const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])*$/;
  return domainRegex.test(domain) && domain.length <= 253;
}

async function validateAndLookup(domain, recordType) {
  if (!isValidDomain(domain)) {
    throw new Error('Invalid domain format');
  }
  
  return await dnsLookup(domain, recordType);
}
```

## Security Considerations

### DNS Spoofing Detection
```javascript
// Compare results from multiple sources
async function detectDNSSpoofing(domain) {
  const results = await Promise.all([
    dnsLookup(domain, 'A'),
    // In practice, you'd query different DNS servers
    dnsLookup(domain, 'A'),
    dnsLookup(domain, 'A')
  ]);
  
  const uniqueResults = new Set(
    results.map(r => JSON.stringify(r.records.sort()))
  );
  
  return {
    consistent: uniqueResults.size === 1,
    results: results.map(r => r.records)
  };
}
```

### Malicious Domain Detection
```javascript
// Check for suspicious DNS patterns
async function analyzeDomainSafety(domain) {
  const txtRecords = await dnsLookup(domain, 'TXT');
  const nsRecords = await dnsLookup(domain, 'NS');
  
  const suspiciousPatterns = [
    /malware/i,
    /phishing/i,
    /suspicious/i
  ];
  
  const hasSuspiciousTXT = txtRecords.records.some(record =>
    suspiciousPatterns.some(pattern => pattern.test(record))
  );
  
  return {
    suspicious: hasSuspiciousTXT,
    nameServers: nsRecords.records,
    txtRecords: txtRecords.records
  };
}
```