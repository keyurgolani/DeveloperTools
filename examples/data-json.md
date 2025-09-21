# JSON Formatting

Format and minify JSON data with customizable indentation for better readability or compact storage.

## Tool: `mcp_dev_utilities_mcp_data_json_format`

### Example 1: Format JSON with Default Indentation
**Input:**
```
Content: "{\"name\":\"John\",\"age\":30,\"city\":\"New York\",\"hobbies\":[\"reading\",\"swimming\"]}"
Action: format
```
**Output:**
```json
{
  "data": {
    "result": "{\n  \"age\": 30,\n  \"city\": \"New York\",\n  \"hobbies\": [\n    \"reading\",\n    \"swimming\"\n  ],\n  \"name\": \"John\"\n}"
  },
  "success": true
}
```

### Example 2: Minify Formatted JSON
**Input:**
```
Content: "{\n  \"users\": [\n    {\n      \"id\": 1,\n      \"name\": \"Alice\",\n      \"email\": \"alice@example.com\"\n    },\n    {\n      \"id\": 2,\n      \"name\": \"Bob\",\n      \"email\": \"bob@example.com\"\n    }\n  ]\n}"
Action: minify
```
**Output:**
```json
{
  "data": {
    "result": "{\"users\":[{\"email\":\"alice@example.com\",\"id\":1,\"name\":\"Alice\"},{\"email\":\"bob@example.com\",\"id\":2,\"name\":\"Bob\"}]}"
  },
  "success": true
}
```

### Example 3: Format with 4-Space Indentation
**Input:**
```
Content: "{\"api\":{\"version\":\"1.0\",\"endpoints\":[\"/users\",\"/posts\",\"/comments\"]},\"config\":{\"debug\":true,\"timeout\":5000}}"
Action: format
Indent: 4
```
**Output:**
```json
{
  "data": {
    "result": "{\n    \"api\": {\n        \"endpoints\": [\n            \"/users\",\n            \"/posts\",\n            \"/comments\"\n        ],\n        \"version\": \"1.0\"\n    },\n    \"config\": {\n        \"debug\": true,\n        \"timeout\": 5000\n    }\n}"
  },
  "success": true
}
```

### Example 4: Format with 8-Space Indentation
**Input:**
```
Content: "{\"nested\":{\"deeply\":{\"very\":{\"much\":\"value\"}}}}"
Action: format
Indent: 8
```
**Output:**
```json
{
  "data": {
    "result": "{\n        \"nested\": {\n                \"deeply\": {\n                        \"very\": {\n                                \"much\": \"value\"\n                        }\n                }\n        }\n}"
  },
  "success": true
}
```

### Example 5: Minify Simple JSON
**Input:**
```
Content: "{\n  \"message\": \"Hello World\",\n  \"timestamp\": \"2024-01-01T00:00:00Z\",\n  \"data\": null,\n  \"success\": true\n}"
Action: minify
```
**Output:**
```json
{
  "data": {
    "result": "{\"data\":null,\"message\":\"Hello World\",\"success\":true,\"timestamp\":\"2024-01-01T00:00:00Z\"}"
  },
  "success": true
}
```

## Actions

### Format
- **Purpose**: Make JSON human-readable with proper indentation
- **Default indent**: 2 spaces
- **Customizable**: 0-8 spaces indentation
- **Sorting**: Keys are automatically sorted alphabetically
- **Use cases**: Development, debugging, documentation

### Minify
- **Purpose**: Remove all unnecessary whitespace
- **Result**: Single-line compact JSON
- **Sorting**: Keys are automatically sorted alphabetically
- **Use cases**: Production APIs, data transmission, storage optimization

## Indentation Options

### 0 Spaces (Compact Format)
```json
{
"name": "John",
"age": 30
}
```

### 2 Spaces (Default)
```json
{
  "name": "John",
  "age": 30
}
```

### 4 Spaces (Common Standard)
```json
{
    "name": "John",
    "age": 30
}
```

### 8 Spaces (High Readability)
```json
{
        "name": "John",
        "age": 30
}
```

## Use Cases

### API Development
```javascript
// Format API responses for debugging
const apiResponse = {
  status: 'success',
  data: { users: [{ id: 1, name: 'John' }] },
  meta: { total: 1, page: 1 }
};

const formatted = formatJSON(JSON.stringify(apiResponse), 'format', 2);
console.log(formatted); // Pretty-printed for debugging
```

### Configuration Files
```javascript
// Format configuration files for readability
const config = {
  database: { host: 'localhost', port: 5432 },
  redis: { host: 'localhost', port: 6379 },
  logging: { level: 'info', file: 'app.log' }
};

const formattedConfig = formatJSON(JSON.stringify(config), 'format', 4);
// Save to config.json with 4-space indentation
```

### Data Processing
```javascript
// Minify JSON for transmission
const largeDataset = {
  records: Array.from({ length: 1000 }, (_, i) => ({
    id: i,
    name: `User ${i}`,
    email: `user${i}@example.com`
  }))
};

const minified = formatJSON(JSON.stringify(largeDataset), 'minify');
// Reduced size for network transmission
```

### Log Processing
```javascript
// Format log entries for analysis
const logEntry = {
  timestamp: '2024-01-01T12:00:00Z',
  level: 'ERROR',
  message: 'Database connection failed',
  context: { host: 'db.example.com', port: 5432 }
};

const readableLog = formatJSON(JSON.stringify(logEntry), 'format', 2);
// Easy to read in log files
```

### Code Generation
```javascript
// Generate formatted JSON for code templates
const schema = {
  type: 'object',
  properties: {
    name: { type: 'string' },
    age: { type: 'number' }
  },
  required: ['name']
};

const formattedSchema = formatJSON(JSON.stringify(schema), 'format', 2);
// Use in code generation templates
```

## Common Patterns

### Environment-Specific Formatting
```javascript
// Different formatting for different environments
function formatForEnvironment(data, environment) {
  const jsonString = JSON.stringify(data);
  
  if (environment === 'development') {
    return formatJSON(jsonString, 'format', 4); // Readable
  } else {
    return formatJSON(jsonString, 'minify'); // Compact for production
  }
}
```

### File Processing
```javascript
// Process JSON files with consistent formatting
async function processJSONFile(filePath, action = 'format', indent = 2) {
  const content = await fs.readFile(filePath, 'utf8');
  const formatted = formatJSON(content, action, indent);
  await fs.writeFile(filePath, formatted);
  return formatted;
}
```

### API Response Formatting
```javascript
// Format API responses based on client preferences
function formatAPIResponse(data, clientPreferences) {
  const jsonString = JSON.stringify(data);
  
  if (clientPreferences.pretty) {
    return formatJSON(jsonString, 'format', clientPreferences.indent || 2);
  } else {
    return formatJSON(jsonString, 'minify');
  }
}
```

### Validation and Formatting
```javascript
// Validate and format JSON in one step
function validateAndFormat(jsonString, action = 'format', indent = 2) {
  try {
    // Validate by parsing
    JSON.parse(jsonString);
    
    // Format if valid
    return {
      valid: true,
      formatted: formatJSON(jsonString, action, indent)
    };
  } catch (error) {
    return {
      valid: false,
      error: error.message
    };
  }
}
```

## Best Practices

### Input Validation
```javascript
function safeFormatJSON(content, action, indent) {
  try {
    // Validate JSON syntax
    JSON.parse(content);
    
    // Validate parameters
    if (!['format', 'minify'].includes(action)) {
      throw new Error('Action must be "format" or "minify"');
    }
    
    if (indent < 0 || indent > 8) {
      throw new Error('Indent must be between 0 and 8');
    }
    
    return formatJSON(content, action, indent);
  } catch (error) {
    return {
      error: error.message,
      input: content
    };
  }
}
```

### Performance Considerations
```javascript
// Cache formatted results for large JSON
const formatCache = new Map();

function cachedFormatJSON(content, action, indent) {
  const cacheKey = `${content.length}:${action}:${indent}`;
  
  if (formatCache.has(cacheKey)) {
    return formatCache.get(cacheKey);
  }
  
  const result = formatJSON(content, action, indent);
  formatCache.set(cacheKey, result);
  
  return result;
}
```

### Batch Processing
```javascript
// Process multiple JSON strings
function batchFormatJSON(jsonStrings, action, indent) {
  return jsonStrings.map((json, index) => {
    try {
      return {
        index,
        success: true,
        result: formatJSON(json, action, indent)
      };
    } catch (error) {
      return {
        index,
        success: false,
        error: error.message
      };
    }
  });
}
```

### Size Optimization
```javascript
// Calculate size savings from minification
function analyzeSizeSavings(jsonString) {
  const original = jsonString;
  const minified = formatJSON(jsonString, 'minify');
  
  return {
    originalSize: original.length,
    minifiedSize: minified.length,
    savings: original.length - minified.length,
    savingsPercent: ((original.length - minified.length) / original.length * 100).toFixed(2)
  };
}
```

## Integration Examples

### Express.js Middleware
```javascript
// Middleware to format JSON responses
function jsonFormatterMiddleware(req, res, next) {
  const originalJson = res.json;
  
  res.json = function(data) {
    if (req.query.pretty === 'true') {
      const formatted = formatJSON(JSON.stringify(data), 'format', 2);
      res.set('Content-Type', 'application/json');
      return res.send(formatted);
    }
    
    return originalJson.call(this, data);
  };
  
  next();
}
```

### CLI Tool Integration
```javascript
// Command-line JSON formatter
function cliFormatter(inputFile, outputFile, options) {
  const content = fs.readFileSync(inputFile, 'utf8');
  const formatted = formatJSON(
    content, 
    options.minify ? 'minify' : 'format',
    options.indent || 2
  );
  
  if (outputFile) {
    fs.writeFileSync(outputFile, formatted);
  } else {
    console.log(formatted);
  }
}
```

### Build Tool Integration
```javascript
// Webpack plugin for JSON formatting
class JSONFormatterPlugin {
  constructor(options = {}) {
    this.options = {
      action: options.minify ? 'minify' : 'format',
      indent: options.indent || 2
    };
  }
  
  apply(compiler) {
    compiler.hooks.emit.tapAsync('JSONFormatterPlugin', (compilation, callback) => {
      Object.keys(compilation.assets).forEach(filename => {
        if (filename.endsWith('.json')) {
          const asset = compilation.assets[filename];
          const formatted = formatJSON(
            asset.source(),
            this.options.action,
            this.options.indent
          );
          
          compilation.assets[filename] = {
            source: () => formatted,
            size: () => formatted.length
          };
        }
      });
      
      callback();
    });
  }
}
```

## Common Use Cases by Industry

### Web Development
- API response formatting
- Configuration file management
- Build tool integration
- Development debugging

### Data Engineering
- ETL pipeline data formatting
- Log processing and analysis
- Data warehouse preparation
- Configuration management

### DevOps
- Infrastructure as Code formatting
- CI/CD pipeline configuration
- Monitoring and alerting setup
- Container orchestration configs

### Mobile Development
- App configuration files
- API response processing
- Local storage optimization
- Debug output formatting