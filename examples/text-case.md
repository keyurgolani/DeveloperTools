# Text Case Conversion

Convert text between different case formats commonly used in programming and documentation.

## Tool: `mcp_dev_utilities_mcp_text_case_convert`

### Example 1: Convert to Uppercase
**Input:**
```
Content: "hello world"
Case Type: uppercase
```
**Output:**
```json
{
  "data": {
    "result": "HELLO WORLD",
    "caseType": "UPPERCASE"
  },
  "success": true
}
```

### Example 2: Convert to Camel Case
**Input:**
```
Content: "hello world from api"
Case Type: camel
```
**Output:**
```json
{
  "data": {
    "result": "helloWorldFromApi",
    "caseType": "camelCase"
  },
  "success": true
}
```

### Example 3: Convert to Snake Case
**Input:**
```
Content: "Convert This To Snake Case"
Case Type: snake
```
**Output:**
```json
{
  "data": {
    "result": "convert_this_to_snake_case",
    "caseType": "snake_case"
  },
  "success": true
}
```

### Example 4: Convert to Kebab Case
**Input:**
```
Content: "My API Endpoint Name"
Case Type: kebab
```
**Output:**
```json
{
  "data": {
    "result": "my-api-endpoint-name",
    "caseType": "kebab-case"
  },
  "success": true
}
```

### Example 5: Convert to Pascal Case
**Input:**
```
Content: "user authentication service"
Case Type: pascal
```
**Output:**
```json
{
  "data": {
    "result": "UserAuthenticationService",
    "caseType": "PascalCase"
  },
  "success": true
}
```

## Supported Case Types

### `uppercase`
Converts all characters to uppercase.
- **Use case**: Constants, environment variables
- **Example**: `HELLO WORLD`

### `lowercase`
Converts all characters to lowercase.
- **Use case**: File names, URLs
- **Example**: `hello world`

### `title`
Capitalizes the first letter of each word.
- **Use case**: Titles, headings
- **Example**: `Hello World`

### `camel`
First word lowercase, subsequent words capitalized, no spaces.
- **Use case**: JavaScript variables, JSON properties
- **Example**: `helloWorld`

### `pascal`
All words capitalized, no spaces.
- **Use case**: Class names, type names
- **Example**: `HelloWorld`

### `snake`
All lowercase with underscores between words.
- **Use case**: Python variables, database columns
- **Example**: `hello_world`

### `kebab`
All lowercase with hyphens between words.
- **Use case**: CSS classes, URL slugs, HTML attributes
- **Example**: `hello-world`

## Common Use Cases
- **API Development**: Converting between different naming conventions
- **Code Generation**: Transforming user input to proper variable names
- **Documentation**: Standardizing naming across different systems
- **Database Design**: Converting field names between conventions
- **URL Generation**: Creating SEO-friendly slugs from titles