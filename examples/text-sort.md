# Text Sorting

Sort text lines alphabetically or numerically, with optional reverse ordering.

## Tool: `mcp_dev_utilities_mcp_text_sort`

### Example 1: Alphabetical Sorting
**Input:**
```
Content: "zebra\napple\nbanana\ncherry\ndog"
Sort Type: alphabetical
```
**Output:**
```json
{
  "data": {
    "result": "apple\nbanana\ncherry\ndog\nzebra"
  },
  "success": true
}
```

### Example 2: Numerical Sorting
**Input:**
```
Content: "100\n5\n25\n1\n300"
Sort Type: numerical
```
**Output:**
```json
{
  "data": {
    "result": "1\n5\n25\n100\n300"
  },
  "success": true
}
```

### Example 3: Reverse Alphabetical Sorting
**Input:**
```
Content: "alpha\nbeta\ngamma\ndelta"
Sort Type: alphabetical
Reverse: true
```
**Output:**
```json
{
  "data": {
    "result": "gamma\ndelta\nbeta\nalpha"
  },
  "success": true
}
```

### Example 4: Sorting Names
**Input:**
```
Content: "John Smith\nAlice Johnson\nBob Wilson\nCarol Davis"
Sort Type: alphabetical
```
**Output:**
```json
{
  "data": {
    "result": "Alice Johnson\nBob Wilson\nCarol Davis\nJohn Smith"
  },
  "success": true
}
```

### Example 5: Reverse Numerical Sorting
**Input:**
```
Content: "3.14\n2.71\n1.41\n0.57"
Sort Type: numerical
Reverse: true
```
**Output:**
```json
{
  "data": {
    "result": "3.14\n2.71\n1.41\n0.57"
  },
  "success": true
}
```

## Sort Types

### Alphabetical Sorting
- Sorts lines in lexicographical order
- Case-sensitive by default
- Useful for organizing lists, names, or text data

### Numerical Sorting
- Sorts lines as numbers (integers or decimals)
- Handles negative numbers correctly
- Non-numeric lines are treated as 0
- Useful for sorting data files, scores, or measurements

## Parameters

### `sort_type` (required)
- `"alphabetical"`: Sort lines as text
- `"numerical"`: Sort lines as numbers

### `reverse` (optional)
- `false` (default): Ascending order (A-Z, 0-9)
- `true`: Descending order (Z-A, 9-0)

## Use Cases

### Development
- Sorting import statements
- Organizing configuration files
- Arranging CSS properties
- Ordering API endpoints

### Data Processing
- Sorting CSV data
- Organizing log entries
- Arranging database results
- Processing survey responses

### Content Management
- Alphabetizing lists
- Organizing documentation sections
- Sorting menu items
- Arranging bibliography entries

### System Administration
- Sorting file lists
- Organizing user accounts
- Arranging server configurations
- Processing system logs

## Examples by Use Case

### Sorting CSS Properties
```
Input:
z-index
margin
padding
background
color

Output:
background
color
margin
padding
z-index
```

### Sorting Version Numbers
```
Input:
1.10.0
1.2.0
1.9.0
2.0.0
1.1.0

Output (numerical):
1.1.0
1.2.0
1.9.0
1.10.0
2.0.0
```

### Sorting File Sizes
```
Input:
1024
512
2048
256
4096

Output (numerical):
256
512
1024
2048
4096
```

## Notes
- Each line is treated as a separate item to sort
- Empty lines are preserved and sorted to the beginning
- For numerical sorting, non-numeric content is treated as 0
- Sorting is stable (equal elements maintain their relative order)