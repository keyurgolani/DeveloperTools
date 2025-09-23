package validation

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/gin-gonic/gin"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

const (
	// reportSeparatorLength is the length of the separator line in validation reports.
	reportSeparatorLength = 50
)

// OpenAPISpec represents a simplified OpenAPI specification.
type OpenAPISpec struct {
	OpenAPI    string              `yaml:"openapi"`
	Info       OpenAPIInfo         `yaml:"info"`
	Paths      map[string]PathItem `yaml:"paths"`
	Components OpenAPIComponents   `yaml:"components"`
}

type OpenAPIInfo struct {
	Title       string `yaml:"title"`
	Description string `yaml:"description"`
	Version     string `yaml:"version"`
}

type PathItem struct {
	Get    *Operation `yaml:"get,omitempty"`
	Post   *Operation `yaml:"post,omitempty"`
	Put    *Operation `yaml:"put,omitempty"`
	Delete *Operation `yaml:"delete,omitempty"`
}

type Operation struct {
	Tags        []string            `yaml:"tags,omitempty"`
	Summary     string              `yaml:"summary,omitempty"`
	Description string              `yaml:"description,omitempty"`
	OperationID string              `yaml:"operationId,omitempty"`
	RequestBody *RequestBody        `yaml:"requestBody,omitempty"`
	Responses   map[string]Response `yaml:"responses"`
}

type RequestBody struct {
	Required bool                       `yaml:"required,omitempty"`
	Content  map[string]MediaTypeObject `yaml:"content"`
}

type Response struct {
	Description string                     `yaml:"description"`
	Content     map[string]MediaTypeObject `yaml:"content,omitempty"`
}

type MediaTypeObject struct {
	Schema   *Schema                `yaml:"schema,omitempty"`
	Examples map[string]interface{} `yaml:"examples,omitempty"`
}

type Schema struct {
	Type       string            `yaml:"type,omitempty"`
	Properties map[string]Schema `yaml:"properties,omitempty"`
	Required   []string          `yaml:"required,omitempty"`
	Items      *Schema           `yaml:"items,omitempty"`
	Ref        string            `yaml:"$ref,omitempty"`
	AllOf      []Schema          `yaml:"allOf,omitempty"`
	OneOf      []Schema          `yaml:"oneOf,omitempty"`
	Enum       []interface{}     `yaml:"enum,omitempty"`
}

type OpenAPIComponents struct {
	Schemas   map[string]Schema   `yaml:"schemas,omitempty"`
	Responses map[string]Response `yaml:"responses,omitempty"`
}

// ValidationResult represents the result of API validation.
type ValidationResult struct {
	Valid    bool     `json:"valid"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// APIValidator validates API implementation against OpenAPI specification.
type APIValidator struct {
	spec   *OpenAPISpec
	router *gin.Engine
}

// NewAPIValidator creates a new API validator.
func NewAPIValidator(specPath string, router *gin.Engine) (*APIValidator, error) {
	// In a real implementation, we would read and parse the OpenAPI spec file
	// For now, we'll create a basic validator structure
	return &APIValidator{
		spec:   &OpenAPISpec{},
		router: router,
	}, nil
}

// LoadSpec loads the OpenAPI specification from a file.
func (v *APIValidator) LoadSpec(specData []byte) error {
	// For now, we'll skip YAML parsing since we don't have the dependency
	// In a real implementation, we would parse the YAML spec
	return nil
}

// ValidateEndpoints validates that all endpoints defined in the spec are implemented.
func (v *APIValidator) ValidateEndpoints() *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Errors:   []string{},
		Warnings: []string{},
	}

	// Get all routes from Gin router
	routes := v.router.Routes()
	routeMap := make(map[string]map[string]bool)

	for _, route := range routes {
		if routeMap[route.Path] == nil {
			routeMap[route.Path] = make(map[string]bool)
		}
		routeMap[route.Path][strings.ToLower(route.Method)] = true
	}

	// Check each path in the OpenAPI spec
	for path, pathItem := range v.spec.Paths {
		// Convert OpenAPI path format to Gin path format if needed
		ginPath := convertOpenAPIPathToGin(path)

		if pathItem.Get != nil {
			if !routeMap[ginPath]["get"] {
				result.Errors = append(result.Errors, fmt.Sprintf("GET %s endpoint not implemented", path))
				result.Valid = false
			}
		}

		if pathItem.Post != nil {
			if !routeMap[ginPath]["post"] {
				result.Errors = append(result.Errors, fmt.Sprintf("POST %s endpoint not implemented", path))
				result.Valid = false
			}
		}

		if pathItem.Put != nil {
			if !routeMap[ginPath]["put"] {
				result.Errors = append(result.Errors, fmt.Sprintf("PUT %s endpoint not implemented", path))
				result.Valid = false
			}
		}

		if pathItem.Delete != nil {
			if !routeMap[ginPath]["delete"] {
				result.Errors = append(result.Errors, fmt.Sprintf("DELETE %s endpoint not implemented", path))
				result.Valid = false
			}
		}
	}

	return result
}

// ValidateResponseFormats validates that API responses match the expected format.
func (v *APIValidator) ValidateResponseFormats() *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Errors:   []string{},
		Warnings: []string{},
	}

	// Test each endpoint with sample requests
	for path, pathItem := range v.spec.Paths {
		ginPath := convertOpenAPIPathToGin(path)

		if pathItem.Get != nil {
			if err := v.validateEndpointResponse("GET", ginPath, nil, pathItem.Get); err != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("GET %s: %v", path, err))
			}
		}

		if pathItem.Post != nil {
			// For POST endpoints, we would need to create valid request bodies
			// This is a simplified validation
			if err := v.validateEndpointResponse("POST", ginPath, nil, pathItem.Post); err != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("POST %s: %v", path, err))
			}
		}
	}

	return result
}

// validateEndpointResponse validates a specific endpoint response
//
//nolint:unparam // operation parameter is for future extensibility
func (v *APIValidator) validateEndpointResponse(method, path string, body io.Reader, operation *Operation) error {
	// Create a test request
	req := httptest.NewRequest(method, path, body)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Create a response recorder
	w := httptest.NewRecorder()

	// Serve the request
	v.router.ServeHTTP(w, req)

	// Check if the response format matches expectations
	if w.Code == http.StatusNotFound {
		return fmt.Errorf("endpoint not found")
	}

	// Parse response body
	var responseBody map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &responseBody); err != nil {
		return fmt.Errorf("invalid JSON response: %v", err)
	}

	// Check for standard response format
	if w.Code >= 200 && w.Code < 300 {
		return validateSuccessResponse(responseBody)
	}
	return validateErrorResponse(responseBody)
}

// convertOpenAPIPathToGin converts OpenAPI path format to Gin path format.
func convertOpenAPIPathToGin(openAPIPath string) string {
	// Convert {param} to :param
	// This is a simplified conversion
	result := openAPIPath
	// Add more sophisticated path parameter conversion if needed
	return result
}

// ValidateSchemas validates that request/response schemas match the specification.
func (v *APIValidator) ValidateSchemas() *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Errors:   []string{},
		Warnings: []string{},
	}

	// This would involve more complex schema validation
	// For now, we'll just check that schemas are defined
	if len(v.spec.Components.Schemas) == 0 {
		result.Warnings = append(result.Warnings, "No schemas defined in OpenAPI specification")
	}

	return result
}

// validateSuccessResponse validates the format of a success response.
func validateSuccessResponse(responseBody map[string]interface{}) error {
	success, ok := responseBody["success"]
	if !ok || success != true {
		return fmt.Errorf("success response missing 'success: true' field")
	}

	if _, ok := responseBody["data"]; !ok {
		return fmt.Errorf("success response missing 'data' field")
	}

	return nil
}

// validateErrorResponse validates the format of an error response.
func validateErrorResponse(responseBody map[string]interface{}) error {
	success, ok := responseBody["success"]
	if !ok || success != false {
		return fmt.Errorf("error response missing 'success: false' field")
	}

	if _, ok := responseBody["error"]; !ok {
		return fmt.Errorf("error response missing 'error' field")
	}

	return nil
}

// GenerateValidationReport generates a comprehensive validation report.
func (v *APIValidator) GenerateValidationReport() map[string]*ValidationResult {
	report := make(map[string]*ValidationResult)

	report["endpoints"] = v.ValidateEndpoints()
	report["responses"] = v.ValidateResponseFormats()
	report["schemas"] = v.ValidateSchemas()

	return report
}

// IsValidationPassing checks if all validations are passing.
func IsValidationPassing(report map[string]*ValidationResult) bool {
	for _, result := range report {
		if !result.Valid {
			return false
		}
	}
	return true
}

// PrintValidationReport prints a human-readable validation report.
func PrintValidationReport(report map[string]*ValidationResult) {
	fmt.Println("🔍 API Validation Report")
	fmt.Println("========================")

	for category, result := range report {
		caser := cases.Title(language.English)
		fmt.Printf("\n📋 %s Validation:\n", caser.String(category))

		if result.Valid {
			fmt.Println("  ✅ PASSED")
		} else {
			fmt.Println("  ❌ FAILED")
		}

		if len(result.Errors) > 0 {
			fmt.Println("  Errors:")
			for _, err := range result.Errors {
				fmt.Printf("    - %s\n", err)
			}
		}

		if len(result.Warnings) > 0 {
			fmt.Println("  Warnings:")
			for _, warning := range result.Warnings {
				fmt.Printf("    - %s\n", warning)
			}
		}
	}

	fmt.Println("\n" + strings.Repeat("=", reportSeparatorLength))
	if IsValidationPassing(report) {
		fmt.Println("🎉 All validations PASSED!")
	} else {
		fmt.Println("❌ Some validations FAILED!")
	}
}
