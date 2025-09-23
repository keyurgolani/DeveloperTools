package validation_test

import (
	"testing"

	"github.com/keyurgolani/DeveloperTools/internal/validation"
	"github.com/stretchr/testify/assert"
)

func TestIsValidationPassing(t *testing.T) {
	// Test with all passing validations
	passingReport := map[string]*validation.ValidationResult{
		"endpoint1": {Valid: true, Errors: []string{}, Warnings: []string{}},
		"endpoint2": {Valid: true, Errors: []string{}, Warnings: []string{}},
	}
	assert.True(t, validation.IsValidationPassing(passingReport))

	// Test with some failing validations
	failingReport := map[string]*validation.ValidationResult{
		"endpoint1": {Valid: true, Errors: []string{}, Warnings: []string{}},
		"endpoint2": {Valid: false, Errors: []string{"error"}, Warnings: []string{}},
	}
	assert.False(t, validation.IsValidationPassing(failingReport))
}
