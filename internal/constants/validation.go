package constants

import "time"

// Validation constants.
const (
	// DefaultValidationTimeout is the default timeout for validation operations.
	DefaultValidationTimeout = 5 * time.Second

	// MaxRegexPatternLength is the maximum allowed regex pattern length.
	MaxRegexPatternLength = 1000

	// JWT token parts count.
	JWTPartsCount = 3

	// UUID version constants.
	UUIDVersion4 = 4

	// Cleanup and maintenance intervals.
	CleanupInterval = 5 * time.Minute

	// Logging and output constants.
	ReportSeparatorLength = 50
)
