package constants

// Logging constants.
const (
	// Log level thresholds for HTTP status codes.
	LogLevelErrorThreshold   = 500 // Server errors (5xx)
	LogLevelWarningThreshold = 400 // Client errors (4xx)

	// Text validation constants.
	MinValidCharRatio = 0.9 // Minimum ratio of valid characters for text detection

	// String parsing constants.
	KeyValuePairParts = 2 // Expected parts when splitting key=value pairs
)
