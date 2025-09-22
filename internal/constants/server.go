package constants

import "time"

// Server configuration constants.
const (
	// DefaultPort is the default HTTP server port.
	DefaultPort = 8080

	// HTTP timeout constants.
	DefaultReadTimeout  = 15 * time.Second
	DefaultWriteTimeout = 15 * time.Second
	DefaultIdleTimeout  = 60 * time.Second

	// Shutdown timeout.
	DefaultShutdownTimeout = 30 * time.Second
	DefaultGracefulTimeout = 3 * time.Second
)

// HTTP status code constants for categorization.
const (
	HTTPStatusClientErrorStart = 400
	HTTPStatusServerErrorStart = 500
)
