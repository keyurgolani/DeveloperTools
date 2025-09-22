package constants

// Argon2 configuration constants.
const (
	// DefaultArgonMemory is the default memory usage in KB (64MB).
	DefaultArgonMemory = 65536

	// DefaultArgonIterations is the default number of iterations.
	DefaultArgonIterations = 3

	// DefaultArgonParallelism is the default parallelism factor.
	DefaultArgonParallelism = 4

	// DefaultArgonSaltLength is the default salt length in bytes.
	DefaultArgonSaltLength = 16

	// DefaultArgonKeyLength is the default key length in bytes.
	DefaultArgonKeyLength = 32

	// Minimum validation constants.
	MinArgonMemory     = 1024 // 1MB minimum
	MinArgonSaltLength = 8    // 8 bytes minimum
	MinArgonKeyLength  = 16   // 16 bytes minimum

	// Argon2 hash format parts count.
	ArgonHashPartsCount = 6
)
