package id

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/jaevor/go-nanoid"
)

const (
	// MaxUUIDCount is the maximum number of UUIDs that can be generated in a single request.
	MaxUUIDCount = 1000
	// MaxNanoIDCount is the maximum number of Nano IDs that can be generated in a single request.
	MaxNanoIDCount = 1000
	// MaxNanoIDSize is the maximum size for a Nano ID.
	MaxNanoIDSize = 50
	// DefaultNanoIDSize is the default size for Nano IDs.
	DefaultNanoIDSize = 21
	// DefaultCount is the default count when not specified.
	DefaultCount = 1
	// UUIDVersion1 represents UUID version 1.
	UUIDVersion1 = 1
	// UUIDVersion4 represents UUID version 4.
	UUIDVersion4 = 4
)

// IDService defines the interface for ID generation operations.
type IDService interface {
	GenerateUUID(version, count int) ([]string, error)
	GenerateNanoID(size, count int) ([]string, error)
}

// Service implements the IDService interface.
type Service struct{}

// NewService creates a new ID service instance.
func NewService() IDService {
	return &Service{}
}

// GenerateUUID generates UUIDs of the specified version and count.
func (s *Service) GenerateUUID(version, count int) ([]string, error) {
	// Validate version
	if version != UUIDVersion1 && version != UUIDVersion4 {
		return nil, fmt.Errorf("unsupported UUID version: %d, only versions 1 and 4 are supported", version)
	}

	// Set default count if not specified
	if count <= 0 {
		count = DefaultCount
	}

	// Validate count limit
	if count > MaxUUIDCount {
		return nil, fmt.Errorf("count exceeds maximum limit of %d", MaxUUIDCount)
	}

	uuids := make([]string, count)

	for i := 0; i < count; i++ {
		var u uuid.UUID
		var err error

		switch version {
		case UUIDVersion1:
			u, err = uuid.NewUUID()
		case UUIDVersion4:
			u, err = uuid.NewRandom()
		}

		if err != nil {
			return nil, fmt.Errorf("failed to generate UUID v%d: %w", version, err)
		}

		uuids[i] = u.String()
	}

	return uuids, nil
}

// GenerateNanoID generates Nano IDs with the specified size and count.
func (s *Service) GenerateNanoID(size, count int) ([]string, error) {
	// Set default size if not specified
	if size <= 0 {
		size = DefaultNanoIDSize
	}

	// Set default count if not specified
	if count <= 0 {
		count = DefaultCount
	}

	// Validate size limit
	if size > MaxNanoIDSize {
		return nil, fmt.Errorf("size exceeds maximum limit of %d", MaxNanoIDSize)
	}

	// Validate count limit
	if count > MaxNanoIDCount {
		return nil, fmt.Errorf("count exceeds maximum limit of %d", MaxNanoIDCount)
	}

	// Create Nano ID generator with specified size
	generate, err := nanoid.Standard(size)
	if err != nil {
		return nil, fmt.Errorf("failed to create Nano ID generator: %w", err)
	}

	ids := make([]string, count)

	for i := 0; i < count; i++ {
		id := generate()
		ids[i] = id
	}

	return ids, nil
}
