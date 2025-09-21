package id

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestService_GenerateUUID(t *testing.T) {
	service := NewService()

	tests := []struct {
		name        string
		version     int
		count       int
		expectError bool
		errorMsg    string
	}{
		{
			name:        "UUID v4 single",
			version:     4,
			count:       1,
			expectError: false,
		},
		{
			name:        "UUID v1 single",
			version:     1,
			count:       1,
			expectError: false,
		},
		{
			name:        "UUID v4 multiple",
			version:     4,
			count:       10,
			expectError: false,
		},
		{
			name:        "UUID v4 default count",
			version:     4,
			count:       0,
			expectError: false,
		},
		{
			name:        "UUID v4 max count",
			version:     4,
			count:       MaxUUIDCount,
			expectError: false,
		},
		{
			name:        "Invalid version",
			version:     3,
			count:       1,
			expectError: true,
			errorMsg:    "unsupported UUID version",
		},
		{
			name:        "Count exceeds limit",
			version:     4,
			count:       MaxUUIDCount + 1,
			expectError: true,
			errorMsg:    "count exceeds maximum limit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uuids, err := service.GenerateUUID(tt.version, tt.count)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, uuids)
				return
			}

			require.NoError(t, err)
			
			expectedCount := tt.count
			if expectedCount <= 0 {
				expectedCount = DefaultCount
			}
			
			assert.Len(t, uuids, expectedCount)

			// Validate each UUID
			for i, uuidStr := range uuids {
				parsedUUID, err := uuid.Parse(uuidStr)
				require.NoError(t, err, "UUID %d should be valid: %s", i, uuidStr)
				
				// Check UUID version
				if tt.version == 4 {
					assert.Equal(t, uuid.Version(4), parsedUUID.Version(), "UUID should be version 4")
				} else if tt.version == 1 {
					assert.Equal(t, uuid.Version(1), parsedUUID.Version(), "UUID should be version 1")
				}
			}

			// Ensure uniqueness for multiple UUIDs
			if len(uuids) > 1 {
				uniqueUUIDs := make(map[string]bool)
				for _, uuidStr := range uuids {
					assert.False(t, uniqueUUIDs[uuidStr], "UUID should be unique: %s", uuidStr)
					uniqueUUIDs[uuidStr] = true
				}
			}
		})
	}
}

func TestService_GenerateNanoID(t *testing.T) {
	service := NewService()

	tests := []struct {
		name        string
		size        int
		count       int
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Default size and count",
			size:        0,
			count:       0,
			expectError: false,
		},
		{
			name:        "Custom size single",
			size:        10,
			count:       1,
			expectError: false,
		},
		{
			name:        "Multiple Nano IDs",
			size:        21,
			count:       5,
			expectError: false,
		},
		{
			name:        "Max size",
			size:        MaxNanoIDSize,
			count:       1,
			expectError: false,
		},
		{
			name:        "Max count",
			size:        21,
			count:       MaxNanoIDCount,
			expectError: false,
		},
		{
			name:        "Size exceeds limit",
			size:        MaxNanoIDSize + 1,
			count:       1,
			expectError: true,
			errorMsg:    "size exceeds maximum limit",
		},
		{
			name:        "Count exceeds limit",
			size:        21,
			count:       MaxNanoIDCount + 1,
			expectError: true,
			errorMsg:    "count exceeds maximum limit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ids, err := service.GenerateNanoID(tt.size, tt.count)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, ids)
				return
			}

			require.NoError(t, err)
			
			expectedCount := tt.count
			if expectedCount <= 0 {
				expectedCount = DefaultCount
			}
			
			expectedSize := tt.size
			if expectedSize <= 0 {
				expectedSize = DefaultNanoIDSize
			}
			
			assert.Len(t, ids, expectedCount)

			// Validate each Nano ID
			for i, id := range ids {
				assert.Len(t, id, expectedSize, "Nano ID %d should have correct length: %s", i, id)
				
				// Check that ID contains only URL-safe characters
				for _, char := range id {
					assert.True(t, isURLSafeChar(char), "Nano ID should contain only URL-safe characters: %s", id)
				}
			}

			// Ensure uniqueness for multiple IDs
			if len(ids) > 1 {
				uniqueIDs := make(map[string]bool)
				for _, id := range ids {
					assert.False(t, uniqueIDs[id], "Nano ID should be unique: %s", id)
					uniqueIDs[id] = true
				}
			}
		})
	}
}

// isURLSafeChar checks if a character is URL-safe (alphanumeric, hyphen, or underscore)
func isURLSafeChar(char rune) bool {
	return (char >= 'a' && char <= 'z') ||
		(char >= 'A' && char <= 'Z') ||
		(char >= '0' && char <= '9') ||
		char == '-' || char == '_'
}

func TestConstants(t *testing.T) {
	// Test that constants have expected values
	assert.Equal(t, 1000, MaxUUIDCount)
	assert.Equal(t, 1000, MaxNanoIDCount)
	assert.Equal(t, 50, MaxNanoIDSize)
	assert.Equal(t, 21, DefaultNanoIDSize)
	assert.Equal(t, 1, DefaultCount)
}

func BenchmarkGenerateUUID(b *testing.B) {
	service := NewService()
	
	b.Run("UUID v4", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := service.GenerateUUID(4, 1)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	
	b.Run("UUID v1", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := service.GenerateUUID(1, 1)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkGenerateNanoID(b *testing.B) {
	service := NewService()
	
	b.Run("Default size", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := service.GenerateNanoID(DefaultNanoIDSize, 1)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	
	b.Run("Small size", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := service.GenerateNanoID(10, 1)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}