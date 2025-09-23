package id_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/keyurgolani/DeveloperTools/internal/modules/id"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getUUIDServiceTestCases() []struct {
	name        string
	version     int
	count       int
	expectError bool
	errorMsg    string
} {
	return []struct {
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
			count:       id.MaxUUIDCount,
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
			count:       id.MaxUUIDCount + 1,
			expectError: true,
			errorMsg:    "count exceeds maximum limit",
		},
	}
}

func executeUUIDServiceTest(t *testing.T, service id.IDService, tt struct {
	name        string
	version     int
	count       int
	expectError bool
	errorMsg    string
},
) {
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
		expectedCount = id.DefaultCount
	}

	assert.Len(t, uuids, expectedCount)
	validateUUIDs(t, uuids, tt.version)
}

func validateUUIDs(t *testing.T, uuids []string, version int) {
	// Validate each UUID
	for i, uuidStr := range uuids {
		parsedUUID, err := uuid.Parse(uuidStr)
		require.NoError(t, err, "UUID %d should be valid: %s", i, uuidStr)

		// Check UUID version
		switch version {
		case 4:
			assert.Equal(t, uuid.Version(4), parsedUUID.Version(), "UUID should be version 4")
		case 1:
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
}

func TestService_GenerateUUID(t *testing.T) {
	service := id.NewService()
	tests := getUUIDServiceTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executeUUIDServiceTest(t, service, tt)
		})
	}
}

func getNanoIDServiceTestCases() []struct {
	name        string
	size        int
	count       int
	expectError bool
	errorMsg    string
} {
	return []struct {
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
			size:        id.MaxNanoIDSize,
			count:       1,
			expectError: false,
		},
		{
			name:        "Max count",
			size:        21,
			count:       id.MaxNanoIDCount,
			expectError: false,
		},
		{
			name:        "Size exceeds limit",
			size:        id.MaxNanoIDSize + 1,
			count:       1,
			expectError: true,
			errorMsg:    "size exceeds maximum limit",
		},
		{
			name:        "Count exceeds limit",
			size:        21,
			count:       id.MaxNanoIDCount + 1,
			expectError: true,
			errorMsg:    "count exceeds maximum limit",
		},
	}
}

func executeNanoIDServiceTest(t *testing.T, service id.IDService, tt struct {
	name        string
	size        int
	count       int
	expectError bool
	errorMsg    string
},
) {
	ids, err := service.GenerateNanoID(tt.size, tt.count)

	if tt.expectError {
		assert.Error(t, err)
		assert.Contains(t, err.Error(), tt.errorMsg)
		assert.Nil(t, ids)
		return
	}

	require.NoError(t, err)
	validateNanoIDs(t, ids, tt.size, tt.count)
}

func validateNanoIDs(t *testing.T, ids []string, size, count int) {
	expectedCount := count
	if expectedCount <= 0 {
		expectedCount = id.DefaultCount
	}

	expectedSize := size
	if expectedSize <= 0 {
		expectedSize = id.DefaultNanoIDSize
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
}

func TestService_GenerateNanoID(t *testing.T) {
	service := id.NewService()
	tests := getNanoIDServiceTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executeNanoIDServiceTest(t, service, tt)
		})
	}
}

// isURLSafeChar checks if a character is URL-safe (alphanumeric, hyphen, or underscore).
func isURLSafeChar(char rune) bool {
	return (char >= 'a' && char <= 'z') ||
		(char >= 'A' && char <= 'Z') ||
		(char >= '0' && char <= '9') ||
		char == '-' || char == '_'
}

func TestConstants(t *testing.T) {
	// Test that constants have expected values
	assert.Equal(t, 1000, id.MaxUUIDCount)
	assert.Equal(t, 1000, id.MaxNanoIDCount)
	assert.Equal(t, 50, id.MaxNanoIDSize)
	assert.Equal(t, 21, id.DefaultNanoIDSize)
	assert.Equal(t, 1, id.DefaultCount)
}

func BenchmarkGenerateUUID(b *testing.B) {
	service := id.NewService()

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
	service := id.NewService()

	b.Run("Default size", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := service.GenerateNanoID(id.DefaultNanoIDSize, 1)
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
