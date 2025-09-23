package time

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	// Supported time formats.
	FormatUnixSeconds      = "unix"
	FormatUnixMilliseconds = "unix_ms"
	FormatISO8601          = "iso8601"
	FormatRFC3339          = "rfc3339"
	FormatHumanReadable    = "human"

	// Layout constants for parsing.
	ISO8601Layout = "2006-01-02T15:04:05Z"
	RFC3339Layout = time.RFC3339
	HumanLayout   = "2006-01-02 15:04:05 UTC"
)

// TimeService defines the interface for time operations.
type TimeService interface {
	ConvertTime(input, inputFormat, outputFormat string) (string, error)
	GetCurrentTime() (*TimeResponse, error)
}

// Service implements the TimeService interface.
type Service struct{}

// NewService creates a new time service instance.
func NewService() TimeService {
	return &Service{}
}

// ConvertTime converts time from one format to another.
func (s *Service) ConvertTime(input, inputFormat, outputFormat string) (string, error) {
	// Parse input time based on input format
	parsedTime, err := s.parseTime(input, inputFormat)
	if err != nil {
		return "", fmt.Errorf("failed to parse input time: %w", err)
	}

	// Format output time based on output format
	result, err := s.formatTime(parsedTime, outputFormat)
	if err != nil {
		return "", fmt.Errorf("failed to format output time: %w", err)
	}

	return result, nil
}

// GetCurrentTime returns the current time in multiple formats (all UTC).
func (s *Service) GetCurrentTime() (*TimeResponse, error) {
	now := time.Now().UTC()

	return &TimeResponse{
		UnixSeconds:      now.Unix(),
		UnixMilliseconds: now.UnixMilli(),
		ISO8601:          now.Format(ISO8601Layout),
		RFC3339:          now.Format(RFC3339Layout),
		HumanReadable:    now.Format(HumanLayout),
	}, nil
}

// parseTime parses a time string based on the specified format.
func (s *Service) parseTime(input, format string) (time.Time, error) {
	input = strings.TrimSpace(input)
	format = strings.ToLower(strings.TrimSpace(format))

	switch format {
	case FormatUnixSeconds:
		seconds, err := strconv.ParseInt(input, 10, 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid unix timestamp: %w", err)
		}
		return time.Unix(seconds, 0).UTC(), nil

	case FormatUnixMilliseconds:
		milliseconds, err := strconv.ParseInt(input, 10, 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid unix milliseconds timestamp: %w", err)
		}
		return time.UnixMilli(milliseconds).UTC(), nil

	case FormatISO8601:
		// Try multiple ISO8601 variants
		layouts := []string{
			ISO8601Layout,
			"2006-01-02T15:04:05.000Z",
			"2006-01-02T15:04:05.000000Z",
			"2006-01-02T15:04:05",
		}

		for _, layout := range layouts {
			if t, err := time.Parse(layout, input); err == nil {
				return t.UTC(), nil
			}
		}
		return time.Time{}, fmt.Errorf("invalid ISO8601 format")

	case FormatRFC3339:
		t, err := time.Parse(RFC3339Layout, input)
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid RFC3339 format: %w", err)
		}
		return t.UTC(), nil

	case FormatHumanReadable:
		// Try multiple human-readable formats
		layouts := []string{
			HumanLayout,
			"2006-01-02 15:04:05",
			"2006-01-02T15:04:05",
			"January 2, 2006 15:04:05 UTC",
			"January 2, 2006 15:04:05",
		}

		for _, layout := range layouts {
			if t, err := time.Parse(layout, input); err == nil {
				return t.UTC(), nil
			}
		}
		return time.Time{}, fmt.Errorf("invalid human-readable format")

	default:
		return time.Time{}, fmt.Errorf("unsupported input format: %s", format)
	}
}

// formatTime formats a time value based on the specified format.
func (s *Service) formatTime(t time.Time, format string) (string, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	utcTime := t.UTC()

	switch format {
	case FormatUnixSeconds:
		return strconv.FormatInt(utcTime.Unix(), 10), nil

	case FormatUnixMilliseconds:
		return strconv.FormatInt(utcTime.UnixMilli(), 10), nil

	case FormatISO8601:
		return utcTime.Format(ISO8601Layout), nil

	case FormatRFC3339:
		return utcTime.Format(RFC3339Layout), nil

	case FormatHumanReadable:
		return utcTime.Format(HumanLayout), nil

	default:
		return "", fmt.Errorf("unsupported output format: %s", format)
	}
}

// GetSupportedFormats returns a list of supported time formats.
func GetSupportedFormats() []string {
	return []string{
		FormatUnixSeconds,
		FormatUnixMilliseconds,
		FormatISO8601,
		FormatRFC3339,
		FormatHumanReadable,
	}
}
