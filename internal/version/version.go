package version

// Version information for the application
// These values are set at build time via ldflags.
var (
	// Version is the current version of the application (set at build time).
	Version = "dev"

	// ServiceName is the name of the service.
	ServiceName = "dev-utilities"

	// BuildDate will be set during build time.
	BuildDate = "unknown"

	// GitCommit will be set during build time.
	GitCommit = "unknown"
)

// Info represents version information.
type Info struct {
	Version   string `json:"version"`
	Service   string `json:"service"`
	BuildDate string `json:"buildDate,omitempty"`
	GitCommit string `json:"gitCommit,omitempty"`
}

// Get returns the version information.
func Get() Info {
	return Info{
		Version:   Version,
		Service:   ServiceName,
		BuildDate: BuildDate,
		GitCommit: GitCommit,
	}
}
