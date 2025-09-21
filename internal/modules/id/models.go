package id

// UUIDRequest represents a request to generate UUIDs
type UUIDRequest struct {
	Version int `json:"version" binding:"required,oneof=1 4"`
	Count   int `json:"count,omitempty"`
}

// UUIDResponse represents the response containing generated UUIDs
type UUIDResponse struct {
	UUIDs []string `json:"uuids"`
}

// NanoIDRequest represents a request to generate Nano IDs
type NanoIDRequest struct {
	Size  int `json:"size,omitempty"`
	Count int `json:"count,omitempty"`
}

// NanoIDResponse represents the response containing generated Nano IDs
type NanoIDResponse struct {
	IDs []string `json:"ids"`
}