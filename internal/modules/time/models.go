package time

// TimeConvertRequest represents a request to convert time between formats.
type TimeConvertRequest struct {
	Input        string `json:"input" binding:"required"`
	InputFormat  string `json:"inputFormat" binding:"required"`
	OutputFormat string `json:"outputFormat" binding:"required"`
}

// TimeConvertResponse represents the response containing converted time.
type TimeConvertResponse struct {
	Result string `json:"result"`
}

// TimeResponse represents the response containing current time in multiple formats.
type TimeResponse struct {
	UnixSeconds      int64  `json:"unixSeconds"`
	UnixMilliseconds int64  `json:"unixMilliseconds"`
	ISO8601          string `json:"iso8601"`
	RFC3339          string `json:"rfc3339"`
	HumanReadable    string `json:"humanReadable"`
}
