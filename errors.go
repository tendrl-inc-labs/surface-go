package surface

import "fmt"

// SurfaceError is the base error type for all API errors.
type SurfaceError struct {
	StatusCode int
	Message    string
	RequestID  string
}

func (e *SurfaceError) Error() string {
	if e.RequestID != "" {
		return fmt.Sprintf("surface: %d %s (request_id=%s)", e.StatusCode, e.Message, e.RequestID)
	}
	return fmt.Sprintf("surface: %d %s", e.StatusCode, e.Message)
}

// AuthenticationError is returned on 401 — invalid or missing API key.
type AuthenticationError struct{ SurfaceError }

// ValidationError is returned on 400 — invalid request parameters.
type ValidationError struct{ SurfaceError }

// NotFoundError is returned on 404 — resource not found.
type NotFoundError struct{ SurfaceError }

// QuotaExceededError is returned on 429 when monthly credit quota is exhausted.
type QuotaExceededError struct{ SurfaceError }

// RateLimitError is returned on 429 when per-minute rate limit is hit.
type RateLimitError struct{ SurfaceError }

// MaliciousFileError is returned by ScanFileSafe/ScanFileStrict when a file
// is rejected based on its threat level. The full ScanResult is attached.
type MaliciousFileError struct {
	Result *ScanResult
}

func (e *MaliciousFileError) Error() string {
	return fmt.Sprintf("surface: file rejected: %s — %s",
		e.Result.SafetyScore.ThreatLevel,
		e.Result.SafetyScore.ThreatSummary,
	)
}
