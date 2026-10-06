package surface

import (
	"errors"
	"fmt"
)

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

// ErrUnavailable matches, via errors.Is, every error that means Surface gave
// no real answer: it could not be reached, the call's Timeout ran out, it
// answered 500/502/503/504, or it sent a body that is not the expected JSON.
var ErrUnavailable = errors.New("surface: scanner unavailable")

// UnavailableError is returned when Surface gave no real answer (see
// ErrUnavailable). StatusCode is the HTTP status, or 0 when no response
// arrived. It unwraps to the cause: the transport error, the JSON decode
// error, or, for a 5xx, a *SurfaceError, so errors.As(err, &surfaceErr)
// keeps working for server errors.
type UnavailableError struct {
	StatusCode int
	Message    string
	Err        error
}

func (e *UnavailableError) Error() string {
	if e.StatusCode != 0 {
		return fmt.Sprintf("surface: unavailable: %d %s", e.StatusCode, e.Message)
	}
	return "surface: unavailable: " + e.Message
}

// Is reports whether target is ErrUnavailable.
func (e *UnavailableError) Is(target error) bool { return target == ErrUnavailable }

// Unwrap returns the underlying cause.
func (e *UnavailableError) Unwrap() error { return e.Err }

// MaliciousFileError is returned by any scan method when the result matches an
// entry in ScanFileOptions.Reject — a threat level ("Clean"/"Suspicious"/
// "Malicious") or a recommended action ("Allow"/"Review"/"Block"), compared
// case-insensitively. The full ScanResult is attached.
type MaliciousFileError struct {
	Result *ScanResult
}

func (e *MaliciousFileError) Error() string {
	return fmt.Sprintf("surface: file rejected: %s — %s",
		e.Result.SafetyScore.ThreatLevel,
		e.Result.SafetyScore.ThreatSummary,
	)
}
