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
	// Code is the server's machine-readable "code" field (e.g.
	// "plan_required"), or "" when it sent none.
	Code string
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

// PermissionDeniedError is returned on 403 — the key is valid but may not do
// this: an RBAC denial ("permission denied: …"), a blocked client IP, or a
// scan profile with payload scanning turned off. Message is the server's text
// and Code its "code" field, if any. A feature the plan does not include is a
// *PlanRequiredError, which errors.As also matches as a
// *PermissionDeniedError. An invalid or missing key is 401 and returns
// *AuthenticationError.
type PermissionDeniedError struct{ SurfaceError }

// PlanRequiredError is returned when the account's plan does not include what
// was asked for: a 403 with Code "plan_required", or the 402 Surface answers
// when ScanFileOptions.Defer is used on a plan without async scanning (that
// one carries no Code). It is a plan wall, not quota exhaustion. Feature and
// CurrentPlan hold the server's "feature" and "current_plan" fields.
type PlanRequiredError struct {
	SurfaceError
	Feature     string
	CurrentPlan string
}

// Unwrap lets errors.As(err, &permissionDenied) match a plan wall too.
func (e *PlanRequiredError) Unwrap() error {
	return &PermissionDeniedError{e.SurfaceError}
}

// QuotaExceededError is returned on 402 when the monthly scan quota is used
// up ("monthly scan quota exceeded (N/M scans used)"). A 429 is a rate limit
// and returns *RateLimitError instead.
type QuotaExceededError struct{ SurfaceError }

// RateLimitError is returned on 429 — too many requests; wait and retry.
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
