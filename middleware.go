package surface

import (
	"bytes"
	"context"
	"io"
	"net/http"
)

// MiddlewareOptions configures the ScanMiddleware behavior.
type MiddlewareOptions struct {
	// Reject lists threat levels that should be blocked (e.g. "Malicious", "Suspicious").
	// If the scan result matches any of these, the request is rejected with 403.
	Reject []string

	// ScanRequests enables scanning of incoming request bodies. Default: true.
	ScanRequests *bool

	// ScanResponses enables scanning of outgoing response bodies. Default: false.
	ScanResponses *bool

	// Label is an optional label for the scan (shown in scan history).
	Label string

	// FailOpen controls behavior when the scanner is unavailable.
	// If true (default), requests pass through when scanning fails.
	// If false, requests are rejected with 503 when scanning fails.
	FailOpen *bool

	// MinSize is the minimum body size (bytes) to scan. Bodies smaller than this
	// are passed through without scanning. Default: 0 (scan everything).
	MinSize int

	// OnThreat is called when a threat is detected. Use for custom logging or alerting.
	// Called before the 403 response is sent. If nil, a default JSON error is returned.
	OnThreat func(r *http.Request, result *ScanResult)

	// OnError is called when scanning fails (scanner unavailable, timeout, etc.).
	// Only called when FailOpen is true (otherwise a 503 is returned automatically).
	OnError func(r *http.Request, err error)
}

func (o *MiddlewareOptions) scanRequests() bool {
	if o == nil || o.ScanRequests == nil {
		return true
	}
	return *o.ScanRequests
}

func (o *MiddlewareOptions) scanResponses() bool {
	if o == nil || o.ScanResponses == nil {
		return false
	}
	return *o.ScanResponses
}

func (o *MiddlewareOptions) failOpen() bool {
	if o == nil || o.FailOpen == nil {
		return true
	}
	return *o.FailOpen
}

func (o *MiddlewareOptions) label() string {
	if o == nil || o.Label == "" {
		return "middleware-scan"
	}
	return o.Label
}

func (o *MiddlewareOptions) shouldReject(threatLevel string) bool {
	if o == nil {
		return false
	}
	for _, level := range o.Reject {
		if level == threatLevel {
			return true
		}
	}
	return false
}

// ScanMiddleware returns an http.Handler that scans request bodies before
// forwarding to the next handler. Detected threats are blocked with 403.
//
// Usage:
//
//	mux.Handle("/agent/receive", surface.ScanMiddleware(client, myHandler, &surface.MiddlewareOptions{
//	    Reject: []string{"Malicious", "Suspicious"},
//	}))
func ScanMiddleware(client *Client, next http.Handler, opts *MiddlewareOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip if request scanning disabled or no body
		if !opts.scanRequests() || r.Body == nil || r.ContentLength == 0 {
			next.ServeHTTP(w, r)
			return
		}

		// Skip small payloads
		if opts != nil && opts.MinSize > 0 && r.ContentLength > 0 && r.ContentLength < int64(opts.MinSize) {
			next.ServeHTTP(w, r)
			return
		}

		// Read the body (we need to buffer it for both scanning and forwarding)
		body, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			if opts.failOpen() {
				r.Body = io.NopCloser(bytes.NewReader(body))
				next.ServeHTTP(w, r)
				return
			}
			http.Error(w, `{"error":"failed to read request body"}`, http.StatusInternalServerError)
			return
		}

		// Skip empty bodies
		if len(body) == 0 {
			r.Body = io.NopCloser(bytes.NewReader(body))
			next.ServeHTTP(w, r)
			return
		}

		// Scan the payload
		result, scanErr := client.ScanPayload(context.Background(), body, opts.label(), nil)
		if scanErr != nil {
			if opts != nil && opts.OnError != nil {
				opts.OnError(r, scanErr)
			}
			if opts.failOpen() {
				// Scanner unavailable — let the request through
				r.Body = io.NopCloser(bytes.NewReader(body))
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"error":"security scan unavailable"}`))
			return
		}

		// Check for threats
		if result.ScanResult != nil && opts.shouldReject(result.ScanResult.SafetyScore.ThreatLevel) {
			if opts != nil && opts.OnThreat != nil {
				opts.OnThreat(r, result.ScanResult)
			}
			// Add scan ID to response headers for audit trail
			if result.ScanResult.RequestID != "" {
				w.Header().Set("X-Surface-Scan-Id", result.ScanResult.RequestID)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"request blocked by security scan","threatLevel":"` +
				result.ScanResult.SafetyScore.ThreatLevel + `","threat":"` +
				result.ScanResult.SafetyScore.PrimaryThreat + `"}`))
			return
		}

		// Add scan ID to request headers for downstream visibility
		if result.ScanResult != nil && result.ScanResult.RequestID != "" {
			r.Header.Set("X-Surface-Scan-Id", result.ScanResult.RequestID)
		}

		// Restore the body and continue
		r.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, r)
	})
}

// ScanHandlerFunc is a convenience wrapper for ScanMiddleware that accepts
// an http.HandlerFunc instead of http.Handler.
func ScanHandlerFunc(client *Client, next http.HandlerFunc, opts *MiddlewareOptions) http.Handler {
	return ScanMiddleware(client, next, opts)
}
