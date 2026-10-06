package surface

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// DefaultTimeout is the per-call budget used when Client.Timeout is zero and
// the caller's context has no deadline. It covers every attempt and retry wait.
const DefaultTimeout = 60 * time.Second

const (
	// maxRetries bounds the retries of one call on 502/503/504 or a refused
	// or reset connection.
	maxRetries = 10
	// maxRetryWait caps a single wait, whether from Retry-After or backoff.
	maxRetryWait = 10 * time.Second
	// defaultRetryBase is the first backoff wait; later waits double up to 8x.
	defaultRetryBase = time.Second
)

func (c *Client) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return DefaultTimeout
}

func (c *Client) backoff(retry int) time.Duration {
	base := c.retryBase
	if base <= 0 {
		base = defaultRetryBase
	}
	if retry > 3 {
		retry = 3
	}
	return base << retry // 1, 2, 4, 8, 8, ... x base
}

// send performs one SDK call against hc. build makes a fresh request for each
// attempt, so bodies are replayable. The call gets Timeout as its deadline
// unless ctx already has one (then the caller's deadline governs). 502, 503,
// 504 and refused/reset connections are retried within that budget, honoring
// Retry-After. It returns the status and body of any response it does not
// treat as unavailable; everything else is an *UnavailableError, except a
// caller cancellation, which comes back as is.
func (c *Client) send(ctx context.Context, hc *http.Client, build func() (*http.Request, error)) (int, []byte, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout())
		defer cancel()
	}
	deadline, _ := ctx.Deadline()

	for retry := 0; ; retry++ {
		req, err := build()
		if err != nil {
			return 0, nil, err
		}
		resp, err := hc.Do(req.WithContext(ctx))
		var last *UnavailableError
		var wait time.Duration
		if err != nil {
			if fail := callerCanceled(ctx, err); fail != nil {
				return 0, nil, fail
			}
			last = transportUnavailable(ctx, err)
			if !isConnRefusedOrReset(err) {
				return 0, nil, last
			}
			wait = c.backoff(retry)
		} else {
			body, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				if fail := callerCanceled(ctx, readErr); fail != nil {
					return 0, nil, fail
				}
				return 0, nil, transportUnavailable(ctx, readErr)
			}
			switch resp.StatusCode {
			case 500:
				return 0, nil, statusUnavailable(resp, body)
			case 502, 503, 504:
				last = statusUnavailable(resp, body)
				wait = retryAfter(resp)
				if wait < 0 {
					wait = c.backoff(retry)
				}
			default:
				return resp.StatusCode, body, nil
			}
		}

		// Give up rather than start a wait the budget cannot cover.
		if retry >= maxRetries || time.Now().Add(wait).After(deadline) {
			return 0, nil, last
		}
		t := time.NewTimer(wait)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			if fail := callerCanceled(ctx, ctx.Err()); fail != nil {
				return 0, nil, fail
			}
			return 0, nil, last
		}
	}
}

// callerCanceled returns err when the caller canceled the context, which is
// their decision rather than Surface being unavailable.
func callerCanceled(ctx context.Context, err error) error {
	if errors.Is(ctx.Err(), context.Canceled) {
		return err
	}
	return nil
}

func transportUnavailable(ctx context.Context, err error) *UnavailableError {
	msg := err.Error()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		msg = "timed out waiting for Surface"
	}
	return &UnavailableError{Message: msg, Err: err}
}

func isConnRefusedOrReset(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET)
}

// statusUnavailable builds the error for a 5xx answer. It wraps a
// *SurfaceError so errors.As callers written for server errors still match.
func statusUnavailable(resp *http.Response, body []byte) *UnavailableError {
	msg, requestID, ok := errorBody(body)
	if !ok || msg == "" {
		msg = resp.Status
	}
	return &UnavailableError{
		StatusCode: resp.StatusCode,
		Message:    msg,
		Err:        &SurfaceError{StatusCode: resp.StatusCode, Message: msg, RequestID: requestID},
	}
}

// errorBody reads Surface's JSON error shape. ok is false when body is not JSON.
func errorBody(body []byte) (msg, requestID string, ok bool) {
	var b struct {
		Error     string `json:"error"`
		RequestID string `json:"requestId"`
	}
	if err := json.Unmarshal(body, &b); err != nil {
		return "", "", false
	}
	return b.Error, b.RequestID, true
}

// retryAfter returns the Retry-After wait in seconds, capped at maxRetryWait,
// or -1 when the header is absent or not a number of seconds.
func retryAfter(resp *http.Response) time.Duration {
	v := strings.TrimSpace(resp.Header.Get("Retry-After"))
	if v == "" {
		return -1
	}
	secs, err := strconv.Atoi(v)
	if err != nil || secs < 0 {
		return -1
	}
	wait := time.Duration(secs) * time.Second
	if wait > maxRetryWait {
		wait = maxRetryWait
	}
	return wait
}

// decodeJSON decodes a successful response. A body that is not the expected
// JSON (an HTML proxy page, a truncated body) is not a real answer.
func decodeJSON(status int, body []byte, out interface{}) error {
	if err := json.Unmarshal(body, out); err != nil {
		return &UnavailableError{
			StatusCode: status,
			Message:    fmt.Sprintf("response is not valid JSON: %v", err),
			Err:        err,
		}
	}
	return nil
}
