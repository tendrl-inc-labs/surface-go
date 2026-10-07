// Package surface provides a Go client for the Surface file scanning API.
//
// Usage:
//
//	client, err := surface.NewClient("your-surface-token")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	result, err := client.ScanFile(context.Background(), "invoice.pdf", nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(result.ScanResult.SafetyScore.ThreatLevel)
package surface

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// base64Encode returns the standard base64 encoding of data.
func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// defaultBaseURL points at the Surface service base. Paths like "/scan" and
// "/account/usage" are appended to it, so it includes the "/api" segment.
const defaultBaseURL = "https://app.tendrl.com/surface/api"

// Client is a Surface API client. It supports two modes:
//   - ModeAPI (default): sends files to the remote Surface API
//   - ModeLocal: scans files locally using the scanner binary
type Client struct {
	APIKey  string
	BaseURL string
	HTTP    *http.Client
	Mode    ScanMode

	// Timeout is the budget for one call, covering every attempt and retry
	// wait. It applies when the caller's context has no deadline; a context
	// deadline governs instead. Zero means DefaultTimeout (60s). When the
	// budget runs out the call returns an *UnavailableError.
	Timeout time.Duration

	// Strictness is the default ActionContext.Strictness for ScanPayload: it
	// fills the context's strictness when the caller's context sets none, and
	// is sent alone when no context is given. Empty leaves the scanner default
	// (StrictnessBalanced). An invalid value makes ScanPayload return an error.
	Strictness string

	// retryBase overrides the first retry backoff (tests only).
	retryBase time.Duration

	// internal fields for local scanner mode
	local       *localDaemon
	localConfig *localConfigInternal
}

// NewClient creates a new Surface API client.
// If apiKey is empty, it falls back to the SURFACE_KEY environment variable.
// Returns an error if no key is available.
func NewClient(apiKey string) (*Client, error) {
	if apiKey == "" {
		apiKey = os.Getenv("SURFACE_KEY")
	}
	if apiKey == "" {
		return nil, &AuthenticationError{SurfaceError{
			StatusCode: 401,
			Message:    "No API key provided. Pass apiKey or set the SURFACE_KEY environment variable.",
		}}
	}
	return &Client{
		APIKey:  apiKey,
		BaseURL: defaultBaseURL,
		HTTP:    http.DefaultClient,
		Timeout: DefaultTimeout,
	}, nil
}

// ScanFileOptions configures a scan request.
type ScanFileOptions struct {
	Defer     bool
	RequestID string
	// Reject lists threat levels ("Malicious"/"Suspicious") or recommended
	// actions ("Block"/"Review") that should be rejected. If the scan result
	// matches any of them, a *MaliciousFileError is returned instead.
	// E.g. []string{"Block"} or []string{"Malicious", "Suspicious"}
	Reject []string
	// Context is caller-supplied context for action screening of tool-call
	// payloads. It lets the screener tell an action that fits who you are and
	// what the user asked (a payment to a known payee, an email the user
	// requested) from one that does not (a payment to an unknown account, data
	// leaving to a personal address). Ignored for payloads that are not tool
	// calls. Supply it from your trusted application state, never from the
	// content being scanned. Optional; omit for face-value screening only.
	Context *ActionContext
}

// ActionContext is what your application knows that the scanned payload does
// not: whose domains are internal, which payees are legitimate, and what the
// user actually asked the agent to do. Every field is optional. See the
// "Action Screening Context" section of the README for use cases.
type ActionContext struct {
	// PrincipalDomains are the domains that count as inside the organization,
	// e.g. []string{"acme.io"}. Data sent outside them is treated as egress.
	PrincipalDomains []string `json:"principal_domains,omitempty"`
	// UserRequest is what the user actually asked for, from your trusted UI
	// channel — never text lifted from the payload. It lets the screener clear
	// an action the user asked for and flag one unrelated to the task.
	UserRequest string `json:"user_request,omitempty"`
	// AllowedEgress lists the external hosts the agent is expected to send data
	// to — its known integrations, e.g. []string{"api.stripe.com", "hooks.slack.com"}.
	// With this present, data sent to a host in neither PrincipalDomains nor this
	// list, and not named in UserRequest, is flagged for review. Leave it empty and
	// ordinary third-party API calls are not judged (only bare-IP and secret egress
	// are), so you opt in to unknown-destination detection by declaring your hosts.
	AllowedEgress []string `json:"allowed_egress,omitempty"`
	// Strictness sets how readily a judgment call becomes a verdict:
	// StrictnessRelaxed, StrictnessBalanced (the scanner default when empty),
	// or StrictnessStrict. Face-dangerous actions Block at every level.
	Strictness string `json:"strictness,omitempty"`
	// Source is who wrote the payload: SourceUserPrompt, SourceContent or
	// SourceToolCall. Empty means unknown. A prompt-injection match in a
	// user's own prompt is held for Review, never blocked, unless Strictness
	// is StrictnessStrict; in content it blocks; with no source it blocks only
	// on corroborated evidence.
	Source string `json:"source,omitempty"`
	// PersonalMailExpected says your users routinely correspond with people on
	// personal mailboxes (customers, candidates, family on Gmail). A send to a
	// personal address the user named in UserRequest is then allowed below
	// StrictnessStrict. A live credential still blocks.
	PersonalMailExpected bool `json:"personal_mail_expected,omitempty"`
}

// Accepted ActionContext.Source values.
const (
	// SourceUserPrompt is text the person the agent works for typed.
	SourceUserPrompt = "user_prompt"
	// SourceContent is text the agent reads: a web page, an email, tool output.
	SourceContent = "content"
	// SourceToolCall is an action the agent is about to take. ToolGuard sets it.
	SourceToolCall = "tool_call"
)

func validateSource(s string) error {
	switch s {
	case "", SourceUserPrompt, SourceContent, SourceToolCall:
		return nil
	}
	return fmt.Errorf("surface: source must be one of %q, %q, %q (got %q)",
		SourceUserPrompt, SourceContent, SourceToolCall, s)
}

// Accepted ActionContext.Strictness values. Empty means the scanner default,
// StrictnessBalanced.
const (
	// StrictnessRelaxed stops only what is certainly malicious.
	StrictnessRelaxed = "relaxed"
	// StrictnessBalanced stops what is certainly malicious and asks before
	// risky or irreversible actions. The default.
	StrictnessBalanced = "balanced"
	// StrictnessStrict asks or stops on anything that needs judgment,
	// including mail to personal addresses and outside recipients.
	StrictnessStrict = "strict"
)

// validateStrictness returns an error unless s is empty or an accepted level.
func validateStrictness(s string) error {
	switch s {
	case "", StrictnessRelaxed, StrictnessBalanced, StrictnessStrict:
		return nil
	}
	return fmt.Errorf("surface: strictness must be one of %q, %q, %q (got %q)",
		StrictnessRelaxed, StrictnessBalanced, StrictnessStrict, s)
}

// Validate reports whether the context's values are acceptable. A nil
// context is valid. ScanPayload calls it before sending.
func (a *ActionContext) Validate() error {
	if a == nil {
		return nil
	}
	if err := validateStrictness(a.Strictness); err != nil {
		return err
	}
	return validateSource(a.Source)
}

// payloadContext is the context sent with a payload scan: the caller's, with
// the client's default strictness filling a gap. It never mutates the caller's
// context, and returns nil when there is nothing to send.
func (c *Client) payloadContext(opts *ScanFileOptions) (*ActionContext, error) {
	if err := validateStrictness(c.Strictness); err != nil {
		return nil, err
	}
	var ctx *ActionContext
	if opts != nil {
		ctx = opts.Context
	}
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if c.Strictness == "" || (ctx != nil && ctx.Strictness != "") {
		return ctx, nil
	}
	merged := ActionContext{}
	if ctx != nil {
		merged = *ctx
	}
	merged.Strictness = c.Strictness
	return &merged, nil
}

func (c *Client) buildURL(path string, params url.Values) string {
	base := strings.TrimRight(c.BaseURL, "/")
	if len(params) > 0 {
		return base + path + "?" + params.Encode()
	}
	return base + path
}

// do sends an authenticated API request built fresh by build for each
// attempt (see send). A 4xx answer becomes its typed error.
func (c *Client) do(ctx context.Context, build func() (*http.Request, error)) (int, []byte, error) {
	status, body, err := c.send(ctx, c.HTTP, func() (*http.Request, error) {
		req, err := build()
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
		return req, nil
	})
	if err != nil {
		return 0, nil, err
	}
	if status >= 400 {
		return 0, nil, parseError(status, body)
	}
	return status, body, nil
}

func parseError(status int, body []byte) error {
	msg, requestID, isJSON := errorBody(body)
	if msg == "" {
		msg = fmt.Sprintf("%d %s", status, http.StatusText(status))
	}

	base := SurfaceError{
		StatusCode: status,
		Message:    msg,
		RequestID:  requestID,
	}

	switch status {
	case 401, 403:
		return &AuthenticationError{base}
	case 400:
		return &ValidationError{base}
	case 404:
		return &NotFoundError{base}
	case 429:
		lower := strings.ToLower(msg)
		if strings.Contains(lower, "quota") || strings.Contains(lower, "credit") {
			return &QuotaExceededError{base}
		}
		return &RateLimitError{base}
	}
	if status >= 500 {
		// 500/502/503/504 never reach here; this is any other 5xx. A JSON
		// answer is a real one, a proxy page is not.
		if !isJSON {
			return &UnavailableError{StatusCode: status, Message: msg, Err: &base}
		}
	}
	return &base
}

func (c *Client) getJSON(ctx context.Context, path string, params url.Values, out interface{}) error {
	status, body, err := c.do(ctx, func() (*http.Request, error) {
		return http.NewRequest("GET", c.buildURL(path, params), nil)
	})
	if err != nil {
		return err
	}
	return decodeJSON(status, body, out)
}

func (c *Client) postJSON(ctx context.Context, path string, in interface{}, out interface{}) error {
	data, err := json.Marshal(in)
	if err != nil {
		return err
	}
	status, body, err := c.do(ctx, func() (*http.Request, error) {
		req, err := http.NewRequest("POST", c.buildURL(path, nil), bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	})
	if err != nil {
		return err
	}
	if out != nil {
		return decodeJSON(status, body, out)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------

// ScanFileResult wraps the two possible responses from a scan request.
// Exactly one of ScanResult or Deferred will be non-nil.
type ScanFileResult struct {
	ScanResult *ScanResult
	Deferred   *DeferredScanResponse
}

// ScanFile uploads a file from disk and scans it.
func (c *Client) ScanFile(ctx context.Context, filePath string, opts *ScanFileOptions) (*ScanFileResult, error) {
	if c.Mode == ModeLocal {
		return c.scanLocalFile(ctx, filePath, opts)
	}
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("surface: open file: %w", err)
	}
	defer f.Close()
	return c.ScanReader(ctx, filepath.Base(filePath), f, opts)
}

// ScanBytes uploads raw bytes and scans them.
func (c *Client) ScanBytes(ctx context.Context, filename string, data []byte, opts *ScanFileOptions) (*ScanFileResult, error) {
	return c.ScanReader(ctx, filename, bytes.NewReader(data), opts)
}

// ScanReader uploads from any io.Reader and scans.
func (c *Client) ScanReader(ctx context.Context, filename string, r io.Reader, opts *ScanFileOptions) (*ScanFileResult, error) {
	if c.Mode == ModeLocal {
		return c.scanLocal(ctx, filename, r, opts)
	}

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile("file", filename)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(part, r); err != nil {
		return nil, err
	}
	w.Close()

	params := url.Values{}
	if opts != nil && opts.Defer {
		params.Set("defer", "true")
	}

	data := buf.Bytes()
	status, body, err := c.do(ctx, func() (*http.Request, error) {
		req, err := http.NewRequest("POST", c.buildURL("/scan", params), bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", w.FormDataContentType())
		// The backend derives the request ID from the X-Request-ID header.
		if opts != nil && opts.RequestID != "" {
			req.Header.Set("X-Request-ID", opts.RequestID)
		}
		return req, nil
	})
	if err != nil {
		return nil, err
	}

	if status == 202 {
		var deferred DeferredScanResponse
		if err := decodeJSON(status, body, &deferred); err != nil {
			return nil, err
		}
		return &ScanFileResult{Deferred: &deferred}, nil
	}

	var result ScanResult
	if err := decodeJSON(status, body, &result); err != nil {
		return nil, err
	}

	if opts != nil && len(opts.Reject) > 0 {
		for _, level := range opts.Reject {
			// reject matches on threat level ("Clean"/"Suspicious"/"Malicious") or
			// recommended action ("Allow"/"Review"/"Block") — the two vocabularies
			// don't overlap, so a single case-insensitive check covers both.
			if strings.EqualFold(result.SafetyScore.ThreatLevel, level) ||
				strings.EqualFold(result.SafetyScore.RecommendedAction, level) {
				return nil, &MaliciousFileError{Result: &result}
			}
		}
	}

	return &ScanFileResult{ScanResult: &result}, nil
}

// ScanPayload scans a raw byte payload without multipart file upload.
// This is useful for middleware scanning — scan API request/response bodies
// between services. The label is an optional name for the payload (e.g.
// "api-request", "agent-message.json"). Defaults to "payload.bin" if empty.
// Content type is auto-detected from bytes.
//
// Text payloads are sent as raw strings (no encoding overhead). Binary payloads
// are automatically base64-encoded with encoding:"base64" set.
func (c *Client) ScanPayload(ctx context.Context, payload []byte, label string, opts *ScanFileOptions) (*ScanFileResult, error) {
	if c.Mode == ModeLocal {
		return c.scanLocalPayload(ctx, payload, label, opts)
	}

	if label == "" {
		label = "payload.bin"
	}

	// Auto-detect: if content is valid UTF-8 text, send raw. Otherwise base64.
	type payloadReq struct {
		Payload  string         `json:"payload"`
		Label    string         `json:"label,omitempty"`
		Encoding string         `json:"encoding,omitempty"`
		Context  *ActionContext `json:"context,omitempty"`
	}
	actionCtx, err := c.payloadContext(opts)
	if err != nil {
		return nil, err
	}
	var reqBody payloadReq
	if utf8.Valid(payload) {
		reqBody = payloadReq{Payload: string(payload), Label: label, Context: actionCtx}
	} else {
		reqBody = payloadReq{Payload: base64Encode(payload), Label: label, Encoding: "base64", Context: actionCtx}
	}
	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	params := url.Values{}
	if opts != nil && opts.Defer {
		params.Set("defer", "true")
	}

	status, body, err := c.do(ctx, func() (*http.Request, error) {
		req, err := http.NewRequest("POST", c.buildURL("/scan/payload", params), bytes.NewReader(bodyJSON))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		// The backend derives the request ID from the X-Request-ID header.
		if opts != nil && opts.RequestID != "" {
			req.Header.Set("X-Request-ID", opts.RequestID)
		}
		return req, nil
	})
	if err != nil {
		return nil, err
	}

	if status == 202 {
		var deferred DeferredScanResponse
		if err := decodeJSON(status, body, &deferred); err != nil {
			return nil, err
		}
		return &ScanFileResult{Deferred: &deferred}, nil
	}

	var result ScanResult
	if err := decodeJSON(status, body, &result); err != nil {
		return nil, err
	}

	if opts != nil && len(opts.Reject) > 0 {
		for _, level := range opts.Reject {
			// reject matches on threat level ("Clean"/"Suspicious"/"Malicious") or
			// recommended action ("Allow"/"Review"/"Block") — the two vocabularies
			// don't overlap, so a single case-insensitive check covers both.
			if strings.EqualFold(result.SafetyScore.ThreatLevel, level) ||
				strings.EqualFold(result.SafetyScore.RecommendedAction, level) {
				return nil, &MaliciousFileError{Result: &result}
			}
		}
	}

	return &ScanFileResult{ScanResult: &result}, nil
}

// ScanFiles scans multiple files concurrently from disk.
// maxConcurrency controls how many uploads run in parallel (0 defaults to 10).
// Returns results in the same order as the input paths. If any scan fails,
// the first error is returned and remaining scans are canceled.
func (c *Client) ScanFiles(ctx context.Context, filePaths []string, opts *ScanFileOptions, maxConcurrency int) ([]*ScanFileResult, error) {
	if maxConcurrency <= 0 {
		maxConcurrency = 10
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make([]*ScanFileResult, len(filePaths))
	var firstErr error
	var errOnce sync.Once

	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup

	for i, fp := range filePaths {
		wg.Add(1)
		go func(idx int, path string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			res, err := c.ScanFile(ctx, path, opts)
			if err != nil {
				errOnce.Do(func() {
					firstErr = err
					cancel()
				})
				return
			}
			results[idx] = res
		}(i, fp)
	}
	wg.Wait()

	if firstErr != nil {
		return nil, firstErr
	}
	return results, nil
}

// GetScan retrieves a deferred scan result by scan ID.
func (c *Client) GetScan(ctx context.Context, scanID string) (json.RawMessage, error) {
	var raw json.RawMessage
	if err := c.getJSON(ctx, "/scan/"+url.PathEscape(scanID), nil, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// ---------------------------------------------------------------------------
// Account / usage
// ---------------------------------------------------------------------------

// GetUsage returns scan usage vs the monthly limit for the current billing period.
func (c *Client) GetUsage(ctx context.Context) (*Usage, error) {
	var u Usage
	if err := c.getJSON(ctx, "/account/usage", nil, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// GetAccount returns full account details.
func (c *Client) GetAccount(ctx context.Context) (json.RawMessage, error) {
	var raw json.RawMessage
	if err := c.getJSON(ctx, "/account", nil, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// ---------------------------------------------------------------------------
// Scan history
// ---------------------------------------------------------------------------

// GetScanHistory returns paginated scan history.
func (c *Client) GetScanHistory(ctx context.Context, page, limit int) (*ScanHistoryPage, error) {
	params := url.Values{}
	if page > 0 {
		params.Set("page", strconv.Itoa(page))
	}
	if limit > 0 {
		params.Set("limit", strconv.Itoa(limit))
	}
	var h ScanHistoryPage
	if err := c.getJSON(ctx, "/account/history", params, &h); err != nil {
		return nil, err
	}
	return &h, nil
}
