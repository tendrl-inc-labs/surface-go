// Package surface provides a Go client for the Surface file scanning API.
//
// Usage:
//
//	client := surface.NewClient("sfk_your_token_here")
//	result, err := client.ScanFile(context.Background(), "malware.exe", nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(result.SafetyScore.ThreatLevel)
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
	// KnownPayees are the accounts you legitimately pay. A payment to one of
	// these is routine; a payment to any other account, with this list present,
	// is flagged.
	KnownPayees []ActionPayee `json:"known_payees,omitempty"`
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
}

// ActionPayee identifies an account the caller legitimately pays. Give whichever
// identifier your payments use; the screener matches on any provided.
type ActionPayee struct {
	Name    string `json:"name,omitempty"`
	IBAN    string `json:"iban,omitempty"`
	Account string `json:"account,omitempty"`
}

func (c *Client) buildURL(path string, params url.Values) string {
	base := strings.TrimRight(c.BaseURL, "/")
	if len(params) > 0 {
		return base + path + "?" + params.Encode()
	}
	return base + path
}

func (c *Client) do(ctx context.Context, req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req = req.WithContext(ctx)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		return nil, c.parseError(resp)
	}
	return resp, nil
}

func (c *Client) parseError(resp *http.Response) error {
	var body struct {
		Error     string `json:"error"`
		RequestID string `json:"requestId"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body.Error == "" {
		body.Error = resp.Status
	}

	base := SurfaceError{
		StatusCode: resp.StatusCode,
		Message:    body.Error,
		RequestID:  body.RequestID,
	}

	switch resp.StatusCode {
	case 401, 403:
		return &AuthenticationError{base}
	case 400:
		return &ValidationError{base}
	case 404:
		return &NotFoundError{base}
	case 429:
		msg := strings.ToLower(body.Error)
		if strings.Contains(msg, "quota") || strings.Contains(msg, "credit") {
			return &QuotaExceededError{base}
		}
		return &RateLimitError{base}
	default:
		return &base
	}
}

func (c *Client) getJSON(ctx context.Context, path string, params url.Values, out interface{}) error {
	req, err := http.NewRequest("GET", c.buildURL(path, params), nil)
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) postJSON(ctx context.Context, path string, body interface{}, out interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", c.buildURL(path, nil), bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.do(ctx, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *Client) putJSON(ctx context.Context, path string, body interface{}, out interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("PUT", c.buildURL(path, nil), bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.do(ctx, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *Client) delete(ctx context.Context, path string) error {
	req, err := http.NewRequest("DELETE", c.buildURL(path, nil), nil)
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, req)
	if err != nil {
		return err
	}
	resp.Body.Close()
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

	req, err := http.NewRequest("POST", c.buildURL("/scan", params), &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	// The backend derives the request ID from the X-Request-ID header.
	if opts != nil && opts.RequestID != "" {
		req.Header.Set("X-Request-ID", opts.RequestID)
	}

	resp, err := c.do(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 202 {
		var deferred DeferredScanResponse
		if err := json.NewDecoder(resp.Body).Decode(&deferred); err != nil {
			return nil, err
		}
		return &ScanFileResult{Deferred: &deferred}, nil
	}

	var result ScanResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
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
	var actionCtx *ActionContext
	if opts != nil {
		actionCtx = opts.Context
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

	req, err := http.NewRequest("POST", c.buildURL("/scan/payload", params), bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	// The backend derives the request ID from the X-Request-ID header.
	if opts != nil && opts.RequestID != "" {
		req.Header.Set("X-Request-ID", opts.RequestID)
	}

	resp, err := c.do(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 202 {
		var deferred DeferredScanResponse
		if err := json.NewDecoder(resp.Body).Decode(&deferred); err != nil {
			return nil, err
		}
		return &ScanFileResult{Deferred: &deferred}, nil
	}

	var result ScanResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
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
// Scan profiles
// ---------------------------------------------------------------------------

// ListProfiles returns all scan profiles for the account.
func (c *Client) ListProfiles(ctx context.Context) ([]ScanProfile, error) {
	var resp struct {
		Profiles []ScanProfile `json:"profiles"`
	}
	if err := c.getJSON(ctx, "/account/profiles", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Profiles, nil
}

// CreateProfile creates a new scan profile.
func (c *Client) CreateProfile(ctx context.Context, params map[string]interface{}) (*ScanProfile, error) {
	var p ScanProfile
	if err := c.postJSON(ctx, "/account/profiles", params, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// UpdateProfile updates an existing scan profile.
func (c *Client) UpdateProfile(ctx context.Context, profileID string, params map[string]interface{}) (*ScanProfile, error) {
	var p ScanProfile
	if err := c.putJSON(ctx, "/account/profiles/"+url.PathEscape(profileID), params, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// DeleteProfile deletes a scan profile.
func (c *Client) DeleteProfile(ctx context.Context, profileID string) error {
	return c.delete(ctx, "/account/profiles/"+url.PathEscape(profileID))
}

// ---------------------------------------------------------------------------
// API keys
// ---------------------------------------------------------------------------

// ListAPIKeys returns all API keys for the account.
func (c *Client) ListAPIKeys(ctx context.Context) ([]APIKey, error) {
	var resp struct {
		Keys []APIKey `json:"keys"`
	}
	if err := c.getJSON(ctx, "/account/keys", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Keys, nil
}

// CreateAPIKey creates a new API key.
func (c *Client) CreateAPIKey(ctx context.Context, label string, profileID string) (*APIKey, error) {
	body := map[string]string{"label": label}
	if profileID != "" {
		body["profile_id"] = profileID
	}
	var k APIKey
	if err := c.postJSON(ctx, "/account/keys", body, &k); err != nil {
		return nil, err
	}
	return &k, nil
}

// DeleteAPIKey deletes an API key.
func (c *Client) DeleteAPIKey(ctx context.Context, keyID string) error {
	return c.delete(ctx, "/account/keys/"+url.PathEscape(keyID))
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
