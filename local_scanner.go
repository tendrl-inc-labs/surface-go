package surface

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// ScanMode determines how the client performs scans.
type ScanMode string

const (
	// ModeAPI sends files to the remote Surface API for scanning.
	// Requires an API key. This is the default mode.
	ModeAPI ScanMode = "api"

	// ModeLocal runs the scanner binary locally in daemon mode.
	// Scans are performed locally; results are reported to the Surface API.
	ModeLocal ScanMode = "local"
)

// LocalConfig configures the local scanner mode.
type LocalConfig struct {
	// APIKey for the Surface API. Falls back to SURFACE_KEY env var.
	// Required for quota tracking and result reporting.
	APIKey string

	// ScannerPath is the path to the surface-scanner binary.
	// If empty, searches $PATH for "surface-scanner".
	ScannerPath string

	// DataDir is the directory for scanner data (threat feeds, YARA rules, models).
	// Defaults to ~/.surface/data/
	DataDir string

	// Port to run the daemon on. 0 (default) picks a random available port.
	Port int
}

// localDaemon manages a scanner binary running in daemon mode.
type localDaemon struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	port    int
	baseURL string
	client  *http.Client
	started bool
}

// NewLocalClient creates a client that scans files locally using the scanner binary.
// The scanner is started in daemon mode on first scan and stopped on Close().
func NewLocalClient(config *LocalConfig) (*Client, error) {
	if config == nil {
		config = &LocalConfig{}
	}

	apiKey := config.APIKey
	if apiKey == "" {
		apiKey = os.Getenv("SURFACE_KEY")
	}
	if apiKey == "" {
		return nil, &AuthenticationError{SurfaceError{
			StatusCode: 401,
			Message:    "No API key provided. Pass APIKey in LocalConfig or set the SURFACE_KEY environment variable.",
		}}
	}

	scannerPath := config.ScannerPath
	if scannerPath == "" {
		var err error
		scannerPath, err = exec.LookPath("surface-scanner")
		if err != nil {
			return nil, fmt.Errorf("surface: scanner binary not found in PATH (set LocalConfig.ScannerPath or install surface-scanner): %w", err)
		}
	}

	if _, err := os.Stat(scannerPath); err != nil {
		return nil, fmt.Errorf("surface: scanner binary not found at %s: %w", scannerPath, err)
	}

	daemon := &localDaemon{
		client: &http.Client{Timeout: 120 * time.Second},
	}

	c := &Client{
		APIKey: apiKey,
		Mode:   ModeLocal,
		HTTP:   http.DefaultClient,
		local:  daemon,
		localConfig: &localConfigInternal{
			scannerPath: scannerPath,
			dataDir:     config.DataDir,
			port:        config.Port,
		},
	}
	return c, nil
}

type localConfigInternal struct {
	scannerPath string
	dataDir     string
	port        int
}

// ensureRunning starts the daemon if it isn't already running.
func (d *localDaemon) ensureRunning(config *localConfigInternal) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.started {
		return nil
	}

	port := config.port
	if port == 0 {
		var err error
		port, err = findFreePort()
		if err != nil {
			return fmt.Errorf("surface: find free port: %w", err)
		}
	}

	args := []string{
		"--daemon",
		fmt.Sprintf("--listen=:%d", port),
	}
	if config.dataDir != "" {
		args = append(args, "--data-dir="+config.dataDir)
	}

	d.cmd = exec.Command(config.scannerPath, args...)
	d.cmd.Stderr = os.Stderr
	if err := d.cmd.Start(); err != nil {
		return fmt.Errorf("surface: start scanner daemon: %w", err)
	}

	d.port = port
	d.baseURL = fmt.Sprintf("http://127.0.0.1:%d", port)

	// Wait for daemon to be ready
	if err := d.waitForReady(); err != nil {
		_ = d.cmd.Process.Kill()
		return fmt.Errorf("surface: scanner daemon failed to start: %w", err)
	}

	d.started = true
	return nil
}

// waitForReady polls the daemon's health endpoint until it responds.
func (d *localDaemon) waitForReady() error {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := d.client.Get(d.baseURL + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("daemon did not become ready within 30 seconds")
}

// scan sends a file to the local daemon and returns the result.
func (d *localDaemon) scan(ctx context.Context, filename string, r io.Reader, opts *ScanFileOptions) (*ScanFileResult, error) {
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

	scanURL := d.baseURL + "/scan"
	if opts != nil && opts.Defer {
		scanURL += "?defer=true"
	}

	req, err := http.NewRequestWithContext(ctx, "POST", scanURL, &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("surface: local scan request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("surface: read scan response: %w", err)
	}

	if resp.StatusCode == http.StatusAccepted {
		var deferred DeferredScanResponse
		if err := json.Unmarshal(body, &deferred); err != nil {
			return nil, fmt.Errorf("surface: decode deferred response: %w", err)
		}
		return &ScanFileResult{Deferred: &deferred}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("surface: local scanner returned %d: %s", resp.StatusCode, string(body))
	}

	var result ScanResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("surface: decode scan result: %w", err)
	}
	return &ScanFileResult{ScanResult: &result}, nil
}

// stop kills the daemon process.
func (d *localDaemon) stop() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.started || d.cmd == nil || d.cmd.Process == nil {
		return nil
	}

	d.started = false
	if err := d.cmd.Process.Signal(os.Interrupt); err != nil {
		_ = d.cmd.Process.Kill()
	}
	_ = d.cmd.Wait()
	return nil
}

// scanLocal handles a scan in local mode, starting the daemon if needed.
func (c *Client) scanLocal(ctx context.Context, filename string, r io.Reader, opts *ScanFileOptions) (*ScanFileResult, error) {
	if err := c.local.ensureRunning(c.localConfig); err != nil {
		return nil, err
	}
	result, err := c.local.scan(ctx, filename, r, opts)
	if err != nil {
		return nil, err
	}

	if opts != nil && len(opts.Reject) > 0 && result.ScanResult != nil {
		for _, level := range opts.Reject {
			// Same semantics as the API path: match a threat level
			// ("Clean"/"Suspicious"/"Malicious") or a recommended action
			// ("Allow"/"Review"/"Block"), case-insensitively.
			if strings.EqualFold(result.ScanResult.SafetyScore.ThreatLevel, level) ||
				strings.EqualFold(result.ScanResult.SafetyScore.RecommendedAction, level) {
				return nil, &MaliciousFileError{Result: result.ScanResult}
			}
		}
	}

	return result, nil
}

// scanLocalFile scans a file from disk in local mode.
func (c *Client) scanLocalFile(ctx context.Context, filePath string, opts *ScanFileOptions) (*ScanFileResult, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("surface: open file: %w", err)
	}
	defer f.Close()
	return c.scanLocal(ctx, filepath.Base(filePath), f, opts)
}

// scanLocalPayload scans a raw payload in local mode via the daemon's /scan/payload endpoint.
func (c *Client) scanLocalPayload(ctx context.Context, payload []byte, label string, opts *ScanFileOptions) (*ScanFileResult, error) {
	if err := c.local.ensureRunning(c.localConfig); err != nil {
		return nil, err
	}

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

	scanURL := c.local.baseURL + "/scan/payload"
	req, err := http.NewRequestWithContext(ctx, "POST", scanURL, bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("surface: local payload scan: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("surface: local scanner returned %d: %s", resp.StatusCode, string(body))
	}

	var result ScanResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("surface: decode local result: %w", err)
	}

	sfr := &ScanFileResult{ScanResult: &result}

	if opts != nil && len(opts.Reject) > 0 {
		for _, level := range opts.Reject {
			// Same semantics as the API path — threat level or recommended
			// action, case-insensitively.
			if strings.EqualFold(result.SafetyScore.ThreatLevel, level) ||
				strings.EqualFold(result.SafetyScore.RecommendedAction, level) {
				return nil, &MaliciousFileError{Result: &result}
			}
		}
	}

	return sfr, nil
}

// Close stops the local scanner daemon if running.
// Safe to call on API-mode clients (no-op).
func (c *Client) Close() error {
	if c.local != nil {
		return c.local.stop()
	}
	return nil
}

func findFreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port, nil
}
