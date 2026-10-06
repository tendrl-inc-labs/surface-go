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

	// Strictness is the client's default ActionContext.Strictness for payload
	// scans (see Client.Strictness). Empty leaves the scanner default.
	Strictness string

	// StartTimeout bounds how long the first scan waits for the daemon to
	// become ready. The first launch on a machine downloads threat feeds, so
	// the default is 2 minutes; later launches take seconds.
	StartTimeout time.Duration

	// Stderr, if set, receives the daemon's log output. By default it is kept
	// out of your program's stderr (a daemon holding that open makes a
	// pipeline like `yourprogram | tail` wait forever); the last few KB are
	// still included in the error if the daemon fails to start.
	Stderr io.Writer
}

const defaultStartTimeout = 2 * time.Minute

// localDaemon manages a scanner binary running in daemon mode.
//
// The daemon listens on loopback only and is started with --parent-pid when
// the binary supports it, so it exits with your program even if Close is
// never called. Older binaries without that flag still work; call Close.
type localDaemon struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	exited  chan struct{} // closed when the daemon process exits
	exitErr error         // set before exited is closed
	logTail *tailBuffer
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

	if err := validateStrictness(config.Strictness); err != nil {
		return nil, err
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

	// No client-level timeout: each call is bounded by Client.Timeout.
	daemon := &localDaemon{
		client: &http.Client{},
	}

	c := &Client{
		APIKey:     apiKey,
		Mode:       ModeLocal,
		HTTP:       http.DefaultClient,
		Timeout:    DefaultTimeout,
		Strictness: config.Strictness,
		local:      daemon,
		localConfig: &localConfigInternal{
			scannerPath:  scannerPath,
			dataDir:      config.DataDir,
			port:         config.Port,
			startTimeout: config.StartTimeout,
			stderr:       config.Stderr,
		},
	}
	return c, nil
}

type localConfigInternal struct {
	scannerPath  string
	dataDir      string
	port         int
	startTimeout time.Duration
	stderr       io.Writer
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

	// Loopback only: the daemon has no authentication of its own, so an
	// all-interfaces bind would expose an open scanning service to the network.
	args := []string{
		"--daemon",
		fmt.Sprintf("--listen=127.0.0.1:%d", port),
	}
	if config.dataDir != "" {
		args = append(args, "--data-dir="+config.dataDir)
	}
	if scannerSupportsParentPID(config.scannerPath) {
		args = append(args, fmt.Sprintf("--parent-pid=%d", os.Getpid()))
	}

	d.logTail = newTailBuffer(8 << 10)
	var logOut io.Writer = d.logTail
	if config.stderr != nil {
		logOut = io.MultiWriter(d.logTail, config.stderr)
	}
	d.cmd = exec.Command(config.scannerPath, args...)
	d.cmd.Stdout = logOut
	d.cmd.Stderr = logOut
	if err := d.cmd.Start(); err != nil {
		return fmt.Errorf("surface: start scanner daemon: %w", err)
	}
	exited := make(chan struct{})
	d.exited = exited
	go func(cmd *exec.Cmd) {
		err := cmd.Wait()
		d.exitErr = err
		close(exited)
	}(d.cmd)

	d.port = port
	d.baseURL = fmt.Sprintf("http://127.0.0.1:%d", port)

	timeout := config.startTimeout
	if timeout <= 0 {
		timeout = defaultStartTimeout
	}
	if err := d.waitForReady(timeout); err != nil {
		_ = d.cmd.Process.Kill()
		<-d.exited
		if tail := strings.TrimSpace(d.logTail.String()); tail != "" {
			err = fmt.Errorf("%w\nscanner output:\n%s", err, tail)
		}
		return fmt.Errorf("surface: scanner daemon failed to start: %w", err)
	}

	d.started = true
	return nil
}

// waitForReady polls the daemon's health endpoint until it responds, the
// daemon exits, or timeout passes. Each poll has its own short timeout so the
// overall deadline holds.
func (d *localDaemon) waitForReady(timeout time.Duration) error {
	poll := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-d.exited:
			if d.exitErr != nil {
				return fmt.Errorf("daemon exited during startup: %v", d.exitErr)
			}
			return fmt.Errorf("daemon exited during startup")
		default:
		}
		resp, err := poll.Get(d.baseURL + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-d.exited:
		case <-time.After(200 * time.Millisecond):
		}
	}
	return fmt.Errorf("daemon did not become ready within %s (the first launch downloads threat feeds; raise LocalConfig.StartTimeout if needed)", timeout)
}

// parentPIDSupport caches, per scanner binary, whether it accepts --parent-pid.
var parentPIDSupport sync.Map

// scannerSupportsParentPID reports whether the binary lists --parent-pid in
// its usage. Binaries from before that flag reject unknown flags and would
// fail to start, so it is only passed when present.
func scannerSupportsParentPID(path string) bool {
	if v, ok := parentPIDSupport.Load(path); ok {
		return v.(bool)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, path, "-h").CombinedOutput() // -h exits non-zero
	ok := bytes.Contains(out, []byte("parent-pid"))
	parentPIDSupport.Store(path, ok)
	return ok
}

// tailBuffer keeps the last max bytes written to it.
type tailBuffer struct {
	mu  sync.Mutex
	max int
	buf []byte
}

func newTailBuffer(max int) *tailBuffer { return &tailBuffer{max: max} }

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if over := len(t.buf) - t.max; over > 0 {
		t.buf = append(t.buf[:0], t.buf[over:]...)
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}

func (c *Client) localScanRequest(ctx context.Context, filename string, r io.Reader, opts *ScanFileOptions) (*ScanFileResult, error) {
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

	scanURL := c.local.baseURL + "/scan"
	if opts != nil && opts.Defer {
		scanURL += "?defer=true"
	}

	data := buf.Bytes()
	status, body, err := c.send(ctx, c.local.client, func() (*http.Request, error) {
		req, err := http.NewRequest("POST", scanURL, bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", w.FormDataContentType())
		return req, nil
	})
	if err != nil {
		return nil, err
	}

	if status == http.StatusAccepted {
		var deferred DeferredScanResponse
		if err := decodeJSON(status, body, &deferred); err != nil {
			return nil, err
		}
		return &ScanFileResult{Deferred: &deferred}, nil
	}

	if status != http.StatusOK {
		return nil, fmt.Errorf("surface: local scanner returned %d: %s", status, string(body))
	}

	var result ScanResult
	if err := decodeJSON(status, body, &result); err != nil {
		return nil, err
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
	select {
	case <-d.exited:
	case <-time.After(5 * time.Second):
		_ = d.cmd.Process.Kill()
		<-d.exited
	}
	return nil
}

// scanLocal handles a scan in local mode, starting the daemon if needed.
func (c *Client) scanLocal(ctx context.Context, filename string, r io.Reader, opts *ScanFileOptions) (*ScanFileResult, error) {
	if err := c.local.ensureRunning(c.localConfig); err != nil {
		return nil, err
	}
	result, err := c.localScanRequest(ctx, filename, r, opts)
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
	actionCtx, err := c.payloadContext(opts)
	if err != nil {
		return nil, err
	}
	if err := c.local.ensureRunning(c.localConfig); err != nil {
		return nil, err
	}

	type payloadReq struct {
		Payload  string         `json:"payload"`
		Label    string         `json:"label,omitempty"`
		Encoding string         `json:"encoding,omitempty"`
		Context  *ActionContext `json:"context,omitempty"`
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
	status, body, err := c.send(ctx, c.local.client, func() (*http.Request, error) {
		req, err := http.NewRequest("POST", scanURL, bytes.NewReader(bodyJSON))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	})
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("surface: local scanner returned %d: %s", status, string(body))
	}

	var result ScanResult
	if err := decodeJSON(status, body, &result); err != nil {
		return nil, err
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
