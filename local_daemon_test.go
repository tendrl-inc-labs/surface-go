package surface

import (
	"bytes"
	"flag"
	"fmt"
	"net/http"
	"os"

	"strings"
	"testing"
	"time"
)

// The test binary doubles as a fake scanner: with FAKE_SCANNER set, TestMain
// runs fakeScanner instead of the tests. FAKE_SCANNER=parentpid lists
// --parent-pid in its usage; =old does not (a binary from before the flag);
// =crash exits during startup. FAKE_SCANNER_ARGS, if set, is a file the fake
// writes its arguments to.
func TestMain(m *testing.M) {
	if mode := os.Getenv("FAKE_SCANNER"); mode != "" {
		fakeScanner(mode)
		return
	}
	os.Exit(m.Run())
}

func fakeScanner(mode string) {
	fs := flag.NewFlagSet("surface-scanner", flag.ContinueOnError)
	fs.Bool("daemon", false, "run as daemon")
	listen := fs.String("listen", "127.0.0.1:8080", "listen address")
	fs.String("data-dir", "", "data dir")
	if mode != "old" {
		fs.Int("parent-pid", 0, "exit with parent")
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2) // -h and unknown flags, like the real flag package
	}
	if f := os.Getenv("FAKE_SCANNER_ARGS"); f != "" {
		_ = os.WriteFile(f, []byte(strings.Join(os.Args[1:], "\n")), 0o600)
		_ = os.WriteFile(f+".key", []byte(os.Getenv("SURFACE_API_KEY")), 0o600)
	}
	if mode == "crash" {
		fmt.Fprintln(os.Stderr, "fatal: could not open threat intel database")
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "fake daemon listening on", *listen)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	_ = http.ListenAndServe(*listen, nil)
	os.Exit(0)
}

func fakeLocalClient(t *testing.T, mode string, cfg LocalConfig) (*Client, string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	argsFile := t.TempDir() + "/args"
	t.Setenv("FAKE_SCANNER", mode)
	t.Setenv("FAKE_SCANNER_ARGS", argsFile)
	cfg.APIKey, cfg.ScannerPath = "sfk_test", exe
	parentPIDSupport.Delete(exe)
	c, err := NewLocalClient(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, argsFile
}

func TestLocalDaemonListensOnLoopbackWithParentPID(t *testing.T) {
	c, argsFile := fakeLocalClient(t, "parentpid", LocalConfig{})
	if err := c.local.ensureRunning(c.localConfig); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(argsFile)
	args := string(raw)
	if !strings.Contains(args, "--listen=127.0.0.1:") {
		t.Errorf("daemon not bound to loopback: %q", args)
	}
	if !strings.Contains(args, fmt.Sprintf("--parent-pid=%d", os.Getpid())) {
		t.Errorf("daemon not tied to this process: %q", args)
	}
}

// The scanner reads its key from SURFACE_API_KEY and will not start without
// one; the client's key must reach it even when only SURFACE_KEY or
// LocalConfig.APIKey was set.
func TestLocalDaemonReceivesClientKey(t *testing.T) {
	t.Setenv("SURFACE_API_KEY", "")
	c, argsFile := fakeLocalClient(t, "parentpid", LocalConfig{})
	if err := c.local.ensureRunning(c.localConfig); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(argsFile + ".key")
	if string(got) != "sfk_test" {
		t.Errorf("daemon SURFACE_API_KEY = %q, want the client's key", got)
	}
	raw, _ := os.ReadFile(argsFile)
	if strings.Contains(string(raw), "sfk_test") {
		t.Errorf("key passed on the command line: %q", raw)
	}
}

func TestLocalDaemonOlderBinaryStartsWithoutParentPID(t *testing.T) {
	c, argsFile := fakeLocalClient(t, "old", LocalConfig{})
	if err := c.local.ensureRunning(c.localConfig); err != nil {
		t.Fatalf("an older binary must still start: %v", err)
	}
	raw, _ := os.ReadFile(argsFile)
	if strings.Contains(string(raw), "parent-pid") {
		t.Errorf("passed --parent-pid to a binary that does not accept it: %q", raw)
	}
}

// A daemon that dies during startup fails the call at once, with its last
// output, instead of waiting out the timeout.
func TestLocalDaemonCrashFailsFastWithOutput(t *testing.T) {
	c, _ := fakeLocalClient(t, "crash", LocalConfig{StartTimeout: time.Minute})
	t0 := time.Now()
	err := c.local.ensureRunning(c.localConfig)
	if err == nil {
		t.Fatal("expected a startup error")
	}
	if d := time.Since(t0); d > 10*time.Second {
		t.Errorf("took %s to notice the daemon exited", d)
	}
	if !strings.Contains(err.Error(), "could not open threat intel database") {
		t.Errorf("error lacks the daemon's output: %v", err)
	}
}

// Daemon output stays out of the program's own stderr unless asked for, so a
// running daemon never holds a caller's pipe open.
func TestLocalDaemonOutputGoesToConfiguredWriter(t *testing.T) {
	var log bytes.Buffer
	c, _ := fakeLocalClient(t, "parentpid", LocalConfig{Stderr: &log})
	if err := c.local.ensureRunning(c.localConfig); err != nil {
		t.Fatal(err)
	}
	if c.local.cmd.Stderr == os.Stderr || c.local.cmd.Stdout == os.Stdout {
		t.Error("daemon output is wired to the program's own stdio")
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(c.local.logTail.String(), "fake daemon listening") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(c.local.logTail.String(), "fake daemon listening") {
		t.Errorf("log tail missing daemon output: %q", c.local.logTail.String())
	}
}

func TestLocalDaemonCloseStopsIt(t *testing.T) {
	c, _ := fakeLocalClient(t, "parentpid", LocalConfig{})
	if err := c.local.ensureRunning(c.localConfig); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.local.exited:
	default:
		t.Error("daemon still running after Close")
	}
}

func TestTailBufferKeepsTheEnd(t *testing.T) {
	b := newTailBuffer(8)
	fmt.Fprint(b, "0123456789")
	fmt.Fprint(b, "ab")
	if got := b.String(); got != "456789ab" {
		t.Errorf("tail = %q", got)
	}
}
