package surface

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newTestLocalClient builds a ModeLocal client whose daemon is already "running"
// and pointed at an httptest server, so local-mode behavior can be exercised
// without the surface-scanner binary.
func newTestLocalClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	c := &Client{
		APIKey: "sfk_test",
		Mode:   ModeLocal,
		HTTP:   http.DefaultClient,
		local: &localDaemon{
			started: true,
			baseURL: srv.URL,
			client:  &http.Client{Timeout: 10 * time.Second},
		},
		localConfig: &localConfigInternal{scannerPath: "unused"},
	}
	return c, srv
}

// Reject in local mode has to behave exactly like Reject in API mode: match a
// threat level OR a recommended action, case-insensitively. "Block" is the value
// the Quick Start uses, and it only ever appears as a recommendedAction.
func TestLocalRejectMatchesRecommendedAction(t *testing.T) {
	c, srv := newTestLocalClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(maliciousScanJSON))
	})
	defer srv.Close()

	_, err := c.ScanBytes(context.Background(), "sample.exe", []byte("payload"),
		&ScanFileOptions{Reject: []string{"Block"}})
	var mfe *MaliciousFileError
	if !errors.As(err, &mfe) {
		t.Fatalf("Reject []string{\"Block\"} was a no-op in local mode: got %v", err)
	}
}

func TestLocalRejectMatchesThreatLevelMixedCase(t *testing.T) {
	c, srv := newTestLocalClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(maliciousScanJSON))
	})
	defer srv.Close()

	_, err := c.ScanBytes(context.Background(), "sample.exe", []byte("payload"),
		&ScanFileOptions{Reject: []string{"mAlIcIoUs"}})
	var mfe *MaliciousFileError
	if !errors.As(err, &mfe) {
		t.Fatalf("mixed-case threat level was a no-op in local mode: got %v", err)
	}
}

// The payload path has its own copy of the reject loop; it must agree.
func TestLocalPayloadRejectMatchesRecommendedAction(t *testing.T) {
	c, srv := newTestLocalClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(maliciousScanJSON))
	})
	defer srv.Close()

	_, err := c.ScanPayload(context.Background(), []byte("payload"), "api-request",
		&ScanFileOptions{Reject: []string{"block"}})
	var mfe *MaliciousFileError
	if !errors.As(err, &mfe) {
		t.Fatalf("Reject []string{\"block\"} was a no-op on the local payload path: got %v", err)
	}
}

func TestLocalPayloadRejectMatchesThreatLevelMixedCase(t *testing.T) {
	c, srv := newTestLocalClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(maliciousScanJSON))
	})
	defer srv.Close()

	_, err := c.ScanPayload(context.Background(), []byte("payload"), "api-request",
		&ScanFileOptions{Reject: []string{"Malicious"}})
	var mfe *MaliciousFileError
	if !errors.As(err, &mfe) {
		t.Fatalf("expected *MaliciousFileError on the local payload path, got %v", err)
	}
}

// Reject must not fire on values the result doesn't carry.
func TestLocalRejectDoesNotFalselyMatch(t *testing.T) {
	c, srv := newTestLocalClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(maliciousScanJSON))
	})
	defer srv.Close()

	res, err := c.ScanBytes(context.Background(), "sample.exe", []byte("payload"),
		&ScanFileOptions{Reject: []string{"clean", "allow"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ScanResult == nil || res.ScanResult.SafetyScore.ThreatLevel != "Malicious" {
		t.Fatalf("expected accepted Malicious result, got %+v", res)
	}
}
