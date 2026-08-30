package surface

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func TestScanBytesFuncRunsHandlerForAccepted(t *testing.T) {
	c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(minimalCoverageScanJSON))
	})
	defer srv.Close()

	var seen *ScanResult
	process := ScanBytesFunc(c, &ScanFileOptions{Reject: []string{"Malicious"}},
		func(res *ScanResult) error {
			seen = res
			return nil
		})

	if err := process(context.Background(), "app.jar", []byte("PK\x03\x04")); err != nil {
		t.Fatalf("process: %v", err)
	}
	if seen == nil {
		t.Fatal("handler was not called for an accepted file")
	}
	if seen.SafetyScore.ThreatLevel != "Informational" {
		t.Fatalf("handler got threatLevel %q, want Informational", seen.SafetyScore.ThreatLevel)
	}
}

func TestScanBytesFuncRejectsBeforeHandler(t *testing.T) {
	c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(maliciousScanJSON))
	})
	defer srv.Close()

	called := false
	process := ScanBytesFunc(c, &ScanFileOptions{Reject: []string{"Malicious"}},
		func(res *ScanResult) error {
			called = true
			return nil
		})

	err := process(context.Background(), "sample.exe", []byte("payload"))
	var mfe *MaliciousFileError
	if !errors.As(err, &mfe) {
		t.Fatalf("expected *MaliciousFileError, got %v", err)
	}
	if called {
		t.Fatal("handler ran for a rejected file")
	}
}

func TestScanBytesFuncRejectsOnRecommendedAction(t *testing.T) {
	// maliciousScanJSON is threatLevel "Malicious" AND recommendedAction "Block".
	c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(maliciousScanJSON))
	})
	defer srv.Close()

	called := false
	process := ScanBytesFunc(c, &ScanFileOptions{Reject: []string{"Block"}},
		func(res *ScanResult) error {
			called = true
			return nil
		})

	err := process(context.Background(), "sample.exe", []byte("payload"))
	var mfe *MaliciousFileError
	if !errors.As(err, &mfe) {
		t.Fatalf("expected *MaliciousFileError for Reject [Block], got %v", err)
	}
	if called {
		t.Fatal("handler ran for a file rejected on recommended action")
	}
}

func TestMiddlewareShouldRejectOnRecommendedAction(t *testing.T) {
	opts := &MiddlewareOptions{Reject: []string{"block"}} // action, lowercase
	if !opts.shouldReject(SafetyScore{ThreatLevel: "Malicious", RecommendedAction: "Block"}) {
		t.Fatal("expected reject when the recommended action is Block")
	}
	if opts.shouldReject(SafetyScore{ThreatLevel: "Clean", RecommendedAction: "Allow"}) {
		t.Fatal("did not expect reject for Clean/Allow")
	}
}
