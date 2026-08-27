package surface

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// maliciousScanJSON is a scan response whose threatLevel is capitalized, exactly
// as the backend emits it.
const maliciousScanJSON = `{
	"name": "sample.exe",
	"size": 10,
	"hash": "abc123",
	"contentType": "application/octet-stream",
	"safetyScore": {
		"score": 5,
		"threatLevel": "Malicious",
		"confidence": "High",
		"confidenceScore": 0.95,
		"confidenceReason": "",
		"primaryThreat": "trojan",
		"threatSummary": "",
		"enginesUsed": [],
		"recommendedAction": "Block",
		"coverage": "full"
	},
	"scanTimeMs": 1,
	"timestamp": 0
}`

// minimalCoverageScanJSON is a JAR every engine cleared. The backend caps it at
// Informational because no ML model covers JVM bytecode.
const minimalCoverageScanJSON = `{
	"name": "app.jar",
	"size": 4096,
	"hash": "def456",
	"contentType": "application/java-archive",
	"safetyScore": {
		"score": 85,
		"threatLevel": "Informational",
		"confidence": "Medium",
		"confidenceScore": 0.6,
		"confidenceReason": "",
		"primaryThreat": "No threats detected",
		"threatSummary": "",
		"enginesUsed": ["YARA"],
		"recommendedAction": "Allow",
		"coverage": "minimal",
		"coverageNote": "Archive of JVM or Android bytecode."
	},
	"scanTimeMs": 1,
	"timestamp": 0
}`

func newTestClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	c, err := NewClient("sfk_test")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.BaseURL = srv.URL
	return c, srv
}

func TestDefaultBaseURL(t *testing.T) {
	c, err := NewClient("sfk_test")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.BaseURL != "https://app.tendrl.com/surface/api" {
		t.Fatalf("default BaseURL = %q, want https://app.tendrl.com/surface/api", c.BaseURL)
	}
}

func TestGetUsageParsesBackendFields(t *testing.T) {
	usage := `{
		"scans_used": 5,
		"max_scans": 100,
		"scans_remaining": 95,
		"max_file_size_mb": 10,
		"plan_tier": "free",
		"reset_at": "2026-07-01",
		"daily_volume": {"dates": ["2026-06-15"], "counts": [5]}
	}`
	c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/account/usage" {
			t.Errorf("usage path = %q, want /account/usage", r.URL.Path)
		}
		w.Write([]byte(usage))
	})
	defer srv.Close()

	u, err := c.GetUsage(context.Background())
	if err != nil {
		t.Fatalf("GetUsage: %v", err)
	}
	if u.ScansUsed != 5 || u.MaxScans != 100 || u.ScansRemaining != 95 {
		t.Errorf("usage = %+v, want scans_used=5 max_scans=100 scans_remaining=95", u)
	}
	if u.MaxFileSizeMB != 10 || u.PlanTier != "free" {
		t.Errorf("usage = %+v, want max_file_size_mb=10 plan_tier=free", u)
	}
	if u.DailyVolume == nil || len(u.DailyVolume.Counts) != 1 || u.DailyVolume.Counts[0] != 5 {
		t.Errorf("daily volume = %+v, want counts=[5]", u.DailyVolume)
	}
}

func TestGetScanHistoryUsesHistoryPath(t *testing.T) {
	var gotPath string
	c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Write([]byte(`{"scans":[],"total":0,"page":1,"limit":25,"has_more":false}`))
	})
	defer srv.Close()

	if _, err := c.GetScanHistory(context.Background(), 1, 25); err != nil {
		t.Fatalf("GetScanHistory: %v", err)
	}
	if gotPath != "/account/history" {
		t.Errorf("history path = %q, want /account/history", gotPath)
	}
}

func TestRejectMatchesCaseInsensitively(t *testing.T) {
	c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(maliciousScanJSON))
	})
	defer srv.Close()

	// lowercase "malicious" must match the server's capitalized "Malicious".
	_, err := c.ScanBytes(context.Background(), "sample.exe", []byte("payload"),
		&ScanFileOptions{Reject: []string{"malicious"}})
	var mfe *MaliciousFileError
	if !errors.As(err, &mfe) {
		t.Fatalf("expected *MaliciousFileError, got %v", err)
	}
}

func TestRejectDoesNotFalselyMatch(t *testing.T) {
	c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(maliciousScanJSON))
	})
	defer srv.Close()

	// Rejecting only "clean" must NOT raise for a Malicious file.
	res, err := c.ScanBytes(context.Background(), "sample.exe", []byte("payload"),
		&ScanFileOptions{Reject: []string{"clean"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ScanResult == nil || res.ScanResult.SafetyScore.ThreatLevel != "Malicious" {
		t.Fatalf("expected accepted Malicious result, got %+v", res)
	}
}

func TestRequestIDSentAsHeaderNotQuery(t *testing.T) {
	var gotHeader, gotQuery string
	c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Request-ID")
		gotQuery = r.URL.RawQuery
		w.Write([]byte(maliciousScanJSON))
	})
	defer srv.Close()

	_, _ = c.ScanBytes(context.Background(), "sample.exe", []byte("payload"),
		&ScanFileOptions{RequestID: "req-abc-123"})
	if gotHeader != "req-abc-123" {
		t.Errorf("X-Request-ID header = %q, want req-abc-123", gotHeader)
	}
	if gotQuery != "" {
		t.Errorf("expected no query params, got %q", gotQuery)
	}
}

// sanity check that the response JSON used above is valid.
func TestMaliciousScanJSONValid(t *testing.T) {
	var r ScanResult
	if err := json.Unmarshal([]byte(maliciousScanJSON), &r); err != nil {
		t.Fatalf("invalid test fixture: %v", err)
	}
}

// Coverage tells a caller how much the verdict is worth for this file's format.
// It has to survive deserialisation or the distinction is invisible to them.
func TestCoverageFieldsSurviveDeserialisation(t *testing.T) {
	c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(minimalCoverageScanJSON))
	})
	defer srv.Close()

	res, err := c.ScanBytes(context.Background(), "app.jar", []byte("PK\x03\x04"), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ScanResult == nil {
		t.Fatal("no scan result")
	}
	ss := res.ScanResult.SafetyScore
	if ss.Coverage != "minimal" {
		t.Errorf("Coverage = %q, want minimal", ss.Coverage)
	}
	if ss.CoverageNote == "" {
		t.Error("CoverageNote is empty — the shortfall was dropped")
	}
	// A minimal scan must never claim Clean.
	if ss.ThreatLevel == "Clean" {
		t.Errorf("ThreatLevel = Clean on a minimal-coverage scan")
	}
}

// An older deployment omits the field entirely; decoding must not break.
func TestScanResponseWithoutCoverageStillDecodes(t *testing.T) {
	const legacy = `{
		"name": "sample.txt",
		"size": 10,
		"hash": "abc123",
		"contentType": "text/plain",
		"safetyScore": {
			"score": 100,
			"threatLevel": "Clean",
			"confidence": "High",
			"confidenceScore": 0.9,
			"confidenceReason": "",
			"primaryThreat": "No threats detected",
			"threatSummary": "",
			"enginesUsed": [],
			"recommendedAction": "Allow"
		},
		"scanTimeMs": 1,
		"timestamp": 0
	}`
	c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(legacy))
	})
	defer srv.Close()

	res, err := c.ScanBytes(context.Background(), "sample.txt", []byte("hello"), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ScanResult == nil {
		t.Fatal("no scan result")
	}
	if got := res.ScanResult.SafetyScore.Coverage; got != "" {
		t.Errorf("Coverage = %q, want empty", got)
	}
}

// Guard against a silent rename: a SafetyScore marshals back to the wire names
// the API documents.
func TestSafetyScoreCoverageJSONNames(t *testing.T) {
	b, err := json.Marshal(SafetyScore{Coverage: "minimal", CoverageNote: "no ML model"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if m["coverage"] != "minimal" {
		t.Errorf(`json key "coverage" = %v, want "minimal"`, m["coverage"])
	}
	if m["coverageNote"] != "no ML model" {
		t.Errorf(`json key "coverageNote" = %v, want "no ML model"`, m["coverageNote"])
	}
}
