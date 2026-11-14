package surface

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// HTTP status → error type, matched to the Surface backend's real bodies:
// quota exhaustion is 402 (not 429); ?defer=true on a plan without async
// scanning is also 402 but is a plan wall; 429 is always a rate limit; 403 is
// never an authentication error.

func errClient(t *testing.T, status int, body string) *Client {
	t.Helper()
	c, srv := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write([]byte(body))
	})
	t.Cleanup(srv.Close)
	return c
}

const (
	quota402 = `{"error":"monthly scan quota exceeded (100/100 scans used)","requestId":"r1"}`
	defer402 = `{"error":"async scanning is not included on the free plan","feature":"async scanning","current_plan":"free","upgrade":true,"requestId":"r2"}`
	plan403  = `{"error":"the free plan includes 1 scan profile(s); this account has 1","feature":"scan profiles","current_plan":"free","code":"plan_required","limit":1,"upgrade":true}`
)

func TestError402QuotaIsQuotaExceeded(t *testing.T) {
	for _, body := range []string{quota402, `{"error":"this plan's 500 local scans for the month are used up"}`} {
		err := scanPayload(errClient(t, 402, body), context.Background())
		var q *QuotaExceededError
		if !errors.As(err, &q) {
			t.Fatalf("body %s: err = %#v, want *QuotaExceededError", body, err)
		}
		if q.StatusCode != 402 || !strings.Contains(q.Message, "used") {
			t.Errorf("got %+v", q.SurfaceError)
		}
		var pd *PermissionDeniedError
		if errors.As(err, &pd) {
			t.Errorf("quota must not be a PermissionDeniedError")
		}
	}
	err := scanPayload(errClient(t, 402, quota402), context.Background())
	var q *QuotaExceededError
	errors.As(err, &q)
	if q.RequestID != "r1" {
		t.Errorf("RequestID = %q", q.RequestID)
	}
}

func TestError402DeferWithoutAsyncIsPlanRequired(t *testing.T) {
	c := errClient(t, 402, defer402)
	_, err := c.ScanBytes(context.Background(), "x.txt", []byte("x"), &ScanFileOptions{Defer: true})
	var pr *PlanRequiredError
	if !errors.As(err, &pr) {
		t.Fatalf("err = %#v, want *PlanRequiredError", err)
	}
	var q *QuotaExceededError
	if errors.As(err, &q) {
		t.Fatal("defer plan wall must not be QuotaExceededError")
	}
	if pr.StatusCode != 402 || pr.Feature != "async scanning" || pr.CurrentPlan != "free" || pr.Code != "" {
		t.Errorf("got %+v", pr)
	}
}

func TestError402OtherIsGeneric(t *testing.T) {
	err := scanPayload(errClient(t, 402, `{"error":"could not verify this API key with the server"}`), context.Background())
	var se *SurfaceError
	if !errors.As(err, &se) || se.StatusCode != 402 {
		t.Fatalf("err = %#v, want *SurfaceError 402", err)
	}
}

func TestError403PlanRequired(t *testing.T) {
	_, err := errClient(t, 403, plan403).GetUsage(context.Background())
	var pr *PlanRequiredError
	if !errors.As(err, &pr) {
		t.Fatalf("err = %#v, want *PlanRequiredError", err)
	}
	if pr.StatusCode != 403 || pr.Code != "plan_required" || pr.Feature != "scan profiles" || pr.CurrentPlan != "free" {
		t.Errorf("got %+v", pr)
	}
	var pd *PermissionDeniedError
	if !errors.As(err, &pd) || pd.Code != "plan_required" {
		t.Errorf("PlanRequiredError should match *PermissionDeniedError via errors.As")
	}
	var ae *AuthenticationError
	if errors.As(err, &ae) {
		t.Errorf("403 must not be AuthenticationError")
	}
}

func TestError403IsPermissionDeniedNotAuth(t *testing.T) {
	for _, msg := range []string{
		"IP address is blocked",
		"permission denied: scans:write required",
		"Payload scanning is not enabled for this scan profile. Update the profile or use an API key linked to a profile with payload scanning enabled.",
	} {
		err := scanPayload(errClient(t, 403, `{"error":"`+msg+`"}`), context.Background())
		var pd *PermissionDeniedError
		if !errors.As(err, &pd) {
			t.Fatalf("%q: err = %#v, want *PermissionDeniedError", msg, err)
		}
		if pd.Message != msg || pd.StatusCode != 403 || pd.Code != "" {
			t.Errorf("got %+v", pd.SurfaceError)
		}
		var ae *AuthenticationError
		var pr *PlanRequiredError
		if errors.As(err, &ae) || errors.As(err, &pr) {
			t.Errorf("%q: wrong type %T", msg, err)
		}
	}
}

func TestError401StaysAuthentication(t *testing.T) {
	err := scanPayload(errClient(t, 401, `{"error":"invalid API key"}`), context.Background())
	var ae *AuthenticationError
	if !errors.As(err, &ae) || ae.StatusCode != 401 {
		t.Fatalf("err = %#v, want *AuthenticationError", err)
	}
}

func TestError429IsAlwaysRateLimit(t *testing.T) {
	for _, body := range []string{
		`{"error":"rate limit exceeded","plan":"free","limit_per_minute":10}`,
		`{"error":"rate limit exceeded","retry_after":"60"}`,
		`{"error":"monthly scan quota exceeded (1/1 scans used)"}`, // still a 429 → rate limit
	} {
		err := scanPayload(errClient(t, 429, body), context.Background())
		var rl *RateLimitError
		var q *QuotaExceededError
		if !errors.As(err, &rl) || errors.As(err, &q) {
			t.Fatalf("body %s: err = %#v, want *RateLimitError", body, err)
		}
	}
}

func TestScanPayloadDoesNotSendDefer(t *testing.T) {
	var query string
	c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		w.Write([]byte(okPayloadJSON))
	})
	defer srv.Close()
	res, err := c.ScanPayload(context.Background(), []byte("hi"), "", &ScanFileOptions{Defer: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(query, "defer") {
		t.Errorf("query = %q, defer should not be sent", query)
	}
	if res.ScanResult == nil || res.Deferred != nil {
		t.Errorf("payload scans are synchronous: %+v", res)
	}
}
