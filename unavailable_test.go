package surface

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const okPayloadJSON = `{"name":"p","size":1,"hash":"h","contentType":"text/plain",
	"safetyScore":{"score":100,"threatLevel":"Clean","recommendedAction":"Allow"},
	"scanTimeMs":1,"timestamp":0}`

// unavailableClient is a test client with a short budget and millisecond
// backoff. Each request increments *hits before handler runs.
func unavailableClient(t *testing.T, timeout time.Duration, handler func(n int32, w http.ResponseWriter, r *http.Request)) (*Client, *int32) {
	t.Helper()
	var hits int32
	c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		handler(atomic.AddInt32(&hits, 1), w, r)
	})
	t.Cleanup(srv.Close)
	c.Timeout = timeout
	c.retryBase = 5 * time.Millisecond
	return c, &hits
}

func scanPayload(c *Client, ctx context.Context) error {
	_, err := c.ScanPayload(ctx, []byte("hello"), "", nil)
	return err
}

func TestNewClientDefaultTimeout(t *testing.T) {
	c, err := NewClient("sfk_test")
	if err != nil {
		t.Fatal(err)
	}
	if c.Timeout != 60*time.Second || c.timeout() != DefaultTimeout {
		t.Errorf("Timeout = %v, want 60s", c.Timeout)
	}
	if (&Client{}).timeout() != DefaultTimeout {
		t.Errorf("zero Timeout should mean DefaultTimeout")
	}
}

func TestUnavailableConnectionRefused(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	c, _ := NewClient("sfk_test")
	c.BaseURL = "http://" + addr
	c.Timeout = 300 * time.Millisecond
	c.retryBase = 5 * time.Millisecond
	start := time.Now()
	err = scanPayload(c, context.Background())
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	var ue *UnavailableError
	if !errors.As(err, &ue) || ue.StatusCode != 0 {
		t.Errorf("want *UnavailableError with no status, got %#v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("took %v, budget was 300ms", time.Since(start))
	}
}

func TestUnavailable500NotRetried(t *testing.T) {
	c, hits := unavailableClient(t, 2*time.Second, func(_ int32, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte(`{"error":"scanner exploded","requestId":"r1"}`))
	})
	err := scanPayload(c, context.Background())
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	var se *SurfaceError
	if !errors.As(err, &se) || se.StatusCode != 500 || se.Message != "scanner exploded" || se.RequestID != "r1" {
		t.Errorf("errors.As SurfaceError = %+v", se)
	}
	if !strings.Contains(err.Error(), "scanner exploded") {
		t.Errorf("message missing server error text: %v", err)
	}
	if atomic.LoadInt32(hits) != 1 {
		t.Errorf("500 retried: %d attempts", atomic.LoadInt32(hits))
	}
}

func TestUnavailableRetries502And503ThenSucceeds(t *testing.T) {
	c, hits := unavailableClient(t, 5*time.Second, func(n int32, w http.ResponseWriter, _ *http.Request) {
		switch n {
		case 1:
			w.WriteHeader(502)
		case 2:
			w.WriteHeader(503)
			w.Write([]byte(`{"error":"warming up"}`))
		default:
			w.Write([]byte(okPayloadJSON))
		}
	})
	res, err := c.ScanPayload(context.Background(), []byte("hello"), "", nil)
	if err != nil {
		t.Fatalf("want success after retries, got %v", err)
	}
	if res.ScanResult.SafetyScore.ThreatLevel != "Clean" {
		t.Errorf("result = %+v", res.ScanResult.SafetyScore)
	}
	if atomic.LoadInt32(hits) != 3 {
		t.Errorf("attempts = %d, want 3", atomic.LoadInt32(hits))
	}
}

// Multipart uploads are rebuilt per attempt, so the retried body is intact.
func TestUnavailableRetryReplaysMultipartBody(t *testing.T) {
	c, hits := unavailableClient(t, 5*time.Second, func(n int32, w http.ResponseWriter, r *http.Request) {
		mr, err := r.MultipartReader()
		if err != nil {
			t.Errorf("attempt %d: %v", n, err)
			return
		}
		part, err := mr.NextPart()
		if err != nil {
			t.Errorf("attempt %d: %v", n, err)
			return
		}
		b, _ := io.ReadAll(part)
		if string(b) != "file-content" {
			t.Errorf("attempt %d body = %q", n, b)
		}
		if n == 1 {
			w.WriteHeader(503)
			return
		}
		w.Write([]byte(okPayloadJSON))
	})
	if _, err := c.ScanBytes(context.Background(), "f.txt", []byte("file-content"), nil); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(hits) != 2 {
		t.Errorf("attempts = %d, want 2", atomic.LoadInt32(hits))
	}
}

func TestUnavailable503ForeverWithinBudget(t *testing.T) {
	c, hits := unavailableClient(t, 300*time.Millisecond, func(_ int32, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(503)
	})
	start := time.Now()
	err := scanPayload(c, context.Background())
	elapsed := time.Since(start)
	var ue *UnavailableError
	if !errors.As(err, &ue) || ue.StatusCode != 503 {
		t.Fatalf("err = %v, want *UnavailableError 503", err)
	}
	if elapsed > 300*time.Millisecond+200*time.Millisecond {
		t.Errorf("took %v, budget was 300ms", elapsed)
	}
	if atomic.LoadInt32(hits) < 2 {
		t.Errorf("attempts = %d, want retries", atomic.LoadInt32(hits))
	}
}

func TestUnavailableMaxRetries(t *testing.T) {
	c, hits := unavailableClient(t, 10*time.Second, func(_ int32, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(504)
	})
	c.retryBase = time.Millisecond
	if err := scanPayload(c, context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if atomic.LoadInt32(hits) != maxRetries+1 {
		t.Errorf("attempts = %d, want %d", atomic.LoadInt32(hits), maxRetries+1)
	}
}

func TestUnavailableHonorsRetryAfter(t *testing.T) {
	var first time.Time
	var gap time.Duration
	c, _ := unavailableClient(t, 5*time.Second, func(n int32, w http.ResponseWriter, _ *http.Request) {
		if n == 1 {
			first = time.Now()
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(503)
			return
		}
		gap = time.Since(first)
		w.Write([]byte(okPayloadJSON))
	})
	if err := scanPayload(c, context.Background()); err != nil {
		t.Fatal(err)
	}
	// Backoff alone would wait 5ms; Retry-After asked for a second.
	if gap < 900*time.Millisecond {
		t.Errorf("retried after %v, want >= 1s", gap)
	}
}

// A Retry-After that would end past the budget is not waited out.
func TestUnavailableRetryAfterPastBudgetGivesUp(t *testing.T) {
	c, hits := unavailableClient(t, time.Second, func(_ int32, w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(503)
	})
	start := time.Now()
	if err := scanPayload(c, context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 300*time.Millisecond || atomic.LoadInt32(hits) != 1 {
		t.Errorf("waited %v over %d attempts; should give up at once", time.Since(start), atomic.LoadInt32(hits))
	}
}

// hangHandler never answers. It drains the body first so the server notices
// the client hanging up and the test server can close promptly.
func hangHandler(_ int32, _ http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	select {
	case <-r.Context().Done():
	case <-time.After(10 * time.Second):
	}
}

func TestUnavailableHangTimesOut(t *testing.T) {
	c, hits := unavailableClient(t, 200*time.Millisecond, hangHandler)
	start := time.Now()
	err := scanPayload(c, context.Background())
	if !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want ErrUnavailable wrapping DeadlineExceeded", err)
	}
	if e := time.Since(start); e < 150*time.Millisecond || e > time.Second {
		t.Errorf("took %v, want ~200ms", e)
	}
	if atomic.LoadInt32(hits) != 1 {
		t.Errorf("hung request retried: %d attempts", atomic.LoadInt32(hits))
	}
}

func TestUnavailableCallerDeadlineWins(t *testing.T) {
	c, _ := unavailableClient(t, 10*time.Second, hangHandler)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := scanPayload(c, ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if e := time.Since(start); e > time.Second {
		t.Errorf("took %v; caller's 150ms deadline should win", e)
	}
}

func TestUnavailableCallerCancelIsNotUnavailable(t *testing.T) {
	c, _ := unavailableClient(t, 10*time.Second, hangHandler)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	err := scanPayload(c, ctx)
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want context.Canceled, not ErrUnavailable", err)
	}
}

func TestUnavailableHTMLBody(t *testing.T) {
	c, _ := unavailableClient(t, 2*time.Second, func(_ int32, w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>Bad gateway</body></html>"))
	})
	if err := scanPayload(c, context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Errorf("ScanPayload err = %v, want ErrUnavailable", err)
	}
	if _, err := c.GetUsage(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Errorf("GetUsage err = %v, want ErrUnavailable", err)
	}
}

func TestUnavailable429Unchanged(t *testing.T) {
	c, hits := unavailableClient(t, 2*time.Second, func(_ int32, w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(429)
		w.Write([]byte(`{"error":"rate limit exceeded"}`))
	})
	err := scanPayload(c, context.Background())
	var rl *RateLimitError
	if !errors.As(err, &rl) || errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %#v, want *RateLimitError", err)
	}
	if atomic.LoadInt32(hits) != 1 {
		t.Errorf("429 retried: %d attempts", atomic.LoadInt32(hits))
	}
}

func TestUnavailable4xxUnchanged(t *testing.T) {
	c, _ := unavailableClient(t, 2*time.Second, func(_ int32, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
	})
	_, err := c.GetScan(context.Background(), "x")
	var nf *NotFoundError
	if !errors.As(err, &nf) || errors.Is(err, ErrUnavailable) || nf.Message != "404 Not Found" {
		t.Fatalf("err = %#v, want *NotFoundError", err)
	}
}

type countingTransport struct{ n int32 }

func (t *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	atomic.AddInt32(&t.n, 1)
	return http.DefaultTransport.RoundTrip(r)
}

func TestUnavailableCustomHTTPClient(t *testing.T) {
	c, _ := unavailableClient(t, 5*time.Second, func(n int32, w http.ResponseWriter, _ *http.Request) {
		if n == 1 {
			w.WriteHeader(503)
			return
		}
		w.Write([]byte(okPayloadJSON))
	})
	tr := &countingTransport{}
	c.HTTP = &http.Client{Transport: tr}
	if err := scanPayload(c, context.Background()); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&tr.n) != 2 {
		t.Errorf("custom client saw %d requests, want 2", atomic.LoadInt32(&tr.n))
	}
}

// ToolGuard fails closed: an unavailable scanner never lets the tool run.
func TestToolGuardUnavailableDoesNotRunTool(t *testing.T) {
	c, _ := unavailableClient(t, 200*time.Millisecond, func(_ int32, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(503)
	})
	ran := false
	tool := Wrap(NewToolGuard(c), "send_email", func(ctx context.Context, to string) (string, error) {
		ran = true
		return "sent", nil
	})
	_, err := tool(context.Background(), "a@b.c")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	if ran {
		t.Error("tool ran while Surface was unavailable")
	}
}

func TestMiddlewareUnavailableFollowsFailOpen(t *testing.T) {
	c, _ := unavailableClient(t, 200*time.Millisecond, func(_ int32, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(503)
	})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	closed := false
	for _, tc := range []struct {
		opts *MiddlewareOptions
		want int
	}{
		{nil, 200},
		{&MiddlewareOptions{FailOpen: &closed}, 503},
	} {
		var seen error
		opts := tc.opts
		if opts == nil {
			opts = &MiddlewareOptions{}
		}
		opts.OnError = func(_ *http.Request, err error) { seen = err }
		rec := httptest.NewRecorder()
		ScanMiddleware(c, next, opts).ServeHTTP(rec, httptest.NewRequest("POST", "/", strings.NewReader("body")))
		if rec.Code != tc.want {
			t.Errorf("status = %d, want %d", rec.Code, tc.want)
		}
		if !errors.Is(seen, ErrUnavailable) {
			t.Errorf("OnError got %v, want ErrUnavailable", seen)
		}
	}
}

func TestLocalModeUnavailable(t *testing.T) {
	var hits int32
	c, srv := newTestLocalClient(t, func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			w.WriteHeader(503)
			return
		}
		if r.URL.Path == "/scan" {
			hangHandler(0, w, r)
			return
		}
		w.Write([]byte(okPayloadJSON))
	})
	defer srv.Close()
	c.Timeout = 300 * time.Millisecond
	c.retryBase = 5 * time.Millisecond

	if _, err := c.ScanPayload(context.Background(), []byte("x"), "", nil); err != nil {
		t.Fatalf("payload after 503 retry: %v", err)
	}
	if _, err := c.ScanBytes(context.Background(), "f", []byte("x"), nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("hung local scan err = %v, want ErrUnavailable", err)
	}
}
