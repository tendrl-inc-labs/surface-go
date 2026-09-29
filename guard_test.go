package surface

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// verdictGuard returns a guard whose server always answers with the given
// recommendedAction (and optional actionScreen), capturing the last request body.
func verdictGuard(t *testing.T, action, primary string, actionScreen map[string]any, seen *map[string]any) *ToolGuard {
	c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if seen != nil {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, seen)
		}
		resp := map[string]any{
			"name": "t.toolcall.json", "size": 1, "hash": "sha256:x",
			"contentType": "application/json",
			"safetyScore": map[string]any{
				"score": 25, "threatLevel": "Malicious", "confidence": "High",
				"confidenceScore": 0.9, "confidenceReason": "x",
				"primaryThreat": primary, "threatSummary": primary,
				"enginesUsed": []string{"Action Screening"}, "recommendedAction": action,
			},
			"scanTimeMs": 1, "timestamp": 0,
		}
		if actionScreen != nil {
			resp["actionScreen"] = actionScreen
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	t.Cleanup(srv.Close)
	return NewToolGuard(c)
}

func TestToolGuard_Screen(t *testing.T) {
	for _, action := range []string{"Allow", "Review", "Block"} {
		g := verdictGuard(t, action, "reason", nil, nil)
		d, err := g.Screen(context.Background(), "t", map[string]any{"a": 1})
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		if d.Action != action {
			t.Errorf("action = %q, want %q", d.Action, action)
		}
		if d.Allowed() != (action == "Allow") || d.Blocked() != (action == "Block") || d.NeedsReview() != (action == "Review") {
			t.Errorf("%s: predicate mismatch", action)
		}
	}
}

func TestToolGuard_ContextForwarded(t *testing.T) {
	var seen map[string]any
	g := verdictGuard(t, "Allow", "", nil, &seen)
	g.ContextFunc = func(name string, args any) *ActionContext {
		return &ActionContext{PrincipalDomains: []string{"acme.io"}, AllowedEgress: []string{"api.stripe.com"}}
	}
	if _, err := g.Screen(context.Background(), "http_request", map[string]any{"url": "x"}); err != nil {
		t.Fatal(err)
	}
	ctx, ok := seen["context"].(map[string]any)
	if !ok {
		t.Fatalf("no context in body: %v", seen)
	}
	if pd, _ := ctx["principal_domains"].([]any); len(pd) != 1 || pd[0] != "acme.io" {
		t.Errorf("principal_domains not forwarded: %v", ctx["principal_domains"])
	}
	if payload, _ := seen["payload"].(string); !strings.Contains(payload, `"tool":"http_request"`) {
		t.Errorf("payload not the tool call: %q", seen["payload"])
	}
}

func TestToolGuard_Check(t *testing.T) {
	if err := verdictGuard(t, "Allow", "", nil, nil).Check(context.Background(), "t", nil); err != nil {
		t.Errorf("Allow should pass Check: %v", err)
	}
	var be *BlockedError
	err := verdictGuard(t, "Block", "Sends data to a bare-IP address", nil, nil).Check(context.Background(), "t", nil)
	if !errors.As(err, &be) {
		t.Fatalf("Block should return *BlockedError, got %v", err)
	}
	if !be.Decision.Blocked() {
		t.Error("decision should be Blocked")
	}
	// Review is held by default: a person should confirm it.
	err = verdictGuard(t, "Review", "", nil, nil).Check(context.Background(), "t", nil)
	var nr *NeedsReviewError
	if !errors.As(err, &nr) || !errors.As(err, &be) {
		t.Errorf("Review should be held with *NeedsReviewError (also a *BlockedError), got %v", err)
	}
}

func TestToolGuard_WrapAndFindings(t *testing.T) {
	as := map[string]any{"detected": true, "toolCalls": 1, "findings": []map[string]any{
		{"toolName": "transfer", "category": "egress", "reason": "Sends data to a bare-IP address", "evidence": "..."},
	}}
	ran := false
	transfer := func(ctx context.Context, args map[string]any) (string, error) { ran = true; return "done", nil }

	// Allow -> runs.
	safe := Wrap(verdictGuard(t, "Allow", "", nil, nil), "transfer", transfer)
	if out, err := safe(context.Background(), map[string]any{"amount": 10}); err != nil || out != "done" || !ran {
		t.Fatalf("Allow: out=%q err=%v ran=%v", out, err, ran)
	}
	// Block -> BlockedError, tool not run, findings present.
	ran = false
	blocked := Wrap(verdictGuard(t, "Block", "Sends data to a bare-IP address", as, nil), "transfer", transfer)
	_, err := blocked(context.Background(), map[string]any{"amount": 10})
	var be *BlockedError
	if !errors.As(err, &be) {
		t.Fatalf("Block should return *BlockedError, got %v", err)
	}
	if ran {
		t.Error("tool ran despite Block")
	}
	if len(be.Decision.Findings) != 1 || be.Decision.Findings[0].ToolName != "transfer" {
		t.Errorf("findings not parsed: %+v", be.Decision.Findings)
	}
}

// wrapRun runs a wrapped no-op tool against a guard and reports whether the
// tool body executed and what error came back.
func wrapRun(t *testing.T, g *ToolGuard) (bool, error) {
	t.Helper()
	ran := false
	tool := Wrap(g, "send_email", func(ctx context.Context, args map[string]any) (string, error) {
		ran = true
		return "ok", nil
	})
	_, err := tool(context.Background(), map[string]any{"to": "x@gmail.com"})
	return ran, err
}

func TestToolGuard_ReviewHeldByDefault(t *testing.T) {
	ran, err := wrapRun(t, verdictGuard(t, "Review", "Document to an outside recipient", nil, nil))
	if ran {
		t.Fatal("tool ran on Review with the default policy")
	}
	var nr *NeedsReviewError
	var be *BlockedError
	if !errors.As(err, &nr) {
		t.Fatalf("want *NeedsReviewError, got %v", err)
	}
	if !errors.As(err, &be) || !be.Decision.NeedsReview() {
		t.Errorf("*NeedsReviewError should also match *BlockedError carrying the Review decision, got %v", err)
	}
	if !errors.Is(err, ErrNeedsReview) || !errors.Is(err, ErrBlocked) {
		t.Errorf("errors.Is should match ErrNeedsReview and ErrBlocked: %v", err)
	}
	if nr.Decision.Reason != "Document to an outside recipient" {
		t.Errorf("decision reason lost: %+v", nr.Decision)
	}
}

func TestToolGuard_ReviewAllow(t *testing.T) {
	g := verdictGuard(t, "Review", "", nil, nil)
	g.OnReview = ReviewAllow
	if ran, err := wrapRun(t, g); !ran || err != nil {
		t.Errorf("ReviewAllow should run the tool: ran=%v err=%v", ran, err)
	}
	g = verdictGuard(t, "Review", "", nil, nil)
	g.OnReview = ReviewHold
	if ran, err := wrapRun(t, g); ran || !errors.Is(err, ErrNeedsReview) {
		t.Errorf("ReviewHold should hold: ran=%v err=%v", ran, err)
	}
}

func TestToolGuard_ReviewCallback(t *testing.T) {
	var asked Decision
	g := verdictGuard(t, "Review", "needs a person", nil, nil)
	g.OnReview = ReviewFunc(func(d Decision) bool { asked = d; return true })
	if ran, err := wrapRun(t, g); !ran || err != nil {
		t.Errorf("callback true should run the tool: ran=%v err=%v", ran, err)
	}
	if asked.Action != "Review" || asked.Reason != "needs a person" {
		t.Errorf("callback did not get the Decision: %+v", asked)
	}

	g = verdictGuard(t, "Review", "", nil, nil)
	g.OnReview = ReviewFunc(func(Decision) bool { return false })
	if ran, err := wrapRun(t, g); ran || !errors.Is(err, ErrNeedsReview) {
		t.Errorf("callback false should hold: ran=%v err=%v", ran, err)
	}

	// Context-aware policy sees the caller's context.
	type key struct{}
	g = verdictGuard(t, "Review", "", nil, nil)
	g.OnReview = func(ctx context.Context, d Decision) bool { return ctx.Value(key{}) == "approved" }
	ran := false
	tool := Wrap(g, "t", func(context.Context, int) (int, error) { ran = true; return 0, nil })
	if _, err := tool(context.WithValue(context.Background(), key{}, "approved"), 1); !ran || err != nil {
		t.Errorf("context-aware policy should run the tool: ran=%v err=%v", ran, err)
	}
}

func TestToolGuard_BlockOnReviewLegacy(t *testing.T) {
	// true holds, and overrides an allowing OnReview.
	g := verdictGuard(t, "Review", "", nil, nil)
	g.BlockOnReview = true
	g.OnReview = ReviewAllow
	if ran, err := wrapRun(t, g); ran || !errors.Is(err, ErrNeedsReview) {
		t.Errorf("BlockOnReview=true should hold: ran=%v err=%v", ran, err)
	}
	var be *BlockedError
	if err := g.Check(context.Background(), "t", nil); !errors.As(err, &be) {
		t.Errorf("BlockOnReview=true should still return a *BlockedError: %v", err)
	}
	// false defers to OnReview (it cannot mean "allow" on its own, since it is
	// the zero value): allowed with ReviewAllow, held with the default.
	g = verdictGuard(t, "Review", "", nil, nil)
	g.BlockOnReview = false
	g.OnReview = ReviewAllow
	if ran, err := wrapRun(t, g); !ran || err != nil {
		t.Errorf("BlockOnReview=false + ReviewAllow should run: ran=%v err=%v", ran, err)
	}
	g = verdictGuard(t, "Review", "", nil, nil)
	g.BlockOnReview = false
	if ran, err := wrapRun(t, g); ran || !errors.Is(err, ErrNeedsReview) {
		t.Errorf("BlockOnReview=false with no OnReview should hold: ran=%v err=%v", ran, err)
	}
}

func TestToolGuard_BlockNeverRuns(t *testing.T) {
	for name, policy := range map[string]ReviewPolicy{
		"allow":    ReviewAllow,
		"callback": ReviewFunc(func(Decision) bool { return true }),
	} {
		g := verdictGuard(t, "Block", "Sends data to a bare-IP address", nil, nil)
		g.OnReview = policy
		ran, err := wrapRun(t, g)
		if ran {
			t.Errorf("%s: Block ran the tool", name)
		}
		var be *BlockedError
		if !errors.As(err, &be) || !be.Decision.Blocked() {
			t.Errorf("%s: want *BlockedError for Block, got %v", name, err)
		}
		if errors.Is(err, ErrNeedsReview) {
			t.Errorf("%s: Block should not be a *NeedsReviewError", name)
		}
	}
}

func TestToolGuard_InvalidStrictnessRejected(t *testing.T) {
	calls := 0
	c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { calls++ })
	defer srv.Close()
	g := NewToolGuard(c)
	g.Strictness = "stirct"
	if _, err := g.Screen(context.Background(), "t", nil); err == nil {
		t.Error("invalid guard strictness should be rejected")
	}
	g = NewToolGuard(c)
	g.Context = &ActionContext{Strictness: "high"}
	if err := g.Check(context.Background(), "t", nil); err == nil {
		t.Error("invalid context strictness should be rejected")
	}
	if calls != 0 {
		t.Errorf("an invalid strictness still reached the server (%d calls)", calls)
	}
}

func TestToolGuard_StrictnessPrecedence(t *testing.T) {
	var seen map[string]any
	strictnessSent := func() any {
		ctx, _ := seen["context"].(map[string]any)
		return ctx["strictness"]
	}

	// Guard strictness fills an empty context, keeping its other fields.
	g := verdictGuard(t, "Allow", "", nil, &seen)
	g.Strictness = StrictnessStrict
	g.Context = &ActionContext{UserRequest: "pay the vendor"}
	d, err := g.Screen(context.Background(), "t", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if strictnessSent() != "strict" || d.Strictness != "strict" {
		t.Errorf("guard strictness not applied: sent=%v decision=%q", strictnessSent(), d.Strictness)
	}
	if ctx, _ := seen["context"].(map[string]any); ctx["user_request"] != "pay the vendor" {
		t.Errorf("context fields lost: %v", ctx)
	}
	if g.Context.Strictness != "" {
		t.Error("guard mutated the caller's context")
	}

	// The context's own strictness wins over the guard's.
	g = verdictGuard(t, "Allow", "", nil, &seen)
	g.Strictness = StrictnessStrict
	g.Context = &ActionContext{Strictness: StrictnessRelaxed}
	if d, _ = g.Screen(context.Background(), "t", nil); strictnessSent() != "relaxed" || d.Strictness != "relaxed" {
		t.Errorf("context strictness should win: sent=%v decision=%q", strictnessSent(), d.Strictness)
	}

	// No strictness anywhere: nothing sent, Decision records balanced.
	g = verdictGuard(t, "Allow", "", nil, &seen)
	seen = nil
	if d, _ = g.Screen(context.Background(), "t", nil); d.Strictness != StrictnessBalanced {
		t.Errorf("default decision strictness = %q, want balanced", d.Strictness)
	}
	if _, present := seen["context"]; present {
		t.Errorf("context sent with nothing to send: %v", seen["context"])
	}

	// Client default applies when the guard and context set none.
	g = verdictGuard(t, "Allow", "", nil, &seen)
	g.Client.Strictness = StrictnessRelaxed
	if d, _ = g.Screen(context.Background(), "t", nil); strictnessSent() != "relaxed" || d.Strictness != "relaxed" {
		t.Errorf("client default not used: sent=%v decision=%q", strictnessSent(), d.Strictness)
	}
}

func TestToolGuard_UserRequestFillsOnlyWhenMissing(t *testing.T) {
	var seen map[string]any
	userRequestSent := func() any {
		ctx, _ := seen["context"].(map[string]any)
		return ctx["user_request"]
	}

	g := verdictGuard(t, "Allow", "", nil, &seen)
	if _, err := g.Screen(context.Background(), "t", nil, WithUserRequest("email the report to bob")); err != nil {
		t.Fatal(err)
	}
	if userRequestSent() != "email the report to bob" {
		t.Errorf("user request not filled into an absent context: %v", seen["context"])
	}

	g = verdictGuard(t, "Allow", "", nil, &seen)
	g.Context = &ActionContext{PrincipalDomains: []string{"acme.io"}}
	if err := g.Check(context.Background(), "t", nil, WithUserRequest("from the hook")); err != nil {
		t.Fatal(err)
	}
	if userRequestSent() != "from the hook" {
		t.Errorf("user request not filled into a context without one: %v", seen["context"])
	}
	if g.Context.UserRequest != "" {
		t.Error("guard mutated the caller's context")
	}

	g = verdictGuard(t, "Allow", "", nil, &seen)
	g.Context = &ActionContext{UserRequest: "from trusted state"}
	if _, err := g.Screen(context.Background(), "t", nil, WithUserRequest("from the hook")); err != nil {
		t.Fatal(err)
	}
	if userRequestSent() != "from trusted state" {
		t.Errorf("context's own user request was overwritten: %v", userRequestSent())
	}
}
