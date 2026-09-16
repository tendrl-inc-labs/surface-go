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
	// Review passes by default, stops when BlockOnReview.
	if err := verdictGuard(t, "Review", "", nil, nil).Check(context.Background(), "t", nil); err != nil {
		t.Errorf("Review should pass by default: %v", err)
	}
	gr := verdictGuard(t, "Review", "", nil, nil)
	gr.BlockOnReview = true
	if err := gr.Check(context.Background(), "t", nil); !errors.As(err, &be) {
		t.Errorf("Review with BlockOnReview should return *BlockedError, got %v", err)
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
