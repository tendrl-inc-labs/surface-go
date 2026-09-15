package surface

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// The context an application supplies is forwarded in the request body under
// "context", with the payee list and user request intact.
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
			KnownPayees:      []ActionPayee{{Name: "Delta", IBAN: "GB29NWBK60161331926819"}},
			UserRequest:      "pay this month's invoices",
		}},
	)
	if err != nil {
		t.Fatalf("ScanPayload: %v", err)
	}
	ctx, ok := gotBody["context"].(map[string]any)
	if !ok {
		t.Fatalf("request body has no context object: %v", gotBody)
	}
	if ctx["user_request"] != "pay this month's invoices" {
		t.Errorf("user_request not forwarded: %v", ctx["user_request"])
	}
	egress, ok := ctx["allowed_egress"].([]any)
	if !ok || len(egress) != 2 || egress[0] != "api.stripe.com" {
		t.Errorf("allowed_egress not forwarded: %v", ctx["allowed_egress"])
	}
	payees, ok := ctx["known_payees"].([]any)
	if !ok || len(payees) != 1 {
		t.Fatalf("known_payees not forwarded: %v", ctx["known_payees"])
	}
	if p := payees[0].(map[string]any); p["iban"] != "GB29NWBK60161331926819" {
		t.Errorf("payee iban not forwarded: %v", p)
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

// Proven value, through the SDK surface: a payment the caller's context marks as
// going to an unknown account is Blocked, while the same call to a known payee is
// Allowed. The mock server stands in for the screener's context-aware verdict —
// the engine-level proof lives in tendrl-surface's action-corpus — so this test
// pins that the SDK carries the context that drives the flip.
func TestScanPayload_ContextFlipsVerdict(t *testing.T) {
	known := "GB29NWBK60161331926819"
	verdictFor := func(opts *ScanFileOptions) string {
		c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			var body struct {
				Payload string         `json:"payload"`
				Context *ActionContext `json:"context"`
			}
			_ = json.Unmarshal(b, &body)
			// Model the screener: a payment to an account not in known_payees is a
			// Block; to a known one, Allow.
			action, verdict := "Block", "Malicious"
			if body.Context != nil {
				for _, p := range body.Context.KnownPayees {
					if p.IBAN == known {
						action, verdict = "Allow", "Clean"
					}
				}
			}
			w.Write([]byte(`{"safetyScore":{"threatLevel":"` + verdict + `","recommendedAction":"` + action + `"}}`))
		})
		defer srv.Close()
		payload := []byte(`{"tool":"create_payment","args":{"iban":"` + known + `","amount":18650}}`)
		res, err := c.ScanPayload(context.Background(), payload, "payment.json", opts)
		if err != nil {
			t.Fatalf("ScanPayload: %v", err)
		}
		return res.ScanResult.SafetyScore.RecommendedAction
	}

	if got := verdictFor(&ScanFileOptions{Context: &ActionContext{
		KnownPayees: []ActionPayee{{Name: "Delta", IBAN: known}},
	}}); got != "Allow" {
		t.Errorf("payment to a known payee: got %q, want Allow", got)
	}
	if got := verdictFor(nil); got != "Block" {
		t.Errorf("payment with no payee context: got %q, want Block", got)
	}
}
