package surface

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

const actionRiskJSON = `{"probability":0.87,"reasons":["deletes files outside the workspace"],"action":"Block","mode":"shadow","calls":1,"modelVersion":"ar-v1","record":{"tool":"rm","target":"/"}}`

func TestScanResult_ActionRiskDecode(t *testing.T) {
	var with ScanResult
	if err := json.Unmarshal([]byte(`{"name":"x","actionRisk":`+actionRiskJSON+`}`), &with); err != nil {
		t.Fatal(err)
	}
	ar := with.ActionRisk
	if ar == nil {
		t.Fatal("ActionRisk = nil, want decoded")
	}
	if ar.Probability != 0.87 || ar.Action != "Block" || ar.Mode != "shadow" || ar.Calls != 1 || ar.ModelVersion != "ar-v1" {
		t.Errorf("decoded = %+v", ar)
	}
	if len(ar.Reasons) != 1 || ar.Reasons[0] != "deletes files outside the workspace" {
		t.Errorf("reasons = %v", ar.Reasons)
	}
	var rec map[string]any
	if err := json.Unmarshal(ar.Record, &rec); err != nil || rec["tool"] != "rm" {
		t.Errorf("record = %s (%v)", ar.Record, err)
	}

	var without ScanResult
	if err := json.Unmarshal([]byte(`{"name":"x"}`), &without); err != nil {
		t.Fatal(err)
	}
	if without.ActionRisk != nil {
		t.Errorf("ActionRisk = %+v, want nil", without.ActionRisk)
	}
	out, _ := json.Marshal(without)
	var m map[string]any
	_ = json.Unmarshal(out, &m)
	if _, ok := m["actionRisk"]; ok {
		t.Error("actionRisk should be omitted when nil")
	}
}

// riskGuard answers with the given recommendedAction and optional raw actionRisk.
func riskGuard(t *testing.T, action string, actionRisk string) *ToolGuard {
	c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"name": "t.toolcall.json", "size": 1, "hash": "sha256:x",
			"contentType": "application/json",
			"safetyScore": map[string]any{
				"score": 90, "threatLevel": "Clean", "confidence": "High",
				"confidenceScore": 0.9, "confidenceReason": "x",
				"primaryThreat": "", "threatSummary": "",
				"enginesUsed": []string{"Action Screening"}, "recommendedAction": action,
			},
			"scanTimeMs": 1, "timestamp": 0,
		}
		if actionRisk != "" {
			resp["actionRisk"] = json.RawMessage(actionRisk)
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	t.Cleanup(srv.Close)
	return NewToolGuard(c)
}

func TestToolGuard_ActionRiskPropagates(t *testing.T) {
	// Shadow risk says Block, but the verdict stays the scan's Allow.
	g := riskGuard(t, "Allow", actionRiskJSON)
	d, err := g.Screen(context.Background(), "rm", map[string]any{"path": "/"})
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != "Allow" || !d.Allowed() {
		t.Errorf("action = %q, want Allow (actionRisk must not change the verdict)", d.Action)
	}
	if d.RiskProbability == nil || *d.RiskProbability != 0.87 {
		t.Errorf("RiskProbability = %v, want 0.87", d.RiskProbability)
	}
	if len(d.RiskReasons) != 1 || d.RiskReasons[0] != "deletes files outside the workspace" {
		t.Errorf("RiskReasons = %v", d.RiskReasons)
	}
	if d.Result == nil || d.Result.ActionRisk == nil || d.Result.ActionRisk.Mode != "shadow" {
		t.Errorf("Result.ActionRisk not carried: %+v", d.Result)
	}
	if err := g.Check(context.Background(), "rm", map[string]any{"path": "/"}); err != nil {
		t.Errorf("Check = %v, want nil", err)
	}
}

func TestToolGuard_ActionRiskZeroProbabilityNoReasons(t *testing.T) {
	g := riskGuard(t, "Allow", `{"probability":0,"action":"Allow","mode":"on","calls":1}`)
	d, err := g.Screen(context.Background(), "ls", nil)
	if err != nil {
		t.Fatal(err)
	}
	if d.RiskProbability == nil || *d.RiskProbability != 0 {
		t.Errorf("RiskProbability = %v, want pointer to 0", d.RiskProbability)
	}
	if d.RiskReasons != nil {
		t.Errorf("RiskReasons = %v, want nil", d.RiskReasons)
	}
}

func TestToolGuard_NoActionRisk(t *testing.T) {
	for _, action := range []string{"Allow", "Review", "Block"} {
		g := riskGuard(t, action, "")
		d, err := g.Screen(context.Background(), "t", map[string]any{"a": 1})
		if err != nil {
			t.Fatal(err)
		}
		if d.Action != action {
			t.Errorf("action = %q, want %q", d.Action, action)
		}
		if d.RiskProbability != nil || d.RiskReasons != nil {
			t.Errorf("%s: risk fields set without actionRisk: %v %v", action, d.RiskProbability, d.RiskReasons)
		}
		if d.Result.ActionRisk != nil {
			t.Errorf("%s: Result.ActionRisk = %+v, want nil", action, d.Result.ActionRisk)
		}
	}
}

func TestScanResult_ContentRiskDecode(t *testing.T) {
	var with ScanResult
	if err := json.Unmarshal([]byte(`{"name":"x","contentRisk":{"probability":0.97,"reasons":["addresses an AI agent and asks it to act"],"action":"Review","mode":"shadow","modelVersion":"content-risk-1"}}`), &with); err != nil {
		t.Fatal(err)
	}
	cr := with.ContentRisk
	if cr == nil || cr.Probability != 0.97 || cr.Action != "Review" || cr.Mode != "shadow" || cr.ModelVersion != "content-risk-1" || len(cr.Reasons) != 1 {
		t.Errorf("decoded = %+v", cr)
	}
	var without ScanResult
	if err := json.Unmarshal([]byte(`{"name":"x"}`), &without); err != nil || without.ContentRisk != nil {
		t.Errorf("without = %+v (%v)", without.ContentRisk, err)
	}
}
