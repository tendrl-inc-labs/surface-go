package surface

import (
	"context"
	"encoding/json"
	"fmt"
)

// Action screening judges the tool call an agent is about to make, before you
// run it, and returns Allow / Review / Block. It is not automatic: the host
// screens the proposed call, the model never scans itself. ToolGuard packages
// that propose -> scan -> branch so you don't hand-wire the scan, the verdict
// check, and the branch on every call.

// ToolFinding is one flagged action from the screener.
type ToolFinding struct {
	ToolName string `json:"toolName"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Reason   string `json:"reason"`
	Evidence string `json:"evidence,omitempty"`
}

// Decision is the verdict on one proposed tool call.
type Decision struct {
	Action   string // "Allow" | "Review" | "Block"
	Reason   string // human-readable, from the strongest finding
	Findings []ToolFinding
	Result   *ScanResult
}

// Allowed reports whether the call may proceed.
func (d Decision) Allowed() bool { return d.Action == "Allow" }

// Blocked reports whether the call must be refused.
func (d Decision) Blocked() bool { return d.Action == "Block" }

// NeedsReview reports whether the call should go to a human.
func (d Decision) NeedsReview() bool { return d.Action == "Review" }

// BlockedError is returned by Check and Wrap when a verdict stops a tool call.
type BlockedError struct{ Decision Decision }

func (e *BlockedError) Error() string {
	return fmt.Sprintf("surface stopped a tool call (%s): %s", e.Decision.Action, e.Decision.Reason)
}

// ContextFunc computes screening context per tool call from trusted state.
type ContextFunc func(name string, args any) *ActionContext

// ToolGuard screens proposed tool calls with Surface and decides the verdict.
// Set Context for a fixed context, or ContextFunc to build one per call from
// your trusted request state (preferred). Never derive context from the tool
// arguments. If BlockOnReview is set, Review is treated as a hard stop.
type ToolGuard struct {
	Client        *Client
	Context       *ActionContext // fixed context; ignored when ContextFunc is set
	ContextFunc   ContextFunc    // per-call context (preferred)
	BlockOnReview bool
}

// NewToolGuard builds a guard for the given client.
func NewToolGuard(c *Client) *ToolGuard { return &ToolGuard{Client: c} }

func (g *ToolGuard) contextFor(name string, args any) *ActionContext {
	if g.ContextFunc != nil {
		return g.ContextFunc(name, args)
	}
	return g.Context
}

// Screen scans a proposed tool call and returns the Decision.
func (g *ToolGuard) Screen(ctx context.Context, name string, args any) (Decision, error) {
	payload, err := json.Marshal(map[string]any{"tool": name, "args": args})
	if err != nil {
		return Decision{}, err
	}
	res, err := g.Client.ScanPayload(ctx, payload, name+".toolcall.json",
		&ScanFileOptions{Context: g.contextFor(name, args)})
	if err != nil {
		return Decision{}, err
	}
	return decisionFrom(res), nil
}

// Check screens a proposed tool call and returns a *BlockedError if it must not
// run (Block, or Review when BlockOnReview), or nil to proceed. Call it at the
// top of your tool dispatch:
//
//	if err := guard.Check(ctx, name, args); err != nil { return err }
func (g *ToolGuard) Check(ctx context.Context, name string, args any) error {
	d, err := g.Screen(ctx, name, args)
	if err != nil {
		return err
	}
	if d.Blocked() || (g.BlockOnReview && d.NeedsReview()) {
		return &BlockedError{Decision: d}
	}
	return nil
}

// Wrap guards a single-argument tool function so it screens its own call before
// running. On a stopping verdict it returns a *BlockedError and the tool is not
// executed. It fits the common `func(ctx, args) (result, error)` tool shape.
func Wrap[A any, R any](g *ToolGuard, name string, fn func(context.Context, A) (R, error)) func(context.Context, A) (R, error) {
	return func(ctx context.Context, args A) (R, error) {
		if err := g.Check(ctx, name, args); err != nil {
			var zero R
			return zero, err
		}
		return fn(ctx, args)
	}
}

func decisionFrom(res *ScanFileResult) Decision {
	if res == nil || res.ScanResult == nil {
		// A deferred scan carries no verdict; it cannot clear a live action.
		return Decision{Action: "Review", Reason: "scan deferred; no verdict yet"}
	}
	sr := res.ScanResult
	d := Decision{
		Action: sr.SafetyScore.RecommendedAction,
		Reason: sr.SafetyScore.PrimaryThreat,
		Result: sr,
	}
	if len(sr.ActionScreen) > 0 {
		var as struct {
			Findings []ToolFinding `json:"findings"`
		}
		if json.Unmarshal(sr.ActionScreen, &as) == nil {
			d.Findings = as.Findings
			if d.Reason == "" && len(as.Findings) > 0 {
				d.Reason = as.Findings[0].Reason
			}
		}
	}
	return d
}
