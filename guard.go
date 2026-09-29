package surface

import (
	"context"
	"encoding/json"
	"errors"
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
	// Strictness is the level the call was screened at: the context's, else
	// the client's default, else StrictnessBalanced.
	Strictness string
}

// Allowed reports whether the call may proceed.
func (d Decision) Allowed() bool { return d.Action == "Allow" }

// Blocked reports whether the call must be refused.
func (d Decision) Blocked() bool { return d.Action == "Block" }

// NeedsReview reports whether the call should go to a human.
func (d Decision) NeedsReview() bool { return d.Action == "Review" }

// ErrBlocked matches, via errors.Is, every error a guard returns to stop a
// tool call: *BlockedError and *NeedsReviewError.
var ErrBlocked = errors.New("surface: tool call stopped")

// ErrNeedsReview matches, via errors.Is, only a *NeedsReviewError: a Review
// verdict held the call for a person to confirm.
var ErrNeedsReview = errors.New("surface: tool call needs review")

// BlockedError is returned by Check and Wrap when a verdict stops a tool call.
type BlockedError struct{ Decision Decision }

func (e *BlockedError) Error() string {
	return fmt.Sprintf("surface stopped a tool call (%s): %s", e.Decision.Action, e.Decision.Reason)
}

// Is reports whether target is ErrBlocked.
func (e *BlockedError) Is(target error) bool { return target == ErrBlocked }

// NeedsReviewError is returned by Check and Wrap on a Review verdict that the
// guard's review policy did not let through: a person should confirm the call
// before it runs. It unwraps to a *BlockedError, so errors.As(err,
// &blockedErr) and errors.Is(err, ErrBlocked) still match and existing
// handling keeps stopping it. Test for it first to ask the user and retry.
type NeedsReviewError struct{ BlockedError }

func (e *NeedsReviewError) Error() string {
	return fmt.Sprintf("surface held a tool call for review: %s", e.Decision.Reason)
}

// Is reports whether target is ErrNeedsReview.
func (e *NeedsReviewError) Is(target error) bool { return target == ErrNeedsReview }

// Unwrap returns the embedded *BlockedError.
func (e *NeedsReviewError) Unwrap() error { return &e.BlockedError }

// ReviewPolicy decides whether a Review verdict lets a guarded tool run
// (true) or holds it with a *NeedsReviewError (false). Review means a person
// should confirm the call, so a custom policy is where you ask them. The
// context is the one passed to Check or the wrapped tool.
type ReviewPolicy func(ctx context.Context, d Decision) bool

// ReviewHold holds every Review verdict. It is the default (a nil OnReview).
func ReviewHold(context.Context, Decision) bool { return false }

// ReviewAllow runs the tool on a Review verdict.
func ReviewAllow(context.Context, Decision) bool { return true }

// ReviewFunc adapts a context-free callback: f gets the Decision and returns
// true to run the tool.
func ReviewFunc(f func(Decision) bool) ReviewPolicy {
	return func(_ context.Context, d Decision) bool { return f(d) }
}

// ScreenOption adjusts one Screen or Check call.
type ScreenOption func(*screenConfig)

type screenConfig struct{ userRequest string }

// WithUserRequest supplies the user's request for this call. It fills
// ActionContext.UserRequest only when the guard's context has none, so a
// framework hook can pass the run's prompt. It must come from your trusted UI
// channel, never from the tool arguments.
func WithUserRequest(req string) ScreenOption {
	return func(c *screenConfig) { c.userRequest = req }
}

// ContextFunc computes screening context per tool call from trusted state.
type ContextFunc func(name string, args any) *ActionContext

// ToolGuard screens proposed tool calls with Surface and decides the verdict.
// Context is optional. Set Context for a fixed value, or ContextFunc if it
// changes per call. Never derive either from the tool arguments.
//
// Review means a person should confirm the call. Check and Wrap hold it by
// default, returning a *NeedsReviewError; set OnReview to change that.
// BlockOnReview is the older spelling: when true it holds Review regardless of
// OnReview. Block never runs, whatever the policy.
type ToolGuard struct {
	Client      *Client
	Context     *ActionContext // fixed context; ignored when ContextFunc is set
	ContextFunc ContextFunc    // only needed if context changes per call
	// Strictness applies to every call whose context sets none: one of
	// StrictnessRelaxed, StrictnessBalanced, StrictnessStrict. Empty leaves
	// the client's default, then the scanner's (balanced). An invalid value
	// makes Screen return an error.
	Strictness string
	// OnReview decides what Check and Wrap do on Review: nil or ReviewHold
	// holds it, ReviewAllow runs it, or supply your own ReviewPolicy (see
	// ReviewFunc) to ask the user.
	OnReview ReviewPolicy
	// BlockOnReview is the legacy spelling of OnReview: ReviewHold. When true
	// it overrides OnReview.
	BlockOnReview bool
}

// NewToolGuard builds a guard for the given client.
func NewToolGuard(c *Client) *ToolGuard { return &ToolGuard{Client: c} }

// contextFor resolves the call's context and fills guard-level defaults into
// a copy, only where the context leaves them empty.
func (g *ToolGuard) contextFor(name string, args any, cfg screenConfig) *ActionContext {
	var ctx *ActionContext
	if g.ContextFunc != nil {
		ctx = g.ContextFunc(name, args)
	} else {
		ctx = g.Context
	}
	fillStrictness := g.Strictness != "" && (ctx == nil || ctx.Strictness == "")
	fillRequest := cfg.userRequest != "" && (ctx == nil || ctx.UserRequest == "")
	if !fillStrictness && !fillRequest {
		return ctx
	}
	merged := ActionContext{}
	if ctx != nil {
		merged = *ctx
	}
	if fillStrictness {
		merged.Strictness = g.Strictness
	}
	if fillRequest {
		merged.UserRequest = cfg.userRequest
	}
	return &merged
}

// strictnessFor is the level a call is screened at.
func (g *ToolGuard) strictnessFor(ctx *ActionContext) string {
	if ctx != nil && ctx.Strictness != "" {
		return ctx.Strictness
	}
	if g.Client != nil && g.Client.Strictness != "" {
		return g.Client.Strictness
	}
	return StrictnessBalanced
}

// reviewRuns reports whether a Review verdict lets the tool run.
func (g *ToolGuard) reviewRuns(ctx context.Context, d Decision) bool {
	if g.BlockOnReview || g.OnReview == nil {
		return false
	}
	return g.OnReview(ctx, d)
}

// Screen scans a proposed tool call and returns the Decision. Options such as
// WithUserRequest adjust this call only.
func (g *ToolGuard) Screen(ctx context.Context, name string, args any, opts ...ScreenOption) (Decision, error) {
	if err := validateStrictness(g.Strictness); err != nil {
		return Decision{}, err
	}
	var cfg screenConfig
	for _, o := range opts {
		if o != nil {
			o(&cfg)
		}
	}
	payload, err := json.Marshal(map[string]any{"tool": name, "args": args})
	if err != nil {
		return Decision{}, err
	}
	actx := g.contextFor(name, args, cfg)
	res, err := g.Client.ScanPayload(ctx, payload, name+".toolcall.json",
		&ScanFileOptions{Context: actx})
	if err != nil {
		return Decision{}, err
	}
	d := decisionFrom(res)
	d.Strictness = g.strictnessFor(actx)
	return d, nil
}

// Check screens a proposed tool call and returns nil to proceed, a
// *BlockedError on Block, or a *NeedsReviewError on Review unless the guard's
// review policy lets it run. Call it at the top of your tool dispatch:
//
//	if err := guard.Check(ctx, name, args); err != nil { return err }
func (g *ToolGuard) Check(ctx context.Context, name string, args any, opts ...ScreenOption) error {
	d, err := g.Screen(ctx, name, args, opts...)
	if err != nil {
		return err
	}
	if d.Blocked() {
		return &BlockedError{Decision: d}
	}
	if d.NeedsReview() && !g.reviewRuns(ctx, d) {
		return &NeedsReviewError{BlockedError{Decision: d}}
	}
	return nil
}

// Wrap guards a single-argument tool function so it screens its own call before
// running. On Block it returns a *BlockedError; on Review it follows the
// guard's review policy, by default returning a *NeedsReviewError. Either way
// the tool is not executed. It fits the common `func(ctx, args) (result, error)` tool shape.
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
