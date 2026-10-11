# Surface Go SDK

Go client for the [Surface](https://tendrl.com/products/surface) file scanning API. Supports two modes: **API mode** (remote scanning via the Surface API) and **Local mode** (scan files locally using the scanner binary). Zero external dependencies — uses only the standard library.

## Installation

Requires Go 1.21+.

```bash
go get github.com/tendrl-inc-labs/surface-go@v0.3.0
```

This README describes v0.3.0. Earlier tags lack `Strictness`, `ReviewFunc`, the `Source*` constants, and `PersonalMailExpected`, so code using them won't compile against v0.2.0; if you use `@latest`, check that `go.mod` records v0.3.0 or later.

## Scan Modes

| Mode | Description | API Key Required | Network Required |
|------|-------------|-----------------|-----------------|
| **API** (default) | Sends files to the Surface API | Yes | Yes |
| **Local** | Runs the scanner binary locally | Yes | No |

## Quick Start — API Mode

```go
package main

import (
    "context"
    "fmt"
    "log"

    surface "github.com/tendrl-inc-labs/surface-go"
)

func main() {
    client, err := surface.NewClient("your-surface-token")
    if err != nil {
        log.Fatal(err)
    }

    result, err := client.ScanFile(context.Background(), "invoice.pdf", nil)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(result.ScanResult.SafetyScore.ThreatLevel)
}
```

The examples scan documents and archives, which the Default scan profile accepts. Executables and scripts (`.exe`, `.sh`, ...) are refused by type with a `*ValidationError` unless the key's profile allows them; see [scan profiles](https://tendrl.com/docs/surface/scan-profiles/).

Prefer not to check the verdict by hand? `ScanFunc` wraps the client: hand it a file, your handler receives the `*ScanResult`, and files matching `Reject` never reach it (`ScanBytesFunc` is the same for in-memory data).

```go
process := surface.ScanFunc(client, &surface.ScanFileOptions{
    Reject: []string{"Block", "Review"}, // uploads: refuse Block and Review
}, func(r *surface.ScanResult) error {
    // Clean, Informational, Suspicious, Risky, or Malicious
    fmt.Println(r.SafetyScore.ThreatLevel)
    return nil // runs only for accepted files
})

if err := process(context.Background(), "invoice.pdf"); err != nil {
    log.Fatal(err) // *MaliciousFileError when the file was rejected
}
```

For file uploads, reject `Review` as well as `Block`. `Block` needs precise evidence (a known-malware hash, an antivirus signature, a malware rule), so new malware recognized only by the models comes back as `Review`; rejecting `Block` alone lets most of it through. Agent tool calls are different: there `Review` means "confirm with the user" (see [Guarding an agent's tool calls](#guarding-an-agents-tool-calls)).

`Reject` matches the recommended action (`"Block"`, `"Review"`) or the threat level (`"Malicious"`, `"Suspicious"`), case-insensitively, in both API and local mode.

## Quick Start — Local Mode

Requires the `surface-scanner` binary installed or available on `$PATH`. The scanner refuses to start without an API key; the client passes its key (from `LocalConfig.APIKey` or `SURFACE_KEY`) to the scanner it launches as `SURFACE_API_KEY`, so set it once for both.

```go
package main

import (
    "context"
    "fmt"
    "log"

    surface "github.com/tendrl-inc-labs/surface-go"
)

func main() {
    client, err := surface.NewLocalClient(nil) // uses SURFACE_KEY env var, finds surface-scanner on $PATH
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close() // stops the scanner daemon

    result, err := client.ScanFile(context.Background(), "invoice.pdf", nil)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(result.ScanResult.SafetyScore.ThreatLevel)
}
```

With custom scanner path:

```go
client, err := surface.NewLocalClient(&surface.LocalConfig{
    APIKey:       "your-surface-token",
    ScannerPath:  "/usr/local/bin/surface-scanner",
    DataDir:      "/var/lib/surface/data",
    StartTimeout: 3 * time.Minute, // optional; default 2 minutes
    Stderr:       os.Stderr,       // optional; the daemon's log
})
```

The local client starts the scanner in daemon mode on a random loopback port (`127.0.0.1`). It starts automatically on the first scan and stops when you call `Close()`. It also exits by itself when your program does, even if `Close()` never runs because the program crashed or was killed. That needs a scanner binary with the `--parent-pid` flag; with an older binary, call `Close()`. The same `ScanFile`, `ScanBytes`, `ScanReader`, and `ScanFiles` methods work in both modes.

The first launch on a machine downloads threat feeds, so the first scan can take a while; `StartTimeout` bounds the wait. The daemon's log stays out of your program's output unless you set `Stderr`; if it fails to start, the error includes its last lines.

## Authentication

`NewClient` checks for an API key in this order:

1. `apiKey` parameter passed to `NewClient()`
2. `SURFACE_KEY` environment variable

```bash
export SURFACE_KEY="your-surface-token"
```

To get a token, create a key in the Surface dashboard under **Access Control → API keys** and copy the token (it is shown once). The token is the secret the SDK sends; the key's ID is not.

If neither is set, `NewClient` returns an `*AuthenticationError`.

## Scanning Files

```go
ctx := context.Background()

// From file path, bytes, or io.Reader
fromPath, err := client.ScanFile(ctx, "invoice.pdf", nil)
fromBytes, err := client.ScanBytes(ctx, "sample.bin", data, nil)
fromReader, err := client.ScanReader(ctx, "upload.zip", reader, nil)

// Reject malicious files — returns *MaliciousFileError
checked, err := client.ScanFile(ctx, "upload.zip", &surface.ScanFileOptions{
    Reject: []string{"Malicious", "Suspicious"},
})

// Deferred scan (returns immediately, poll for results)
queued, err := client.ScanFile(ctx, "large.zip", &surface.ScanFileOptions{Defer: true})
if queued.Deferred != nil {
    raw, err := client.GetScan(ctx, queued.Deferred.ScanID)
}
```

## Scan Payload

Scan raw content without writing to disk. Accepts `[]byte` payload and a filename label:

```go
result, err := client.ScanPayload(ctx, []byte("<?php system('id');"), "test.php", nil)
fmt.Println(result.ScanResult.SafetyScore.ThreatLevel)
```

The payload is sent as raw text to `POST /api/scan/payload`. Binary payloads are automatically base64-encoded by the SDK. Supports the same `ScanFileOptions` as `ScanFile`.

## Action Screening Context

When you scan a tool call an agent is about to make, some actions are dangerous on their own (deleting a database, a secret in a URL) and some are dangerous only relative to *you* — a payment is fine to a known vendor but not to an account you've never paid; an email is fine to a colleague but not leaving to a personal address. The scanner sees the tool call but not your vendor list, your domains, or what the user asked. `Context` supplies those facts so it can decide confidently instead of defaulting to a cautious "Review".

```go
result, err := client.ScanPayload(ctx, toolCallJSON, "agent-step.json", &surface.ScanFileOptions{
    Context: &surface.ActionContext{
        PrincipalDomains: []string{"acme.io"},                       // what counts as "inside"
        AllowedEgress:    []string{"api.stripe.com", "hooks.slack.com"}, // outside hosts you legitimately call
        UserRequest:      userMessage,                               // what the user actually asked
    },
})
```

**Strictness**

`Strictness` sets how readily a judgment call turns into a verdict. It never changes face-dangerous actions (a public share, a secret in a URL, destructive commands), which Block at every level.

- `surface.StrictnessRelaxed`: stop only what's certainly malicious.
- `surface.StrictnessBalanced` (the default): stop what's certainly malicious, ask before risky or irreversible actions.
- `surface.StrictnessStrict`: ask or stop on anything that needs judgment, including mail to personal addresses and outside recipients.

```go
&surface.ActionContext{PrincipalDomains: []string{"acme.io"}, UserRequest: userMessage, Strictness: surface.StrictnessStrict}
```

Set `client.Strictness` (or `LocalConfig.Strictness`) for a default on every `ScanPayload`: it fills the context's strictness only when the context sets none, and is sent on its own when you pass no context. Leave it empty and the scanner uses balanced, so an agent with no configuration isn't stopped while it does routine work. An invalid value is rejected with an error before anything is sent.

**Who wrote it: `Source`.** Tell Surface where the payload came from and it judges prompt injection accordingly. `surface.SourceUserPrompt`: the person your agent works for typed it; their own text ("ignore my previous instruction", a story, a pasted log, a translation) is not flagged, and a direct override is held for Review, never blocked, unless `Strictness` is strict. `surface.SourceContent`: text the agent reads (a web page, an email, tool output), where a single injection pattern blocks. `surface.SourceToolCall`: an action the agent is about to take; `ToolGuard` sets it for you. Empty, an injection blocks only when two independent signals agree. `MiddlewareOptions.Source` sets it for a whole endpoint:

```go
handler := surface.ScanMiddleware(client, chatHandler, &surface.MiddlewareOptions{Source: surface.SourceUserPrompt})
```

**Personal mailboxes.** Agents mail customers and candidates on Gmail all day, so below strict a send to a personal mailbox is held only on evidence: `UserRequest` was passed and never named the address (or is itself an override like "ignore previous instructions"), or the message describes a customer list or export it sends in bulk ("all customer records"). Without `UserRequest` such sends aren't judged below strict, so pass it. Sensitive data to a personal mailbox is blocked at strict; the recipient's own address never counts as the data. Set `PersonalMailExpected: true` when your users routinely correspond with people on personal mailboxes, and even a bulk send to an address named in `UserRequest` passes below strict. A live credential still blocks.

**Threat levels.** A Block that rests only on a risky agent action (a tool call, not malware or an injection) is reported as `ThreatLevel: "Risky"` with `RecommendedAction: "Block"`; malware and injections stay `"Malicious"`. Reject on `"Block"` to stop both.

**Content risk.** When the scanner's content-risk engine is on, a scan of content an agent will read (`Source: surface.SourceContent`, or no source) carries `result.ContentRisk`: `Probability` (calibrated likelihood that the text tries to steer the agent into a harmful action, such as a planted "note to the assistant" asking it to post data out or change a payout), `Action` (what this engine alone recommends), `Mode` (`shadow` = reported only) and plain-language `Reasons`. It is absent for a user's own prompt and for tool calls.

**Use cases**

- **Data egress** — an email or upload leaving `PrincipalDomains` (or to a free-mail address) is flagged; a recipient the user named in `UserRequest` is cleared. With `AllowedEgress` set, an HTTP POST of data to a host on neither list is flagged for review, so a Stripe or Slack call passes while a POST to an unknown endpoint is caught; a bare-IP destination or a secret in the body is flagged even without it.
- **Dangerous on its face** — a crypto-address payout, a gift-card purchase that returns the codes, `rm -rf` of a data directory, or an admin grant is flagged with no context needed.
- **Task fit** — an action unrelated to `UserRequest` (a refund during "summarize my tickets") is surfaced.

**Suggested implementation**

- Build `Context` from your **trusted application state** — your configured domains, your known integration hosts, the user's message from your own UI. **Never** populate it from the payload being scanned; that would let an attacker vouch for their own request.
- `Context` is optional. Pass only the fields you have; those values are typed (a domain list must be a slice of strings) and `Strictness` is validated. Omit it and screening still runs on face value — nothing that is dangerous on its own is missed.
- Only what you put in `Context` is sent with the scan (for hosted scans, to the API). Keep `UserRequest` to the instruction itself.

### Guarding an agent's tool calls

Action screening runs in your agent loop, around tool execution — it is not automatic. `ToolGuard` packages the propose → scan → branch pattern so you don't hand-wire it. Either call `Screen` and branch, `Check` at the top of your dispatch, or `Wrap` a single-argument tool.

```go
guard := &surface.ToolGuard{Client: client}

// Decide yourself
d, err := guard.Screen(ctx, call.Name, call.Args)
switch {
case err != nil:      return err
case d.Blocked():     return refuse(d.Reason)      // d.Findings has the action + evidence
case d.NeedsReview(): return escalateToHuman(call, d)
default:              return run(call)
}

// Or refuse at the top of a tool's dispatch
if err := guard.Check(ctx, call.Name, call.Args); err != nil {
    return err // *surface.BlockedError on Block, *surface.NeedsReviewError on Review
}

// Or wrap a single-argument tool
safeTransfer := surface.Wrap(guard, "transfer", transferFunds)
_, err = safeTransfer(ctx, TransferArgs{To: "acct_…", Amount: 4800})
```

Review means a person should confirm the call. `Check` and `Wrap` hold it by default: the tool does not run and you get a `*surface.NeedsReviewError`. That error unwraps to a `*surface.BlockedError` (and matches `errors.Is(err, surface.ErrBlocked)`), so handling written for Block still stops it; check for it first to ask the user and retry. Block never runs, whatever the policy. Set `OnReview` to change what happens on Review:

```go
guard.OnReview = surface.ReviewAllow // run it anyway
guard.OnReview = surface.ReviewFunc(func(d surface.Decision) bool {
    return askUser(d.Reason) // true runs the tool
})
// or a surface.ReviewPolicy, func(ctx, d) bool, when you need the call's context
```

`BlockOnReview: true` is the older spelling of the default hold and overrides `OnReview`.

```go
var nr *surface.NeedsReviewError
if errors.As(err, &nr) {
    return askUser(nr.Decision.Reason, nr.Decision.Findings)
}
```

Context is optional. Pass the fields you have from trusted app state — never from the tool arguments. `ContextFunc` is only needed if the values change per call.

```go
guard := &surface.ToolGuard{
    Client: client,
    Context: &surface.ActionContext{
        PrincipalDomains: []string{"acme.io"},
        AllowedEgress:    []string{"api.stripe.com", "hooks.slack.com"},
        UserRequest:      session.UserMessage,
    },
    Strictness: surface.StrictnessBalanced, // used when the context sets none
}
```

`guard.Strictness` fills the context's strictness when it has none, ahead of the client's default. `Decision.Strictness` records the level the call was screened at (`"balanced"` when nothing set one). A framework hook that has the run's prompt can pass it per call with `guard.Screen(ctx, name, args, surface.WithUserRequest(prompt))` (also accepted by `Check`); it fills `UserRequest` only when the guard's context has none.

## Agentic Security

Payload scan results may include additional threat detection from agentic security engines. These fields are present on `ScanResult` as `json.RawMessage` (decode as needed):

- **`CodeExtraction`** — embedded code blocks found in the payload (scripts, shell commands)
- **`PromptInjection`** — prompt injection attempts detected in text content
- **`SensitiveData`** — exposed credentials, API keys, or PII
- **`ToolCallAnalysis`** — suspicious tool/function call patterns

`ScanResult.ActionRisk` (`*ActionRisk`, nil when the feature is off or the payload is not a tool call) is a typed learned risk assessment of a tool call: `Probability` (calibrated 0-1), `Reasons`, `Action` (this engine's own recommendation), `Mode` (`"shadow"` means it does not affect the verdict, or `"on"`), `Calls`, `ModelVersion`, and `Record` (`json.RawMessage`). A guard's `Decision` mirrors it as `RiskProbability *float64` and `RiskReasons []string`; these are informational and never change `Decision.Action`.

```go
if result.ScanResult.PromptInjection != nil {
    fmt.Println("Prompt injection detected in payload")
}
```

## Middleware

`ScanMiddleware` wraps any `http.Handler` to automatically scan request bodies before they reach your handler. Requests with threats matching the `Reject` list receive a 403 response. Leave `Reject` unset and it is `[]string{"Block"}`: whatever Surface recommends blocking (Malicious, Risky, a type the profile refuses) is rejected.

```go
mux := http.NewServeMux()
mux.HandleFunc("/api/data", dataHandler)

protected := surface.ScanMiddleware(client, mux, &surface.MiddlewareOptions{
    Reject: []string{"Malicious"},
})

log.Fatal(http.ListenAndServe(":8080", protected))
```

`FailOpen` is a `*bool` so unset (the default, fail open) is distinguishable from an explicit `false`. Set it only when you want a hard 503 if the scanner is down:

```go
failClosed := false
surface.ScanMiddleware(client, mux, &surface.MiddlewareOptions{
    Reject:   []string{"Malicious"},
    FailOpen: &failClosed,
})
```

For a single handler function, use `ScanHandlerFunc`:

```go
http.Handle("/upload", surface.ScanHandlerFunc(client, uploadHandler, nil))
```

Custom threat callback:

```go
surface.ScanMiddleware(client, mux, &surface.MiddlewareOptions{
    Reject: []string{"Malicious"},
    OnThreat: func(r *http.Request, result *surface.ScanResult) {
        log.Printf("blocked %s from %s", result.SafetyScore.ThreatLevel, r.RemoteAddr)
    },
})
```

`OnThreat` runs for logging and alerting only — the middleware writes the 403 itself, so the callback has no `http.ResponseWriter` and cannot change the response.

Options: `Reject`, `ScanRequests`, `Label`, `FailOpen`, `MinSize`, `OnThreat`, `OnError`.

**This middleware scans requests, not responses.** That is deliberate, and it
differs from the JavaScript SDK, whose `createSafeFetch` scans both. Scanning an
outgoing response in an `http.Handler` means buffering it in a wrapping
`ResponseWriter`, which changes the contract every downstream handler is written
against, including streaming and flushing. Scan outbound payloads explicitly
with `ScanBytes` or `ScanReader` where you produce them.

## Batch Scanning

Scan multiple files concurrently with `ScanFiles`. The third argument controls max concurrency (0 defaults to 10). If any scan fails, remaining scans are canceled and the first error is returned:

```go
paths := []string{"file1.pdf", "file2.zip", "file3.csv"}
results, err := client.ScanFiles(ctx, paths, nil, 5)
if err != nil {
    log.Fatal(err)
}
for _, r := range results {
    fmt.Println(r.ScanResult.SafetyScore.ThreatLevel)
}
```

## Account & Usage

```go
usage, err := client.GetUsage(ctx)
fmt.Printf("%d/%d scans used this period (%d remaining)\n", usage.ScansUsed, usage.MaxScans, usage.ScansRemaining)

account, err := client.GetAccount(ctx)
```

## Profiles and API Keys

The SDK doesn't manage scan profiles or API keys. Each key is bound to a profile, and scans use it automatically, so scanning code never needs to choose one. Create and edit profiles and keys in the Surface dashboard, the [REST API](https://tendrl.com/docs/surface/api/), or the [Surface MCP tools](https://tendrl.com/docs/surface/ai/mcp-server/). See [scan profiles](https://tendrl.com/docs/surface/scan-profiles/) for what each setting does.

## Scan History

```go
history, err := client.GetScanHistory(ctx, 1, 25)
for _, scan := range history.Scans {
    fmt.Printf("%s: %s (history weight %d)\n", scan.Filename, scan.ThreatLevel, scan.CreditsUsed)
}
```

## Webhook Verification

```go
isValid := surface.VerifyWebhookSignature(
    bodyBytes,
    "your_webhook_secret",
    r.Header.Get("X-Surface-Signature"),
)
```

## net/http Integration

```go
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	surface "github.com/tendrl-inc-labs/surface-go"
)

var client, _ = surface.NewClient("")

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "missing file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	data, _ := io.ReadAll(file)
	result, err := client.ScanBytes(r.Context(), header.Filename, data, &surface.ScanFileOptions{
		Reject: []string{"Malicious"},
	})
	if err != nil {
		if _, ok := err.(*surface.MaliciousFileError); ok {
			http.Error(w, "file rejected", http.StatusBadRequest)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "clean",
		"score":  result.ScanResult.SafetyScore.Score,
	})
}

func main() {
	http.HandleFunc("/upload", uploadHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

## Echo Integration

```go
package main

import (
	"io"
	"net/http"

	"github.com/labstack/echo/v4"
	surface "github.com/tendrl-inc-labs/surface-go"
)

var client, _ = surface.NewClient("")

func uploadHandler(c echo.Context) error {
	file, err := c.FormFile("file")
	if err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "missing file"})
	}

	src, _ := file.Open()
	defer src.Close()
	data, _ := io.ReadAll(src)

	result, err := client.ScanBytes(c.Request().Context(), file.Filename, data, &surface.ScanFileOptions{
		Reject: []string{"Malicious"},
	})
	if err != nil {
		if _, ok := err.(*surface.MaliciousFileError); ok {
			return c.JSON(http.StatusBadRequest, echo.Map{"error": "file rejected"})
		}
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, echo.Map{
		"status": "clean",
		"score":  result.ScanResult.SafetyScore.Score,
	})
}

func main() {
	e := echo.New()
	e.POST("/upload", uploadHandler)
	e.Logger.Fatal(e.Start(":8080"))
}
```

## Error Handling

Errors are returned as typed structs; match them with `errors.As` / `errors.Is`:

```go
result, err := client.ScanFile(ctx, "test.pdf", nil)
var (
    quotaErr *surface.QuotaExceededError
    rateErr  *surface.RateLimitError
    authErr  *surface.AuthenticationError
    nfErr    *surface.NotFoundError
    apiErr   *surface.SurfaceError
)
switch {
case errors.Is(err, surface.ErrUnavailable):
    fmt.Println("Surface unavailable:", err) // see below
case errors.As(err, &quotaErr):
    fmt.Println("Monthly scan quota exhausted")
case errors.As(err, &rateErr):
    fmt.Println("Rate limit hit")
case errors.As(err, &authErr):
    fmt.Println("Invalid API key")
case errors.As(err, &nfErr):
    fmt.Println("Resource not found")
case errors.As(err, &apiErr):
    fmt.Printf("API error %d: %s\n", apiErr.StatusCode, apiErr.Message)
}
```

## When Surface is unavailable

Anything that is not a real answer from Surface returns an `*surface.UnavailableError`, and `errors.Is(err, surface.ErrUnavailable)` is true: the server could not be reached (refused, reset, DNS), the call's timeout ran out, it answered 500/502/503/504, or it sent a body that is not the expected JSON (an HTML proxy error page, say). `StatusCode` is the HTTP status when there was one. For a 5xx it also wraps a `*surface.SurfaceError`, so existing `errors.As(err, &apiErr)` checks keep matching. A 429 is still a `*RateLimitError` (or `*QuotaExceededError`), and other 4xx errors are unchanged.

Each call has a 60-second budget (`surface.DefaultTimeout`) covering every attempt and wait. Change it with `client.Timeout`; a deadline on the context you pass governs instead:

```go
client.Timeout = 15 * time.Second
```

Within the budget the SDK retries 502, 503, 504 and refused or reset connections, up to 10 times, waiting for the response's `Retry-After` (capped at 10 s) or backing off 1, 2, 4, 8 s. It never starts a wait the budget cannot cover. A 500, a 4xx and a request that hung until the timeout are not retried. Hosted deploys restart the scanner, which answers 503 for about 45 seconds while it warms up, so a scan during a deploy is slower rather than failed. A custom `client.HTTP` is used for every attempt.

`ToolGuard` and `Wrap` fail closed: when Surface is unavailable the tool does not run and the error is returned. `ScanMiddleware` follows `FailOpen` (default open: the request goes through; set it to `false` for a 503).

## Requirements

- Go 1.21+
- No external dependencies
- **Local mode only**: `surface-scanner` binary ([download](https://tendrl.com/docs/surface/scanner-binary/))
