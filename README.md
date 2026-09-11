# Surface Go SDK

Go client for the [Surface](https://tendrl.com/products/surface) file scanning API. Supports two modes: **API mode** (remote scanning via the Surface API) and **Local mode** (scan files locally using the scanner binary). Zero external dependencies — uses only the standard library.

## Installation

```bash
go get github.com/tendrl-inc-labs/surface-go
```

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
    client, err := surface.NewClient("sfk_your_token_here")
    if err != nil {
        log.Fatal(err)
    }

    result, err := client.ScanFile(context.Background(), "suspicious.exe", nil)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(result.ScanResult.SafetyScore.ThreatLevel)
}
```

Prefer not to check the verdict by hand? `ScanFunc` wraps the client: hand it a file, your handler receives the `*ScanResult`, and files matching `Reject` never reach it (`ScanBytesFunc` is the same for in-memory data).

```go
process := surface.ScanFunc(client, &surface.ScanFileOptions{
    Reject: []string{"Block"}, // refuse what the scanner recommends blocking
}, func(r *surface.ScanResult) error {
    // Clean, Informational, Suspicious, or Malicious
    fmt.Println(r.SafetyScore.ThreatLevel)
    return nil // runs only for accepted files
})

if err := process(context.Background(), "suspicious.exe"); err != nil {
    log.Fatal(err) // *MaliciousFileError when the file was rejected
}
```

`Reject` matches the recommended action (`"Block"`, `"Review"`) or the threat level (`"Malicious"`, `"Suspicious"`), case-insensitively, in both API and local mode.

## Quick Start — Local Mode

Requires the `surface-scanner` binary installed or available on `$PATH`.

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

    result, err := client.ScanFile(context.Background(), "suspicious.exe", nil)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(result.ScanResult.SafetyScore.ThreatLevel)
}
```

With custom scanner path:

```go
client, err := surface.NewLocalClient(&surface.LocalConfig{
    APIKey:      "sfk_your_token_here",
    ScannerPath: "/usr/local/bin/surface-scanner",
    DataDir:     "/var/lib/surface/data",
})
```

The local client starts the scanner in daemon mode on a random port. It starts automatically on the first scan and stops when you call `Close()`. The same `ScanFile`, `ScanBytes`, `ScanReader`, and `ScanFiles` methods work in both modes.

## Authentication

`NewClient` checks for an API key in this order:

1. `apiKey` parameter passed to `NewClient()`
2. `SURFACE_KEY` environment variable

```bash
export SURFACE_KEY="sfk_your_token_here"
```

If neither is set, `NewClient` returns an `*AuthenticationError`.

## Scanning Files

```go
ctx := context.Background()

// From file path, bytes, or io.Reader
fromPath, err := client.ScanFile(ctx, "malware.exe", nil)
fromBytes, err := client.ScanBytes(ctx, "sample.bin", data, nil)
fromReader, err := client.ScanReader(ctx, "upload.zip", reader, nil)

// Reject malicious files — returns *MaliciousFileError
checked, err := client.ScanFile(ctx, "upload.exe", &surface.ScanFileOptions{
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

## Agentic Security

Payload scan results may include additional threat detection from agentic security engines. These fields are present on `ScanResult` as `json.RawMessage` (decode as needed):

- **`CodeExtraction`** — embedded code blocks found in the payload (scripts, shell commands)
- **`PromptInjection`** — prompt injection attempts detected in text content
- **`SensitiveData`** — exposed credentials, API keys, or PII
- **`ToolCallAnalysis`** — suspicious tool/function call patterns

```go
if result.ScanResult.PromptInjection != nil {
    fmt.Println("Prompt injection detected in payload")
}
```

## Middleware

`ScanMiddleware` wraps any `http.Handler` to automatically scan request bodies before they reach your handler. Requests with threats matching the `Reject` list receive a 403 response.

```go
mux := http.NewServeMux()
mux.HandleFunc("/api/data", dataHandler)

// FailOpen is a *bool so that "unset" (nil, the default) is distinguishable
// from an explicit false. Unset means fail open.
failOpen := true

protected := surface.ScanMiddleware(client, mux, &surface.MiddlewareOptions{
    Reject:   []string{"Malicious", "Suspicious"},
    Label:    "api-gateway",
    FailOpen: &failOpen, // allow requests through if scanning fails
})

log.Fatal(http.ListenAndServe(":8080", protected))
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
paths := []string{"file1.exe", "file2.pdf", "file3.zip"}
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

## Scan Profiles

```go
profiles, err := client.ListProfiles(ctx)

profile, err := client.CreateProfile(ctx, map[string]interface{}{
    "name":          "Images Only",
    "allowed_types": "jpg,jpeg,png,gif,webp",
})

_, err = client.UpdateProfile(ctx, profile.ID, map[string]interface{}{
    "name": "Images & PDFs",
})

err = client.DeleteProfile(ctx, profile.ID)
```

### Profile Engine Configuration

Control which engines run and configure per-engine settings via `engine_config`:

```go
profile, err := client.CreateProfile(ctx, map[string]interface{}{
    "name":                "Agentic Intake",
    "allowed_types":       "json,txt,md",
    "enable_payload_scan": true,
    "engine_config": map[string]interface{}{
        "prompt_injection": map[string]interface{}{"enabled": true},
        "sensitive_data":   map[string]interface{}{"enabled": true, "mask_output": true},
        "ml":               map[string]interface{}{"threshold": 0.8},
    },
})
```

Built-in profiles are provisioned server-side; see the [scan profiles documentation](https://tendrl.com/docs/surface/scan-profiles/) for what a new account starts with.

## API Keys

```go
keys, err := client.ListAPIKeys(ctx)
newKey, err := client.CreateAPIKey(ctx, "Production", profileID)
err = client.DeleteAPIKey(ctx, keyID)
```

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

Errors are returned as typed structs you can assert on:

```go
result, err := client.ScanFile(ctx, "test.exe", nil)
if err != nil {
    switch err.(type) {
    case *surface.QuotaExceededError:
        fmt.Println("Monthly scan quota exhausted")
    case *surface.RateLimitError:
        fmt.Println("Rate limit hit")
    case *surface.AuthenticationError:
        fmt.Println("Invalid API key")
    case *surface.NotFoundError:
        fmt.Println("Resource not found")
    case *surface.SurfaceError:
        e := err.(*surface.SurfaceError)
        fmt.Printf("API error %d: %s\n", e.StatusCode, e.Message)
    }
}
```

## Requirements

- Go 1.21+
- No external dependencies
- **Local mode only**: `surface-scanner` binary ([download](https://tendrl.com/docs/surface/scanner-binary/))
