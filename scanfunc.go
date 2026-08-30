package surface

import (
	"context"
	"fmt"
)

// ScanFunc wraps a handler so a file is scanned before it runs. The returned
// function takes a file path; the handler receives the accepted *ScanResult.
// If the scan matches the Reject policy in opts, a *MaliciousFileError is
// returned and the handler is never called.
//
// It is the imperative-Go analogue of the Python SDK's @scan decorator: the
// caller hands over a file, the handler receives a result, and rejection is one
// option away.
//
//	process := surface.ScanFunc(client, &surface.ScanFileOptions{
//	    Reject: []string{"Malicious", "Suspicious"},
//	}, func(r *surface.ScanResult) error {
//	    return store(r) // only runs for accepted files
//	})
//	if err := process(ctx, "upload.pdf"); err != nil {
//	    // *MaliciousFileError when the file was rejected
//	}
func ScanFunc(client *Client, opts *ScanFileOptions, handler func(*ScanResult) error) func(ctx context.Context, filePath string) error {
	return func(ctx context.Context, filePath string) error {
		res, err := client.ScanFile(ctx, filePath, opts)
		if err != nil {
			return err
		}
		if res.ScanResult == nil {
			return fmt.Errorf("surface: ScanFunc does not support deferred scans")
		}
		return handler(res.ScanResult)
	}
}

// ScanBytesFunc is ScanFunc for in-memory data — the shape you want inside an
// HTTP handler, where you already hold the bytes. The returned function takes a
// filename hint and the raw bytes; the handler receives the accepted result.
// Rejection returns a *MaliciousFileError, same as ScanFunc.
func ScanBytesFunc(client *Client, opts *ScanFileOptions, handler func(*ScanResult) error) func(ctx context.Context, filename string, data []byte) error {
	return func(ctx context.Context, filename string, data []byte) error {
		res, err := client.ScanBytes(ctx, filename, data, opts)
		if err != nil {
			return err
		}
		if res.ScanResult == nil {
			return fmt.Errorf("surface: ScanBytesFunc does not support deferred scans")
		}
		return handler(res.ScanResult)
	}
}
