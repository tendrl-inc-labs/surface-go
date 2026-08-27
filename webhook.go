package surface

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// VerifyWebhookSignature verifies an HMAC-SHA256 webhook signature.
// signatureHeader should be the value of the X-Surface-Signature header
// in the format "sha256=<hex>".
func VerifyWebhookSignature(body []byte, secret string, signatureHeader string) bool {
	if !strings.HasPrefix(signatureHeader, "sha256=") {
		return false
	}
	expected := signatureHeader[len("sha256="):]

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	computed := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(computed), []byte(expected))
}
