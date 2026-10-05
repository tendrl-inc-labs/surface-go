package surface

import "testing"

// With Reject unset the middleware rejects whatever Surface recommends
// blocking, Risky included. It used to reject nothing. An empty non-nil slice
// still means "reject nothing".
func TestMiddlewareDefaultRejectsBlock(t *testing.T) {
	cases := []struct {
		opts *MiddlewareOptions
		s    SafetyScore
		want bool
	}{
		{nil, SafetyScore{ThreatLevel: "Malicious", RecommendedAction: "Block"}, true},
		{&MiddlewareOptions{}, SafetyScore{ThreatLevel: "Risky", RecommendedAction: "Block"}, true},
		{&MiddlewareOptions{}, SafetyScore{ThreatLevel: "Suspicious", RecommendedAction: "Review"}, false},
		{&MiddlewareOptions{Reject: []string{}}, SafetyScore{ThreatLevel: "Malicious", RecommendedAction: "Block"}, false},
		{&MiddlewareOptions{Reject: []string{"Suspicious"}}, SafetyScore{ThreatLevel: "Suspicious", RecommendedAction: "Review"}, true},
	}
	for i, c := range cases {
		if got := c.opts.shouldReject(c.s); got != c.want {
			t.Errorf("case %d: shouldReject(%+v) = %v, want %v", i, c.s, got, c.want)
		}
	}
}
