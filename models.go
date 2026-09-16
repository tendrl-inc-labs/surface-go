package surface

import "encoding/json"

// ---------------------------------------------------------------------------
// Scan response models (camelCase JSON keys)
// ---------------------------------------------------------------------------

// CVEInfo represents a CVE record enriched from scan results.
type CVEInfo struct {
	ID           string   `json:"id"`
	Description  string   `json:"description"`
	References   []string `json:"references,omitempty"`
	CVSSScore    float64  `json:"cvssScore,omitempty"`
	CVSSSeverity string   `json:"cvssSeverity,omitempty"`
	Affected     []string `json:"affected,omitempty"`
}

// IOC represents an indicator of compromise extracted from a file.
type IOC struct {
	Items []string `json:"items,omitempty"`
	Type  string   `json:"type,omitempty"`
}

// SafetyScore represents the unified safety assessment of a scanned file.
type SafetyScore struct {
	Score             int      `json:"score"`
	ThreatLevel       string   `json:"threatLevel"`
	Confidence        string   `json:"confidence"`
	ConfidenceScore   float64  `json:"confidenceScore"`
	ConfidenceReason  string   `json:"confidenceReason"`
	PrimaryThreat     string   `json:"primaryThreat"`
	ThreatSummary     string   `json:"threatSummary"`
	EnginesUsed       []string `json:"enginesUsed"`
	Info              string   `json:"info,omitempty"`
	RecommendedAction string   `json:"recommendedAction"`
	// Coverage says how far detection reaches for this file's format: "full"
	// (dedicated ML model plus every engine — PE, ELF), "partial" (every engine
	// runs, detection varies by language — scripts, documents, archives, and the
	// default), or "minimal" (pattern rules and threat feeds only, no ML model
	// exists — Java bytecode, Mach-O, and archives of .class/.dex). A minimal
	// scan never comes back Clean: safety is capped at 85 (Informational), which
	// still recommends Allow. CoverageNote explains a minimal result.
	Coverage     string    `json:"coverage,omitempty"`
	CoverageNote string    `json:"coverageNote,omitempty"`
	CVEFindings  []CVEInfo `json:"cveFindings,omitempty"`
}

// ArchiveEntry holds the per-file scan result for an entry extracted from an archive.
type ArchiveEntry struct {
	Name       string   `json:"name"`
	Size       int64    `json:"size,omitempty"`
	Verdict    string   `json:"verdict,omitempty"`
	Threats    []string `json:"threats,omitempty"`
	IOCTypes   []string `json:"iocTypes,omitempty"`
	IOCCount   int      `json:"iocCount,omitempty"`
	Skipped    bool     `json:"skipped,omitempty"`
	SkipReason string   `json:"skipReason,omitempty"`
}

// AnalysisIndicator is a single oletools analysis result entry.
type AnalysisIndicator struct {
	Type        string `json:"type"`
	Keyword     string `json:"keyword"`
	Description string `json:"description"`
}

// OletoolsResult holds the oletools Office document analysis output.
type OletoolsResult struct {
	Skipped         bool                `json:"skipped,omitempty"`
	Reason          string              `json:"reason,omitempty"`
	Suspicious      bool                `json:"suspicious"`
	MacrosFound     bool                `json:"macros_found"`
	AutoExec        bool                `json:"auto_exec,omitempty"`
	DDEFound        bool                `json:"dde_found,omitempty"`
	Indicators      []string            `json:"indicators,omitempty"`
	AnalysisResults []AnalysisIndicator `json:"analysis_results,omitempty"`
	Error           string              `json:"error,omitempty"`
}

// StaticAnalysisResult holds static file analysis metadata.
type StaticAnalysisResult struct {
	FileType     string            `json:"fileType"`
	Indicators   []string          `json:"indicators,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	DocumentInfo map[string]string `json:"documentInfo,omitempty"`
}

// ScanResult is the primary scan response returned by the API.
type ScanResult struct {
	RequestID           string                `json:"requestId,omitempty"`
	Name                string                `json:"name"`
	Size                int64                 `json:"size"`
	Hash                string                `json:"hash"`
	ContentType         string                `json:"contentType"`
	SafetyScore         SafetyScore           `json:"safetyScore"`
	ScanTimeMs          int64                 `json:"scanTimeMs"`
	Timestamp           int64                 `json:"timestamp"`
	PayloadIOCs         []IOC                 `json:"payloadIOCs,omitempty"`
	ArchiveEntries      []ArchiveEntry        `json:"archiveEntries,omitempty"`
	ArchiveType         string                `json:"archiveType,omitempty"`
	HasEncryptedEntries bool                  `json:"hasEncryptedEntries,omitempty"`
	OletoolsResult      *OletoolsResult       `json:"oletoolsResult,omitempty"`
	StaticAnalysis      *StaticAnalysisResult `json:"staticAnalysis,omitempty"`
	ScannerVersion      string                `json:"scannerVersion,omitempty"`
	ScannerMode         string                `json:"scannerMode,omitempty"`
	ScanType            string                `json:"scanType,omitempty"` // "file" or "payload"

	// Agentic security engines (payload scans)
	CodeExtraction   json.RawMessage `json:"codeExtraction,omitempty"`
	PromptInjection  json.RawMessage `json:"promptInjection,omitempty"`
	SensitiveData    json.RawMessage `json:"sensitiveData,omitempty"`
	ToolCallAnalysis json.RawMessage `json:"toolCallAnalysis,omitempty"`
	// ActionScreen carries {detected, toolCalls, findings:[{toolName, category,
	// severity, reason, evidence}], contextual} when a tool call was flagged. The
	// reason is also mirrored in SafetyScore.PrimaryThreat.
	ActionScreen json.RawMessage `json:"actionScreen,omitempty"`
}

// DeferredScanResponse is returned when a scan is queued (HTTP 202).
type DeferredScanResponse struct {
	ScanID    string `json:"scanId"`
	RequestID string `json:"requestId"`
	Status    string `json:"status"`
	Message   string `json:"message,omitempty"`
}

// ---------------------------------------------------------------------------
// Account / billing models (snake_case JSON keys)
// ---------------------------------------------------------------------------

// Account represents a Surface user account.
type Account struct {
	ID               string `json:"id"`
	Email            string `json:"email"`
	DisplayName      string `json:"display_name"`
	APIKey           string `json:"api_key,omitempty"`
	AllowedTypes     string `json:"allowed_types"`
	MaxFileSize      int64  `json:"max_file_size"`
	BlockMaliciousIP bool   `json:"block_malicious_ip"`
	PlanID           string `json:"plan_id"`
	MonthlyCredits   int    `json:"monthly_credits"`
	CreditsUsed      int    `json:"credits_used"`
	CreditsResetAt   string `json:"credits_reset_at"`
	IsAdmin          bool   `json:"is_admin"`
	CreatedAt        string `json:"created_at"`
}

// Plan represents a billing plan tier.
type Plan struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	MonthlyCredits int    `json:"monthly_credits"`
	PriceCents     int    `json:"price_cents"`
	MaxFileSizeMB  int    `json:"max_file_size_mb"`
	RateLimit      int    `json:"rate_limit"`
	Description    string `json:"description"`
}

// CreditTier maps file sizes to credit costs.
type CreditTier struct {
	Label    string `json:"label"`
	MaxBytes int64  `json:"max_bytes"`
	Credits  int    `json:"credits"`
}

// DailyVolume holds per-day scan counts for the last 30 days.
type DailyVolume struct {
	Dates  []string `json:"dates"`
	Counts []int    `json:"counts"`
}

// Usage holds the current billing period's scan quota, matching the
// /account/usage response.
type Usage struct {
	ScansUsed      int          `json:"scans_used"`
	MaxScans       int          `json:"max_scans"`
	ScansRemaining int          `json:"scans_remaining"`
	MaxFileSizeMB  int          `json:"max_file_size_mb"`
	PlanTier       string       `json:"plan_tier"`
	ResetAt        string       `json:"reset_at"`
	DailyVolume    *DailyVolume `json:"daily_volume,omitempty"`
}

// ScanProfile defines a reusable scanning configuration.
type ScanProfile struct {
	ID                string                 `json:"id"`
	AccountID         string                 `json:"account_id"`
	Name              string                 `json:"name"`
	IsDefault         bool                   `json:"is_default"`
	AllowedTypes      string                 `json:"allowed_types"`
	MaxFileSize       int64                  `json:"max_file_size"`
	BlockMaliciousIP  bool                   `json:"block_malicious_ip"`
	EnablePayloadScan bool                   `json:"enable_payload_scan"`
	EngineConfig      map[string]interface{} `json:"engine_config"`
	WebhookURL        string                 `json:"webhook_url,omitempty"`
	WebhookAPIKey     string                 `json:"webhook_api_key,omitempty"`
	CreatedAt         string                 `json:"created_at"`
	UpdatedAt         string                 `json:"updated_at"`
}

// APIKey represents an API key linked to a scan profile.
type APIKey struct {
	ID          string `json:"id"`
	AccountID   string `json:"account_id"`
	ProfileID   string `json:"profile_id"`
	KeyID       string `json:"key_id"`
	KeyValue    string `json:"key_value,omitempty"`
	Label       string `json:"label"`
	LastUsedAt  string `json:"last_used_at,omitempty"`
	CreatedAt   string `json:"created_at"`
	ProfileName string `json:"profile_name,omitempty"`
}

// ScanHistoryEntry represents a single scan in the history.
type ScanHistoryEntry struct {
	ID            string `json:"id"`
	AccountID     string `json:"account_id"`
	RequestID     string `json:"request_id"`
	Filename      string `json:"filename"`
	FileHash      string `json:"file_hash"`
	FileSize      int64  `json:"file_size"`
	ContentType   string `json:"content_type"`
	SafetyScore   int    `json:"safety_score"`
	ThreatLevel   string `json:"threat_level"`
	PrimaryThreat string `json:"primary_threat"`
	ScanTimeMs    int64  `json:"scan_time_ms"`
	CreditsUsed   int    `json:"credits_used"`
	ClientIP      string `json:"client_ip"`
	APIKeyID      string `json:"api_key_id,omitempty"`
	Status        string `json:"status"`
	CreatedAt     string `json:"created_at"`
}

// ScanHistoryPage is a paginated list of scan history entries.
type ScanHistoryPage struct {
	Scans   []ScanHistoryEntry `json:"scans"`
	Total   int                `json:"total"`
	Page    int                `json:"page"`
	Limit   int                `json:"limit"`
	HasMore bool               `json:"has_more"`
}

// WebhookFile describes the file in a webhook payload.
type WebhookFile struct {
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	Hash        string `json:"hash"`
	ContentType string `json:"contentType"`
}

// WebhookPayload is the body sent to webhook URLs on scan completion.
type WebhookPayload struct {
	RequestID    string      `json:"requestId"`
	File         WebhookFile `json:"file"`
	ScanResult   ScanResult  `json:"scanResult"`
	ThreatLevel  string      `json:"threatLevel"`
	IsMalicious  bool        `json:"isMalicious"`
	IsSuspicious bool        `json:"isSuspicious"`
	Timestamp    string      `json:"timestamp"`
	ScanDuration int         `json:"scanDuration"`
}
