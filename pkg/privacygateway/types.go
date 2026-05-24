package privacygateway

import "time"

// PrivacyLevel classifies the maximum sensitivity detected in a request.
type PrivacyLevel string

const (
	PrivacyLevelPublic     PrivacyLevel = "P0_public"
	PrivacyLevelPreference PrivacyLevel = "P1_preference"
	PrivacyLevelPersonal   PrivacyLevel = "P2_personal"
	PrivacyLevelSensitive  PrivacyLevel = "P3_sensitive"
	PrivacyLevelSecret     PrivacyLevel = "P4_secret"
)

// Decision is the policy outcome for a request that may leave the private zone.
type Decision string

const (
	DecisionAllow     Decision = "allow"
	DecisionReview    Decision = "review"
	DecisionBlock     Decision = "block"
	DecisionLocalOnly Decision = "local_only"
)

// Redaction describes one sanitized finding without storing the raw secret.
type Redaction struct {
	Type        string       `json:"type"`
	Placeholder string       `json:"placeholder,omitempty"`
	Count       int          `json:"count"`
	Level       PrivacyLevel `json:"level"`
	Action      string       `json:"action"`
}

// CompileRequest is the input to the privacy compiler. UserInput is allowed to
// contain raw private information because this endpoint is intended to run only
// inside the no-network private zone.
type CompileRequest struct {
	UserInput     string   `json:"user_input"`
	Task          string   `json:"task,omitempty"`
	NeedExternal  bool     `json:"need_external"`
	AllowedLevels []string `json:"allowed_levels,omitempty"`
	OutputFormat  string   `json:"output_format,omitempty"`
	DryRun        bool     `json:"dry_run"`
}

// CompileResponse contains only sanitized information that may be shown in an
// external-call preview. It intentionally never returns raw private findings.
type CompileResponse struct {
	Decision       Decision     `json:"decision"`
	RiskLevel      PrivacyLevel `json:"risk_level"`
	ExternalPrompt string       `json:"external_prompt,omitempty"`
	SafeSummary    string       `json:"safe_summary"`
	Redactions     []Redaction  `json:"redactions"`
	Reasons        []string     `json:"reasons"`
	RequiresReview bool         `json:"requires_review"`
}

// ResponseCheckRequest checks untrusted external model/search output before it
// is allowed back into the local model context.
type ResponseCheckRequest struct {
	Content string `json:"content"`
}

// ResponseCheckResponse reports whether external content is safe enough to use
// as reference data. The content remains untrusted even when Allowed is true.
type ResponseCheckResponse struct {
	Allowed          bool     `json:"allowed"`
	RiskLevel        string   `json:"risk_level"`
	Findings         []string `json:"findings"`
	SanitizedContent string   `json:"sanitized_content"`
	Untrusted        bool     `json:"untrusted"`
}

// AuditEvent stores a privacy-preserving record of a gateway decision.
type AuditEvent struct {
	Event             string            `json:"event"`
	Time              time.Time         `json:"time"`
	Decision          Decision          `json:"decision"`
	RiskLevel         PrivacyLevel      `json:"risk_level"`
	RedactionSummary  map[string]int    `json:"redaction_summary"`
	RawContentLogged  bool              `json:"raw_private_content_logged"`
	AdditionalContext map[string]string `json:"additional_context,omitempty"`
}
