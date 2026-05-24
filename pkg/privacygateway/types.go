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

// PlaceholderBinding is local-only state used by the rehydration engine. Raw
// values must never be returned by API handlers or sent to the public zone.
type PlaceholderBinding struct {
	Placeholder string       `json:"placeholder"`
	RawValue    string       `json:"-"`
	Type        string       `json:"type"`
	Level       PrivacyLevel `json:"level"`
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
	RequestID      string       `json:"request_id,omitempty"`
	Decision       Decision     `json:"decision"`
	RiskLevel      PrivacyLevel `json:"risk_level"`
	ExternalPrompt string       `json:"external_prompt,omitempty"`
	SafeSummary    string       `json:"safe_summary"`
	Redactions     []Redaction  `json:"redactions"`
	Reasons        []string     `json:"reasons"`
	RequiresReview bool         `json:"requires_review"`
}

// ApprovalRequest records explicit user approval for a review decision.
type ApprovalRequest struct {
	RequestID string `json:"request_id"`
	Approved  bool   `json:"approved"`
	Reason    string `json:"reason,omitempty"`
}

// ApprovalResponse is returned after a user approval decision is stored.
type ApprovalResponse struct {
	RequestID string   `json:"request_id"`
	Approved  bool     `json:"approved"`
	Decision  Decision `json:"decision"`
}

// ExportPromptRequest asks the private gateway to release a sanitized external
// prompt after policy and approval gates are satisfied.
type ExportPromptRequest struct {
	RequestID string `json:"request_id"`
}

// ExportPromptResponse contains a sanitized prompt that may be sent to the
// public-zone external gateway. It must never contain raw private values.
type ExportPromptResponse struct {
	RequestID      string       `json:"request_id"`
	ExternalPrompt string       `json:"external_prompt"`
	Decision       Decision     `json:"decision"`
	RiskLevel      PrivacyLevel `json:"risk_level"`
}

// RehydrateRequest replaces local-only placeholders in external output after
// the response checker has accepted the content as untrusted reference data.
type RehydrateRequest struct {
	RequestID       string `json:"request_id"`
	ExternalContent string `json:"external_content"`
}

// RehydrateResponse is safe to show only to the local user. It may contain raw
// private data after placeholders are restored.
type RehydrateResponse struct {
	RequestID string   `json:"request_id"`
	Content   string   `json:"content"`
	Warnings  []string `json:"warnings,omitempty"`
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
	RequestID         string            `json:"request_id,omitempty"`
	Decision          Decision          `json:"decision"`
	RiskLevel         PrivacyLevel      `json:"risk_level"`
	RedactionSummary  map[string]int    `json:"redaction_summary"`
	RawContentLogged  bool              `json:"raw_private_content_logged"`
	AdditionalContext map[string]string `json:"additional_context,omitempty"`
}
