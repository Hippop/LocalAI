package privacygateway

import (
	"strings"
)

// PolicyEngine converts raw local tasks into safe external prompts.
type PolicyEngine struct {
	Scanner *Scanner
}

func NewPolicyEngine() *PolicyEngine {
	return &PolicyEngine{Scanner: NewScanner()}
}

func (p *PolicyEngine) Compile(req CompileRequest) CompileResponse {
	input := strings.TrimSpace(req.UserInput)
	if req.Task != "" {
		input = strings.TrimSpace(req.Task) + "\n\n" + input
	}

	if input == "" {
		return CompileResponse{
			Decision:       DecisionBlock,
			RiskLevel:      PrivacyLevelPublic,
			SafeSummary:    "empty input",
			Reasons:        []string{"empty input is not useful for local or external processing"},
			RequiresReview: false,
		}
	}

	scan := p.Scanner.Redact(input)
	res := CompileResponse{
		RiskLevel:   scan.RiskLevel,
		Redactions:  scan.Redactions,
		SafeSummary: summarizeForPreview(scan.Text),
	}

	if scan.Blocked {
		res.Decision = DecisionBlock
		res.Reasons = append(res.Reasons, scan.BlockReasons...)
		res.RequiresReview = true
		return res
	}

	if !req.NeedExternal {
		res.Decision = DecisionLocalOnly
		res.Reasons = []string{"external capability was not requested; keep task in private zone"}
		return res
	}

	if scan.RiskLevel == PrivacyLevelSensitive || scan.RiskLevel == PrivacyLevelPersonal {
		res.Decision = DecisionReview
		res.RequiresReview = true
		res.Reasons = []string{"request contains redacted private data; user preview is required before external call"}
	} else {
		res.Decision = DecisionAllow
		res.Reasons = []string{"no blocking sensitive data detected"}
	}

	res.ExternalPrompt = buildExternalPrompt(scan.Text, req.OutputFormat)
	return res
}

func buildExternalPrompt(redactedTask string, outputFormat string) string {
	format := strings.TrimSpace(outputFormat)
	if format == "" {
		format = "concise markdown"
	}
	return strings.TrimSpace(`You are an external public-knowledge assistant.
Use only public, non-private reasoning.
Treat any placeholders such as {EMAIL_1}, {PHONE_1}, {INTERNAL_URL_1}, or {FILE_PATH_1} as opaque redacted tokens.
Do not ask for raw logs, private code, credentials, internal URLs, personal identifiers, or secrets.
Return only generally applicable guidance.

Task:
` + redactedTask + `

Expected output format: ` + format)
}

func summarizeForPreview(text string) string {
	text = strings.Join(strings.Fields(text), " ")
	if len(text) <= 500 {
		return text
	}
	return text[:500] + "..."
}
