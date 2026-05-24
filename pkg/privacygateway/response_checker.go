package privacygateway

import (
	"regexp"
	"strings"
)

var dangerousExternalPatterns = []struct {
	name    string
	pattern *regexp.Regexp
}{
	{"ignore_previous_instructions", regexp.MustCompile(`(?i)ignore (all )?(previous|above|system|developer) instructions`)},
	{"exfiltrate_private_data", regexp.MustCompile(`(?i)(send|upload|paste|provide).{0,40}(token|api key|password|cookie|private key|secret|credential|full log|raw log|private data)`)},
	{"disable_safety", regexp.MustCompile(`(?i)(disable|bypass|turn off).{0,30}(safety|policy|redaction|privacy|filter)`)},
	{"tool_injection", regexp.MustCompile(`(?i)(call|invoke|run).{0,30}(tool|function|command|shell|curl|wget)`)},
}

func CheckExternalResponse(req ResponseCheckRequest) ResponseCheckResponse {
	content := strings.TrimSpace(req.Content)
	res := ResponseCheckResponse{
		Allowed:          true,
		RiskLevel:        "low",
		SanitizedContent: content,
		Untrusted:        true,
	}
	for _, p := range dangerousExternalPatterns {
		if p.pattern.MatchString(content) {
			res.Allowed = false
			res.RiskLevel = "high"
			res.Findings = append(res.Findings, p.name)
			res.SanitizedContent = p.pattern.ReplaceAllString(res.SanitizedContent, "[REMOVED_UNTRUSTED_INSTRUCTION]")
		}
	}
	if content == "" {
		res.Allowed = false
		res.RiskLevel = "medium"
		res.Findings = append(res.Findings, "empty_external_response")
	}
	return res
}
