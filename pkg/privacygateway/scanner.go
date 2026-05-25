package privacygateway

import (
	"regexp"
	"sort"
	"strings"
)

type detector struct {
	name        string
	level       PrivacyLevel
	action      string
	placeholder string
	pattern     *regexp.Regexp
	block       bool
}

// Scanner detects sensitive content using deterministic rules. It is not meant
// to be the only defense; it is the final mandatory gate before an external call.
type Scanner struct {
	detectors []detector
}

func NewScanner() *Scanner {
	return &Scanner{detectors: []detector{
		// Blockers must run before masking detectors. Otherwise a long secret-like
		// digit sequence could be partially masked as a phone number before the
		// secret detector has a chance to block it.
		{name: "private_key", level: PrivacyLevelSecret, action: "block", block: true, pattern: regexp.MustCompile(`(?is)-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`)},
		{name: "api_key_or_token", level: PrivacyLevelSecret, action: "block", block: true, pattern: regexp.MustCompile(`(?i)\b(?:api[_-]?key|secret|token|access[_-]?token|refresh[_-]?token|password|passwd|pwd)\b\s*[:=]\s*['\"]?[^\s'\"]{8,}`)},
		{name: "bearer_token", level: PrivacyLevelSecret, action: "block", block: true, pattern: regexp.MustCompile(`(?i)\bbearer\s+[a-z0-9._~+/=-]{16,}`)},
		{name: "id_card_like", level: PrivacyLevelSecret, action: "block", block: true, pattern: regexp.MustCompile(`\b\d{15}(?:\d{2}[0-9Xx])?\b`)},
		{name: "credit_card_like", level: PrivacyLevelSecret, action: "block", block: true, pattern: regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)},
		{name: "email", level: PrivacyLevelPersonal, action: "placeholder", placeholder: "EMAIL", pattern: regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)},
		{name: "phone", level: PrivacyLevelPersonal, action: "placeholder", placeholder: "PHONE", pattern: regexp.MustCompile(`(?m)(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)?\d{3,4}[\s.-]?\d{4}\b`)},
		{name: "internal_url", level: PrivacyLevelSensitive, action: "placeholder", placeholder: "INTERNAL_URL", pattern: regexp.MustCompile(`(?i)\bhttps?://(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|[^\s/]*\.(?:local|internal|intranet|corp))(?:/[^\s]*)?`)},
		{name: "file_path", level: PrivacyLevelSensitive, action: "placeholder", placeholder: "FILE_PATH", pattern: regexp.MustCompile(`(?m)(?:/[A-Za-z0-9._\-]+){2,}|[A-Za-z]:\\(?:[^\\\r\n]+\\?){2,}`)},
	}}
}

type ScanResult struct {
	Text         string
	Redactions   []Redaction
	Bindings     []PlaceholderBinding
	RiskLevel    PrivacyLevel
	Blocked      bool
	BlockReasons []string
}

func (s *Scanner) Redact(input string) ScanResult {
	result := ScanResult{Text: input, RiskLevel: PrivacyLevelPublic}
	for _, d := range s.detectors {
		matches := d.pattern.FindAllStringIndex(result.Text, -1)
		if len(matches) == 0 {
			continue
		}
		result.RiskLevel = maxLevel(result.RiskLevel, d.level)
		redaction := Redaction{Type: d.name, Count: len(matches), Level: d.level, Action: d.action}
		if d.block {
			result.Blocked = true
			result.BlockReasons = append(result.BlockReasons, "blocked "+d.name)
			redaction.Action = "block"
		} else {
			placeholderPrefix := d.placeholder
			if placeholderPrefix == "" {
				placeholderPrefix = strings.ToUpper(d.name)
			}
			redaction.Placeholder = "{" + placeholderPrefix + "}"
			var bindings []PlaceholderBinding
			result.Text, bindings = replaceMatches(result.Text, d.pattern, placeholderPrefix, d)
			result.Bindings = append(result.Bindings, bindings...)
		}
		result.Redactions = append(result.Redactions, redaction)
	}
	result.Redactions = mergeRedactions(result.Redactions)
	return result
}

func replaceMatches(input string, pattern *regexp.Regexp, placeholderPrefix string, d detector) (string, []PlaceholderBinding) {
	seen := map[string]string{}
	counter := 0
	bindings := []PlaceholderBinding{}
	output := pattern.ReplaceAllStringFunc(input, func(match string) string {
		if ph, ok := seen[match]; ok {
			return ph
		}
		counter++
		ph := "{" + placeholderPrefix + "_" + itoa(counter) + "}"
		seen[match] = ph
		bindings = append(bindings, PlaceholderBinding{
			Placeholder: ph,
			RawValue:    match,
			Type:        d.name,
			Level:       d.level,
		})
		return ph
	})
	return output, bindings
}

func mergeRedactions(items []Redaction) []Redaction {
	m := map[string]Redaction{}
	for _, item := range items {
		key := item.Type + "|" + string(item.Level) + "|" + item.Action
		existing := m[key]
		existing.Type = item.Type
		existing.Level = item.Level
		existing.Action = item.Action
		existing.Count += item.Count
		if existing.Placeholder == "" {
			existing.Placeholder = item.Placeholder
		}
		m[key] = existing
	}
	out := make([]Redaction, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

func maxLevel(a, b PrivacyLevel) PrivacyLevel {
	if levelRank(b) > levelRank(a) {
		return b
	}
	return a
}

func levelRank(level PrivacyLevel) int {
	switch level {
	case PrivacyLevelSecret:
		return 4
	case PrivacyLevelSensitive:
		return 3
	case PrivacyLevelPersonal:
		return 2
	case PrivacyLevelPreference:
		return 1
	default:
		return 0
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
