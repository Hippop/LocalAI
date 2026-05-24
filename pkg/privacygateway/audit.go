package privacygateway

import "time"

func NewAuditEvent(event string, res CompileResponse) AuditEvent {
	summary := map[string]int{}
	for _, r := range res.Redactions {
		summary[r.Type] += r.Count
	}
	return AuditEvent{
		Event:            event,
		Time:             time.Now().UTC(),
		Decision:         res.Decision,
		RiskLevel:        res.RiskLevel,
		RedactionSummary: summary,
		RawContentLogged: false,
	}
}
