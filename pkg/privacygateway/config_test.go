package privacygateway

import "testing"

func TestConfigBlockKeyword(t *testing.T) {
	engine, err := NewPolicyEngineWithConfig(Config{BlockKeywords: []string{"Apollo-X"}})
	if err != nil {
		t.Fatalf("failed to build engine: %v", err)
	}
	res := engine.Compile(CompileRequest{UserInput: "Research Apollo-X troubleshooting", NeedExternal: true})
	if res.Decision != DecisionBlock {
		t.Fatalf("expected block decision, got %s", res.Decision)
	}
}

func TestConfigMaskKeyword(t *testing.T) {
	engine, err := NewPolicyEngineWithConfig(Config{MaskKeywords: []string{"Apollo-X"}})
	if err != nil {
		t.Fatalf("failed to build engine: %v", err)
	}
	res := engine.Compile(CompileRequest{UserInput: "Research Apollo-X troubleshooting", NeedExternal: true})
	if res.Decision != DecisionReview {
		t.Fatalf("expected review decision, got %s", res.Decision)
	}
	if contains(res.ExternalPrompt, "Apollo-X") {
		t.Fatalf("external prompt leaked custom masked keyword: %s", res.ExternalPrompt)
	}
}

func TestCustomDetector(t *testing.T) {
	engine, err := NewPolicyEngineWithConfig(Config{CustomDetectors: []CustomDetector{{
		Name:        "ticket_id",
		Pattern:     `TICKET-[0-9]+`,
		Level:       "P3",
		Action:      "placeholder",
		Placeholder: "TICKET",
	}}})
	if err != nil {
		t.Fatalf("failed to build engine: %v", err)
	}
	res := engine.Compile(CompileRequest{UserInput: "Summarize TICKET-12345", NeedExternal: true})
	if contains(res.ExternalPrompt, "TICKET-12345") {
		t.Fatalf("external prompt leaked custom detector value: %s", res.ExternalPrompt)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
