package privacygateway

import "testing"

func TestSessionApprovalAndRehydration(t *testing.T) {
	engine := NewPolicyEngine()
	res, bindings := engine.CompileWithBindings(CompileRequest{
		UserInput:    "Write a short message to tom@example.com about a public Java 21 question.",
		NeedExternal: true,
	})
	if res.Decision != DecisionReview {
		t.Fatalf("expected review decision, got %s", res.Decision)
	}
	store := NewSessionStore()
	session, err := store.Put(res, bindings)
	if err != nil {
		t.Fatalf("failed to store session: %v", err)
	}
	if session.RequestID == "" || session.Response.RequestID == "" {
		t.Fatalf("expected request id to be assigned")
	}
	if session.Approved {
		t.Fatalf("new review session should not be approved by default")
	}
	approved, err := store.Approve(session.RequestID, true, "user reviewed safe prompt")
	if err != nil {
		t.Fatalf("approval failed: %v", err)
	}
	if !approved.Approved {
		t.Fatalf("expected approved session")
	}
	content := Rehydrate("Send this to {EMAIL_1}", approved.Bindings)
	if content != "Send this to tom@example.com" {
		t.Fatalf("unexpected rehydrated content: %s", content)
	}
}

func TestRehydrateDoesNotInventMissingBindings(t *testing.T) {
	content := Rehydrate("Hello {EMAIL_2}", []PlaceholderBinding{{Placeholder: "{EMAIL_1}", RawValue: "tom@example.com"}})
	if content != "Hello {EMAIL_2}" {
		t.Fatalf("unexpected replacement: %s", content)
	}
}
