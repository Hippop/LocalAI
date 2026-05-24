package privacygateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServerExportPromptRequiresApprovalForReviewDecision(t *testing.T) {
	srv := NewServer()
	handler := srv.Routes()

	compileBody := `{"user_input":"Help with a public Java question for tom@example.com","need_external":true}`
	compileReq := httptest.NewRequest(http.MethodPost, "/v1/privacy/compile", bytes.NewBufferString(compileBody))
	compileReq.Header.Set("Content-Type", "application/json")
	compileRec := httptest.NewRecorder()
	handler.ServeHTTP(compileRec, compileReq)
	if compileRec.Code != http.StatusOK {
		t.Fatalf("compile status = %d, body = %s", compileRec.Code, compileRec.Body.String())
	}
	var compiled CompileResponse
	if err := json.Unmarshal(compileRec.Body.Bytes(), &compiled); err != nil {
		t.Fatalf("failed to decode compile response: %v", err)
	}
	if compiled.Decision != DecisionReview {
		t.Fatalf("expected review decision, got %s", compiled.Decision)
	}

	exportBody, _ := json.Marshal(ExportPromptRequest{RequestID: compiled.RequestID})
	exportReq := httptest.NewRequest(http.MethodPost, "/v1/privacy/export-prompt", bytes.NewReader(exportBody))
	exportReq.Header.Set("Content-Type", "application/json")
	exportRec := httptest.NewRecorder()
	handler.ServeHTTP(exportRec, exportReq)
	if exportRec.Code != http.StatusForbidden {
		t.Fatalf("expected export before approval to be forbidden, got %d", exportRec.Code)
	}

	approveBody, _ := json.Marshal(ApprovalRequest{RequestID: compiled.RequestID, Approved: true, Reason: "reviewed"})
	approveReq := httptest.NewRequest(http.MethodPost, "/v1/privacy/approve", bytes.NewReader(approveBody))
	approveReq.Header.Set("Content-Type", "application/json")
	approveRec := httptest.NewRecorder()
	handler.ServeHTTP(approveRec, approveReq)
	if approveRec.Code != http.StatusOK {
		t.Fatalf("approval status = %d, body = %s", approveRec.Code, approveRec.Body.String())
	}

	exportReq = httptest.NewRequest(http.MethodPost, "/v1/privacy/export-prompt", bytes.NewReader(exportBody))
	exportReq.Header.Set("Content-Type", "application/json")
	exportRec = httptest.NewRecorder()
	handler.ServeHTTP(exportRec, exportReq)
	if exportRec.Code != http.StatusOK {
		t.Fatalf("expected export after approval to succeed, got %d, body = %s", exportRec.Code, exportRec.Body.String())
	}
	var exported ExportPromptResponse
	if err := json.Unmarshal(exportRec.Body.Bytes(), &exported); err != nil {
		t.Fatalf("failed to decode export response: %v", err)
	}
	if exported.ExternalPrompt == "" {
		t.Fatalf("expected external prompt")
	}
	if bytes.Contains([]byte(exported.ExternalPrompt), []byte("tom@example.com")) {
		t.Fatalf("external prompt leaked raw email: %s", exported.ExternalPrompt)
	}
}
