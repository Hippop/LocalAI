package privacygateway

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
)

type Server struct {
	Policy *PolicyEngine
	Store  *SessionStore
	Vault  *EncryptedMemoryVault
	Audit  func(AuditEvent)
}

func NewServer() *Server {
	return &Server{
		Policy: NewPolicyEngine(),
		Store:  NewSessionStore(),
		Audit: func(event AuditEvent) {
			b, _ := json.Marshal(event)
			log.Printf("privacy_audit=%s", string(b))
		},
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/v1/privacy/compile", s.handleCompile)
	mux.HandleFunc("/v1/privacy/approve", s.handleApprove)
	mux.HandleFunc("/v1/privacy/rehydrate", s.handleRehydrate)
	mux.HandleFunc("/v1/privacy/external/response-check", s.handleResponseCheck)
	mux.HandleFunc("/v1/privacy/vault/put", s.handleVaultPut)
	mux.HandleFunc("/v1/privacy/vault/get", s.handleVaultGet)
	mux.HandleFunc("/v1/privacy/vault/list", s.handleVaultList)
	mux.HandleFunc("/v1/privacy/vault/delete", s.handleVaultDelete)
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleCompile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req CompileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	res, bindings := s.Policy.CompileWithBindings(req)
	session, err := s.Store.Put(res, bindings)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create privacy session"})
		return
	}
	res = session.Response
	if s.Audit != nil {
		s.Audit(NewAuditEvent("privacy_compile", res))
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req ApprovalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	session, err := s.Store.Approve(req.RequestID, req.Approved, req.Reason)
	if errors.Is(err, ErrSessionNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "privacy session not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to update approval"})
		return
	}
	if s.Audit != nil {
		event := NewAuditEvent("privacy_approval", session.Response)
		event.AdditionalContext = map[string]string{"approved": boolString(req.Approved)}
		s.Audit(event)
	}
	writeJSON(w, http.StatusOK, ApprovalResponse{
		RequestID: session.RequestID,
		Approved:  session.Approved,
		Decision:  session.Response.Decision,
	})
}

func (s *Server) handleRehydrate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req RehydrateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	session, ok := s.Store.Get(req.RequestID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "privacy session not found"})
		return
	}
	if session.Response.Decision == DecisionBlock {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "blocked sessions cannot be rehydrated"})
		return
	}
	if session.Response.Decision == DecisionReview && !session.Approved {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "user approval is required before rehydration"})
		return
	}
	checked := CheckExternalResponse(ResponseCheckRequest{Content: req.ExternalContent})
	if !checked.Allowed {
		writeJSON(w, http.StatusForbidden, checked)
		return
	}
	content := Rehydrate(checked.SanitizedContent, session.Bindings)
	warnings := []string{"external content was treated as untrusted reference data before local rehydration"}
	if s.Audit != nil {
		s.Audit(NewAuditEvent("privacy_rehydrate", session.Response))
	}
	writeJSON(w, http.StatusOK, RehydrateResponse{
		RequestID: session.RequestID,
		Content:   content,
		Warnings:  warnings,
	})
}

func (s *Server) handleResponseCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req ResponseCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	writeJSON(w, http.StatusOK, CheckExternalResponse(req))
}

func (s *Server) handleVaultPut(w http.ResponseWriter, r *http.Request) {
	if !s.requireVault(w) {
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req VaultPutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	record, err := s.Vault.Put(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if s.Audit != nil {
		s.Audit(AuditEvent{Event: "vault_put", RawContentLogged: false, AdditionalContext: map[string]string{"key": record.Key}})
	}
	record.Value = ""
	writeJSON(w, http.StatusOK, record)
}

func (s *Server) handleVaultGet(w http.ResponseWriter, r *http.Request) {
	if !s.requireVault(w) {
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req VaultGetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	record, err := s.Vault.Get(req.Key)
	if errors.Is(err, ErrVaultRecordNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "vault record not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to read vault record"})
		return
	}
	if s.Audit != nil {
		s.Audit(AuditEvent{Event: "vault_get", RawContentLogged: false, AdditionalContext: map[string]string{"key": record.Key}})
	}
	writeJSON(w, http.StatusOK, record)
}

func (s *Server) handleVaultList(w http.ResponseWriter, r *http.Request) {
	if !s.requireVault(w) {
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	records, err := s.Vault.List()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list vault"})
		return
	}
	writeJSON(w, http.StatusOK, VaultListResponse{Records: records})
}

func (s *Server) handleVaultDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requireVault(w) {
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req VaultDeleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	if err := s.Vault.Delete(req.Key); errors.Is(err, ErrVaultRecordNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "vault record not found"})
		return
	} else if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to delete vault record"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) requireVault(w http.ResponseWriter) bool {
	if s.Vault == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "memory vault is not configured"})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}
