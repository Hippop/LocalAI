package privacygateway

import (
	"encoding/json"
	"log"
	"net/http"
)

type Server struct {
	Policy *PolicyEngine
	Audit  func(AuditEvent)
}

func NewServer() *Server {
	return &Server{
		Policy: NewPolicyEngine(),
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
	mux.HandleFunc("/v1/privacy/external/response-check", s.handleResponseCheck)
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
	res := s.Policy.Compile(req)
	if s.Audit != nil {
		s.Audit(NewAuditEvent("privacy_compile", res))
	}
	writeJSON(w, http.StatusOK, res)
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

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
