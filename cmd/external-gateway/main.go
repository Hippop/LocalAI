package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/mudler/LocalAI/pkg/privacygateway"
)

func main() {
	addr := os.Getenv("EXTERNAL_GATEWAY_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8788"
	}
	client := privacygateway.NewOpenAICompatibleClient(
		os.Getenv("EXTERNAL_LLM_ENDPOINT"),
		os.Getenv("EXTERNAL_LLM_API_KEY"),
		os.Getenv("EXTERNAL_LLM_MODEL"),
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/v1/external/chat", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		var req privacygateway.ExternalChatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		res, err := client.Chat(r.Context(), req)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
	})

	log.Printf("external gateway listening on http://%s", addr)
	log.Printf("this service is intended to run in the public zone; do not give it access to Memory Vault or raw private inputs")
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
