package main

import (
	"log"
	"net/http"
	"os"

	"github.com/mudler/LocalAI/pkg/privacygateway"
)

func main() {
	addr := os.Getenv("PRIVACY_GATEWAY_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8787"
	}

	srv := privacygateway.NewServer()
	log.Printf("privacy gateway listening on http://%s", addr)
	log.Printf("this service is intended to run in the private zone; keep Local LLM sandbox network disabled")
	if err := http.ListenAndServe(addr, srv.Routes()); err != nil {
		log.Fatal(err)
	}
}
