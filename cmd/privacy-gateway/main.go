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
	vaultPath := os.Getenv("PRIVACY_VAULT_PATH")
	vaultPassphrase := os.Getenv("PRIVACY_VAULT_PASSPHRASE")
	if vaultPath != "" || vaultPassphrase != "" {
		vault, err := privacygateway.NewEncryptedMemoryVault(vaultPath, vaultPassphrase)
		if err != nil {
			log.Fatalf("failed to configure encrypted memory vault: %v", err)
		}
		srv.Vault = vault
		log.Printf("encrypted memory vault enabled at %s", vaultPath)
	} else {
		log.Printf("encrypted memory vault disabled; set PRIVACY_VAULT_PATH and PRIVACY_VAULT_PASSPHRASE to enable it")
	}

	log.Printf("privacy gateway listening on http://%s", addr)
	log.Printf("this service is intended to run in the private zone; keep Local LLM sandbox network disabled")
	if err := http.ListenAndServe(addr, srv.Routes()); err != nil {
		log.Fatal(err)
	}
}
