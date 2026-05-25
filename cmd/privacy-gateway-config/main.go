package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/mudler/LocalAI/pkg/privacygateway"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8787", "listen address")
	policyFile := flag.String("policy-file", "", "optional JSON policy config file")
	vaultFile := flag.String("vault-file", "", "optional encrypted vault file")
	vaultCode := flag.String("vault-code", "", "optional local vault unlock code")
	flag.Parse()

	srv := privacygateway.NewServer()
	if *policyFile != "" {
		cfg, err := privacygateway.LoadConfig(*policyFile)
		if err != nil {
			log.Fatalf("failed to load policy config: %v", err)
		}
		policy, err := privacygateway.NewPolicyEngineWithConfig(cfg)
		if err != nil {
			log.Fatalf("failed to build policy engine: %v", err)
		}
		srv.Policy = policy
		log.Printf("policy config loaded from %s", *policyFile)
	}
	if *vaultFile != "" || *vaultCode != "" {
		vault, err := privacygateway.NewEncryptedMemoryVault(*vaultFile, *vaultCode)
		if err != nil {
			log.Fatalf("failed to configure encrypted vault: %v", err)
		}
		srv.Vault = vault
		log.Printf("encrypted vault enabled at %s", *vaultFile)
	}

	log.Printf("configurable privacy gateway listening on http://%s", *addr)
	if err := http.ListenAndServe(*addr, srv.Routes()); err != nil {
		log.Fatal(err)
	}
}
