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

	log.Printf("configurable privacy gateway listening on http://%s", *addr)
	if err := http.ListenAndServe(*addr, srv.Routes()); err != nil {
		log.Fatal(err)
	}
}
