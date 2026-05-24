package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

type checkResult struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Details string `json:"details,omitempty"`
}

type report struct {
	Status string        `json:"status"`
	Checks []checkResult `json:"checks"`
}

func main() {
	checks := []checkResult{
		checkProxyEnv(),
		checkDNS(),
		checkOutboundTCP(),
		checkLocalhostTCP(),
	}
	status := "pass"
	for _, c := range checks {
		if !c.Passed {
			status = "fail"
			break
		}
	}
	out := report{Status: status, Checks: checks}
	_ = json.NewEncoder(os.Stdout).Encode(out)
	if status != "pass" {
		os.Exit(1)
	}
}

func checkProxyEnv() checkResult {
	vars := []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"}
	found := []string{}
	for _, name := range vars {
		if os.Getenv(name) != "" {
			found = append(found, name)
		}
	}
	if len(found) > 0 {
		return checkResult{Name: "proxy_environment", Passed: false, Details: fmt.Sprintf("proxy variables are set: %v", found)}
	}
	return checkResult{Name: "proxy_environment", Passed: true, Details: "no proxy environment variables detected"}
}

func checkDNS() checkResult {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := net.DefaultResolver.LookupHost(ctx, "example.com")
	if err == nil {
		return checkResult{Name: "dns_resolution_blocked", Passed: false, Details: "DNS resolution succeeded; private-zone sandbox may have network access"}
	}
	return checkResult{Name: "dns_resolution_blocked", Passed: true, Details: "DNS resolution failed as expected"}
}

func checkOutboundTCP() checkResult {
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.Dial("tcp", "1.1.1.1:443")
	if err == nil {
		_ = conn.Close()
		return checkResult{Name: "outbound_tcp_blocked", Passed: false, Details: "outbound TCP connection succeeded; private-zone sandbox is not isolated"}
	}
	return checkResult{Name: "outbound_tcp_blocked", Passed: true, Details: "outbound TCP connection failed as expected"}
}

func checkLocalhostTCP() checkResult {
	d := net.Dialer{Timeout: 500 * time.Millisecond}
	conn, err := d.Dial("tcp", "127.0.0.1:80")
	if err == nil {
		_ = conn.Close()
		return checkResult{Name: "localhost_tcp_review", Passed: false, Details: "localhost:80 is reachable; review whether host services expose network egress"}
	}
	return checkResult{Name: "localhost_tcp_review", Passed: true, Details: "localhost:80 is not reachable"}
}
