# Privacy Gateway MVP

This MVP implements the first executable slice of the local privacy Agent architecture described in `docs/local-privacy-agent-system-design.md`.

It separates the system into two logical services:

| Service | Zone | Network | Raw private data | Provider credentials |
|---|---|---:|---:|---:|
| `privacy-gateway` | Private Zone | No external network recommended | Yes, only inside private zone | No |
| `external-gateway` | Public Zone | Yes | No | Yes |

The main rule is:

```text
Private Zone may touch raw private data but must not call external models directly.
Public Zone may call external models but must only receive sanitized prompts.
```

---

## Implemented components

```text
cmd/privacy-gateway                    Private-zone HTTP service
cmd/external-gateway                   Public-zone OpenAI-compatible external service
pkg/privacygateway/types.go            Shared request, response, and audit types
pkg/privacygateway/scanner.go          Deterministic privacy scanner and redactor
pkg/privacygateway/policy.go           Privacy policy compiler and external prompt builder
pkg/privacygateway/response_checker.go Untrusted external response checker
pkg/privacygateway/audit.go            Privacy-preserving audit event builder
pkg/privacygateway/server.go           Private-zone HTTP routes
```

---

## Build and test

```bash
go test ./pkg/privacygateway

go build ./cmd/privacy-gateway

go build ./cmd/external-gateway
```

---

## Run private-zone privacy gateway

```bash
PRIVACY_GATEWAY_ADDR=127.0.0.1:8787 go run ./cmd/privacy-gateway
```

Production hardening should run this service in a private-zone sandbox with no external network egress.

---

## Compile a private task into a safe external prompt

```bash
curl -s http://127.0.0.1:8787/v1/privacy/compile \
  -H 'Content-Type: application/json' \
  -d @examples/privacygateway/compile-request.json
```

The response includes:

```text
decision         allow, review, block, or local_only
risk_level       highest detected privacy level
external_prompt  sanitized prompt for public-zone use, when allowed
safe_summary     preview-safe summary
redactions       counts and types only, never raw findings
requires_review  whether user preview is required
```

Decision meanings:

| Decision | Meaning |
|---|---|
| `allow` | No blocking sensitive data detected; may call external gateway. |
| `review` | Redacted personal or sensitive data detected; user preview is required. |
| `block` | Secret-like data detected; do not call external gateway. |
| `local_only` | No external capability requested; keep inside private zone. |

---

## Check external response before local model consumption

```bash
curl -s http://127.0.0.1:8787/v1/privacy/external/response-check \
  -H 'Content-Type: application/json' \
  -d @examples/privacygateway/response-check-request.json
```

The response is always marked `untrusted: true`. Even allowed content should be treated as reference data, not instructions.

---

## Run public-zone external gateway

Set provider endpoint, model, and credential through environment variables, then run:

```bash
EXTERNAL_GATEWAY_ADDR=127.0.0.1:8788 go run ./cmd/external-gateway
```

The external gateway must not have access to Memory Vault, raw user input, private-zone logs, local private files, browser profiles, or internal repositories.

---

## Public-zone chat call

Only pass the `external_prompt` returned by `/v1/privacy/compile` after policy approval or user review.

```bash
curl -s http://127.0.0.1:8788/v1/external/chat \
  -H 'Content-Type: application/json' \
  -d '{
    "prompt": "sanitized prompt produced by privacy-gateway",
    "model": "provider-model-name"
  }'
```

---

## Current MVP limitations

This is an MVP, not a complete security product.

Known gaps:

```text
No encrypted Memory Vault implementation yet.
No rehydration engine yet.
No user approval UI yet.
No full policy-as-code engine yet.
No sandbox launcher yet.
No network namespace verification yet.
No user-custom sensitive dictionary yet.
No local NER model integration yet.
```

Recommended next steps:

```text
1. Add Memory Vault with local encryption.
2. Add placeholder mapping and local-only rehydration.
3. Add user approval UI for review decisions.
4. Add UID-level firewall or sandbox launcher.
5. Add configurable sensitive keyword dictionaries.
6. Add CI red-team tests for leakage and injection.
7. Add a typed protocol between local orchestrator and external gateway.
```
