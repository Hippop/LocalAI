# Privacy Gateway Approved Flow

This document describes the current safe flow for the privacy gateway MVP.

The gateway deliberately separates preview, approval, export, external processing, and local rehydration.

```text
compile -> approve -> export-prompt -> external-gateway -> rehydrate
```

## 1. Compile private input

`POST /v1/privacy/compile`

The private-zone gateway scans the raw user task, stores local-only placeholder mappings in the private session store, and returns a preview-safe response.

For `review` decisions, the response does **not** expose `external_prompt`. This prevents clients from bypassing the approval gate.

Example request:

```json
{
  "user_input": "Help with a public Java 21 troubleshooting question for tom@example.com",
  "need_external": true,
  "output_format": "concise markdown"
}
```

Example response:

```json
{
  "request_id": "local-session-id",
  "decision": "review",
  "risk_level": "P2_personal",
  "safe_summary": "Help with a public Java 21 troubleshooting question for {EMAIL_1}",
  "redactions": [
    {
      "type": "email",
      "placeholder": "{EMAIL}",
      "count": 1,
      "level": "P2_personal",
      "action": "placeholder"
    }
  ],
  "requires_review": true
}
```

## 2. Approve reviewed requests

`POST /v1/privacy/approve`

Only the user or trusted local UI should approve a `review` decision.

```json
{
  "request_id": "local-session-id",
  "approved": true,
  "reason": "User reviewed redactions and approved external use."
}
```

## 3. Export sanitized prompt

`POST /v1/privacy/export-prompt`

This is the only private-zone endpoint that returns the sanitized prompt intended for the public-zone external gateway.

Rules:

```text
allow      -> export allowed
review     -> export allowed only after approval
block      -> export denied
local_only -> export denied
```

Example request:

```json
{
  "request_id": "local-session-id"
}
```

Example response:

```json
{
  "request_id": "local-session-id",
  "decision": "review",
  "risk_level": "P2_personal",
  "external_prompt": "sanitized prompt with placeholders only"
}
```

## 4. Send only sanitized prompt to public zone

`POST /v1/external/chat`

The public-zone gateway must receive only the exported sanitized prompt. It must not receive raw user input, Memory Vault data, local session bindings, or private files.

## 5. Rehydrate external output locally

`POST /v1/privacy/rehydrate`

External output is checked as untrusted reference data before local-only placeholders are restored.

```json
{
  "request_id": "local-session-id",
  "external_content": "Suggested response for {EMAIL_1}: ..."
}
```

The final response is safe to show only to the local user because it may contain restored private values.

## 6. Encrypted Memory Vault

The private gateway supports encrypted local storage through `EncryptedMemoryVault` and these endpoints:

```text
POST /v1/privacy/vault/put
POST /v1/privacy/vault/get
GET  /v1/privacy/vault/list
POST /v1/privacy/vault/delete
```

`list` never returns raw values. `get` is private-zone only.

## 7. Configurable policy

The configurable command supports deterministic project-specific policy:

```bash
go run ./cmd/privacy-gateway-config \
  -addr 127.0.0.1:8787 \
  -policy-file examples/privacygateway/privacy-policy.sample.json
```

Optional encrypted vault flags are also available:

```bash
go run ./cmd/privacy-gateway-config \
  -vault-file ./private/vault.enc \
  -vault-code local-only-unlock-code
```

Do not run the private-zone gateway with external network access in production.
