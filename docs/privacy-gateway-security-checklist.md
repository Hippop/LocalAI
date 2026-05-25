# Privacy Gateway Security Checklist

This checklist is intended for development, review, and deployment of the local privacy Agent system.

## 1. Boundary checks

- [ ] Local LLM runtime has no direct internet access.
- [ ] Local LLM runtime cannot reach DNS resolvers.
- [ ] Local LLM runtime cannot reach public TCP endpoints.
- [ ] Local LLM runtime does not receive external provider credentials.
- [ ] Public external gateway cannot read Memory Vault.
- [ ] Public external gateway cannot read raw user input.
- [ ] Public external gateway cannot read local session bindings.
- [ ] Public external gateway cannot read private-zone logs.

Use:

```bash
go run ./cmd/privacy-sandbox-check
```

Expected result in a no-network private sandbox:

```json
{
  "status": "pass"
}
```

## 2. Privacy flow checks

- [ ] `/v1/privacy/compile` creates a local request session.
- [ ] `/v1/privacy/compile` hides `external_prompt` for `review` decisions.
- [ ] `/v1/privacy/export-prompt` blocks `review` decisions until user approval.
- [ ] `/v1/privacy/export-prompt` blocks `block` and `local_only` decisions.
- [ ] `/v1/privacy/rehydrate` blocks unapproved `review` sessions.
- [ ] `/v1/privacy/rehydrate` checks external output before restoring placeholders.
- [ ] Rehydration runs only in the private zone.

## 3. Redaction checks

- [ ] Email addresses are replaced with placeholders before export.
- [ ] Phone numbers are replaced with placeholders before export.
- [ ] Internal URLs are replaced with placeholders before export.
- [ ] File paths are replaced with placeholders before export.
- [ ] Secret-like fields are blocked, not masked.
- [ ] Project-specific keywords can be masked or blocked through config.
- [ ] Custom regex detectors work for organization-specific identifiers.

## 4. Vault checks

- [ ] Memory Vault is disabled unless explicitly configured.
- [ ] Memory Vault file does not contain plaintext private values.
- [ ] Vault list does not return raw values.
- [ ] Vault get is private-zone only.
- [ ] Vault logs do not include raw values.
- [ ] Vault deletion removes the record from encrypted storage.

## 5. Logging checks

- [ ] Raw user input is never written to audit logs.
- [ ] Placeholder bindings are never written to audit logs.
- [ ] External provider responses are not logged before response checking.
- [ ] Audit events include only counts, decisions, and request IDs.
- [ ] Debug logging is disabled or redacted in production.

## 6. External response checks

- [ ] External output is always treated as untrusted reference data.
- [ ] Prompt-injection phrases are detected and blocked.
- [ ] Requests to provide credentials, raw logs, private code, or internal URLs are blocked.
- [ ] Dangerous tool/command suggestions are flagged before local consumption.

## 7. CI checks to add

Recommended test commands:

```bash
go test ./pkg/privacygateway

go test ./cmd/privacy-gateway ./cmd/privacy-gateway-config ./cmd/external-gateway ./cmd/privacy-sandbox-check
```

Recommended red-team fixtures:

```text
private email leak
internal URL leak
file path leak
provider credential leak
prompt injection in external response
custom project keyword leak
vault plaintext-at-rest check
review flow approval bypass
```

## 8. Known limitations

- The deterministic scanner is useful but incomplete; add local NER or structured classifiers later.
- The current vault uses a simple local unlock code derivation suitable for MVP only; production should use a proper KDF and OS keychain integration.
- The current session store is in-memory only; restart loses approval and placeholder mappings.
- The public external gateway is intentionally minimal and does not implement rate limiting or authentication yet.
- The private gateway should be protected by local-only access controls before real use.
