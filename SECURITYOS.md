# SecurityOS — Azure-native Paperclip fork

This is the SecurityOS fork of [Paperclip](https://github.com/paperclipai/paperclip).
It adds three Azure seam packages that replace Paperclip's default local-process
execution with a governed, keyless, private-endpoint-only Azure stack.

## Three seam packages

| Package | Path | Paperclip seam |
|---|---|---|
| `@securityos/adapter-foundry` | `packages/adapters/foundry` | Model adapter — replaces `adapter-claude-local`; calls Azure OpenAI / Foundry keyless via managed identity |
| `@securityos/secrets-azure-keyvault` | `packages/shared/secrets-azure-keyvault` | SecretsProvider — replaces env-var secrets; Key Vault + managed identity |
| `@securityos/aca-jobs-backend` | `packages/shared/aca-jobs-backend` | Execution backend — each agent run is an ephemeral ACA Job with a per-engagement managed identity |

## Security posture

- **Keyless**: no API keys, no client secrets. All auth via `DefaultAzureCredential`
  (managed identity in ACA; developer credential locally).
- **Per-engagement isolation**: the foundry adapter resolves a separate
  `ManagedIdentityCredential` per `engagement.managedIdentityClientId`. The ACA-jobs
  backend verifies the deployed job's bound identity via ARM GET before dispatch.
- **Private-by-default**: `AZURE_OPENAI_ENDPOINT` must be a Private Endpoint URL;
  Key Vault is reached over a PE; ACA Jobs run in a deny-egress subnet.
- **Immutable audit**: every adapter invoke, secret read/write, and job dispatch emits
  a structured audit event. Audit sinks fail-closed (missing sink = error, not no-op).
- **Lane allowlist**: `adapter-foundry` checks `engagement.allowedLanes` before any
  token acquisition. A deployment not on the allowlist is refused with a logged event.

## Registration

Register the foundry adapter in Paperclip's adapter registry (server config):

```json
{
  "adapters": ["@securityos/adapter-foundry"],
  "defaultAdapter": "foundry"
}
```

Set environment variables on the ACA orchestrator app:
```
AZURE_OPENAI_ENDPOINT=https://securityos-foundry.openai.azure.com/
AZURE_CLIENT_ID=<app-managed-identity-client-id>
SECURITYOS_KEY_VAULT_URI=https://securityos-kv.vault.azure.net/
```

## Upstream

Upstream: `paperclipai/paperclip` (MIT). SecurityOS additions are MIT-licensed.
Seam packages live in `packages/adapters/foundry` and `packages/shared/`.
The rest of the repo tracks upstream unchanged to ease future merges.
