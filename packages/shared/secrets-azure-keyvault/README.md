# @securityos/secrets-azure-keyvault

A **Paperclip-compatible secrets provider** backed by **Azure Key Vault**, using
**keyless Microsoft Entra managed identity** (`DefaultAzureCredential`). This is
the SecurityOS drop-in replacement for Paperclip's AWS Secrets Manager provider
(fork-plan §3.3, PRD R9 / §11.1).

## Security contract (non-negotiable)

- **Plaintext values NEVER touch the database.** The DB stores only
  `SecretMetadata` (logical key, Key Vault secret name, **version ref**, scope,
  timestamps). Plaintext is fetched from Key Vault and returned in-memory at
  runtime only — exactly mirroring the AWS provider.
- **Keyless.** Authentication is a `ManagedIdentityCredential` **pinned to an
  explicit `managedIdentityClientId`** (`AZURE_CLIENT_ID`). We deliberately do
  NOT use `DefaultAzureCredential`, whose chain could silently pick up a stray
  `AZURE_CLIENT_SECRET`/env credential. **No API keys, no connection strings, no
  secrets in code or config.**
- **Immutable audit — mandatory and fail-closed.** The `audit` hook is
  **required**: the constructor throws (`AuditRequiredError`) without it. Every
  `get`/`set`/`list`/`delete`/`getVersion` and every inline-env attempt emits a
  `SecretAccessEvent`, and **the audit is awaited before plaintext is returned**.
  If the sink throws, the operation **fails closed** with an `AuditSinkError` —
  a secret read whose access could not be recorded never returns plaintext.
  **The caller persists** the event (to `secret_access_events`, forwarded to Log
  Analytics + WORM export). No plaintext is ever placed in an audit event.
- **Per-engagement isolation at the cloud boundary.** The provider is **bound to
  one engagement scope**, derived from the run identity / environment
  (`PAPERCLIP_DEPLOYMENT_ID` + `PAPERCLIP_ENGAGEMENT_ID`, set by the
  per-engagement ACA Job alongside its bound managed identity) — NOT trusted
  from the caller-supplied `scope` arg. Any operation whose `scope` does not
  match the binding is **denied** (`ScopeIsolationError`, deny-by-default) and
  audited. This is app-layer defense-in-depth on top of the real boundary: **one
  Key Vault per engagement** (or per-secret RBAC scopes) so an engagement's
  managed identity has no data-plane access to any other engagement's vault.
- **Attributable.** Every operation requires a caller/principal; if none is
  passed it defaults to the bound principal (`PAPERCLIP_PRINCIPAL` / the pinned
  managed-identity client id — the authenticated identity). Operations with no
  resolvable principal are denied (`CallerRequiredError`).
- **Strict mode defaults ON.** Inline-env secret resolution is forbidden by
  default; set `PAPERCLIP_SECRETS_STRICT_MODE=false` (or `strictMode: false`) to
  opt out.

> `list()` enumerates the **entire vault** and filters by tag in-process (it
> needs list permission over the whole vault). With a shared vault a run could
> enumerate other engagements' secret names/tags (never their values) — which is
> exactly why the cloud-boundary design is one vault per engagement.

> Private-by-default note: with Key Vault `public network access disabled` +
> `network_acls.default_action = Deny`, the **data plane** is reachable only
> over a **Private Endpoint**. This provider must run from inside the VNet (the
> Paperclip-AOS Container App / agent job), not from a public hosted agent.

## Secret naming

Logical secrets resolve to a deterministic Key Vault object name, sanitized to
the Key Vault rule `^[0-9a-zA-Z-]{1,127}$`:

```
paperclip-{deploymentId}-{engagementId}-{key}-{hash}
```

`{hash}` is a fixed-length (12 hex) hash of the **canonical, length-prefixed**
`(deploymentId, engagementId, key)` tuple. Dash-joining sanitized segments is
ambiguous on its own — `({engagementId:'a-b'},'c')` and `({engagementId:'a'},'b-c')`
would render the same readable prefix — so the hash (computed over a
length-unambiguous encoding of the raw tuple) is **always** appended and is what
guarantees distinct tuples never collide, including after truncation. Illegal
characters (`/ _ . :` …) become dashes; runs collapse; leading/trailing dashes
trim; the readable prefix is truncated if needed to keep the whole name ≤127. The
original `{deploymentId, engagementId, key}` triple is also written to the
secret's **tags**, so `list` recovers the logical key without parsing the name.

## Install

```bash
npm install   # @azure/keyvault-secrets, @azure/identity
npm run build
npm test
```

## Environment

| Variable | Required | Meaning |
|---|---|---|
| `AZURE_KEYVAULT_URL` | yes (unless a `client`/`vaultUrl` is passed) | Vault data-plane URL, e.g. `https://kv-eng-001.vault.azure.net` |
| `AZURE_CLIENT_ID` | yes (unless a `client`/`credential` is passed) | Client id of the engagement's user-assigned managed identity to **pin** the credential to |
| `PAPERCLIP_DEPLOYMENT_ID` | yes (for the binding) | Deployment id of the engagement scope this run is bound to |
| `PAPERCLIP_ENGAGEMENT_ID` | yes (for the binding) | Engagement id this run is bound to; mismatched scopes are denied |
| `PAPERCLIP_PRINCIPAL` | no | Default attributed principal (defaults to `AZURE_CLIENT_ID`) |
| `PAPERCLIP_SECRETS_STRICT_MODE` | no | `false` allows inline env secrets (**default is strict/`true`**) |

The credential is a `ManagedIdentityCredential` **pinned** to `AZURE_CLIENT_ID`
(or `managedIdentityClientId`). No client-secret env var is consulted; a stray
`AZURE_CLIENT_SECRET` cannot be used.

## RBAC role required

The provider's identity needs **data-plane** access. With Key Vault in **RBAC**
authorization mode, assign:

- **`Key Vault Secrets Officer`** — for the orchestrator identity that needs
  `get` + `set` + `delete` + `list` (read/write secrets, manage versions).
- **`Key Vault Secrets User`** — for read-only agent-run identities that only
  need `get`/`list` (recommended for deny-by-default agent jobs).

## Usage (Paperclip wiring)

```ts
import { KeyVaultSecretsProvider } from "@securityos/secrets-azure-keyvault";

// Built once at boot. `audit` is MANDATORY (constructor throws without it) and
// fails closed; vaultUrl defaults to AZURE_KEYVAULT_URL; the credential is a
// ManagedIdentityCredential pinned to AZURE_CLIENT_ID; the engagement binding
// defaults to PAPERCLIP_DEPLOYMENT_ID + PAPERCLIP_ENGAGEMENT_ID.
const secrets = new KeyVaultSecretsProvider({
  // strictMode defaults to true.
  audit: async (event) => {
    await db.insert(secretAccessEvents).values(event); // metadata only, no plaintext
    // optionally: appInsights.trackEvent({ name: "secret-access", properties: event });
  },
});

// The bound engagement scope comes from the run identity/env. Passing a scope
// for a DIFFERENT engagement is denied (ScopeIsolationError) and audited.
const scope = { deploymentId: "dep01", engagementId: "eng-acme" }; // engagement == company

// set → returns metadata + version ref to persist; value stays in Key Vault.
const meta = await secrets.set(scope, "db-password", plaintext, agentRunId);
await db.update(secretBindings).set({ kvName: meta.secretName, version: meta.version });

// get → plaintext in-memory at runtime only.
const { value } = await secrets.get(scope, "db-password", agentRunId);

await secrets.getVersion(scope, "db-password", meta.version, agentRunId);
await secrets.list(scope, agentRunId);   // only this engagement's secrets
await secrets.delete(scope, "db-password", agentRunId);
```

Register it where Paperclip resolves its secrets provider (the same seam the AWS
provider plugs into), e.g.:

```ts
import type { SecretsProvider } from "@securityos/secrets-azure-keyvault";
const provider: SecretsProvider = secrets; // satisfies Paperclip's provider contract
registerSecretsProvider("azure-keyvault", provider);
```

### Strict mode / inline-env guard

```ts
// Throws StrictModeViolationError when PAPERCLIP_SECRETS_STRICT_MODE=true,
// so a forgotten `OPENAI_API_KEY=...` env injection cannot silently work.
await secrets.resolveInlineEnv(scope, "openai-api-key", "OPENAI_API_KEY");
```

## API

| Method | Returns | Notes |
|---|---|---|
| `get(scope, key, caller?)` | `SecretValue` | Plaintext + metadata (runtime only) |
| `getVersion(scope, key, version, caller?)` | `SecretValue` | Specific historical version |
| `set(scope, key, value, caller?)` | `SecretMetadata` | Returns version ref; no plaintext |
| `list(scope, caller?)` | `SecretMetadata[]` | Scoped to the engagement |
| `delete(scope, key, caller?)` | `void` | Soft-delete via Key Vault |
| `resolveInlineEnv(scope, key, envVar, caller?)` | `string` | Forbidden in strict mode |

`SecretMetadata` is what you persist. `SecretValue extends SecretMetadata` and
adds `value` — never persist `value`.

## Terraform wiring snippet

Do **not** edit the shared root `main.tf` / `variables.tf`. Add the role
assignment(s) in the engagement / orchestration module that already provisions
the Key Vault and the managed identities (provider `azurerm ~> 4.0`):

```hcl
# Orchestrator identity: full read/write on the engagement Key Vault.
resource "azurerm_role_assignment" "aos_secrets_officer" {
  scope                = azurerm_key_vault.engagement.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = azurerm_user_assigned_identity.aos_orchestrator.principal_id
}

# Per-engagement agent-run identity: read-only (deny-by-default).
resource "azurerm_role_assignment" "agent_secrets_user" {
  scope                = azurerm_key_vault.engagement.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.engagement_agent.principal_id
}

# Key Vault stays private-by-default (already set in azure-foundation):
#   public_network_access_enabled = false
#   enable_rbac_authorization     = true
#   network_acls { default_action = "Deny" }
# Reach the data plane over a Private Endpoint from the AOS Container App / job.
```

Then surface the vault URL to the app as a plain (non-secret) setting:

```hcl
# In the Container App / Job template env block:
# AZURE_KEYVAULT_URL          = azurerm_key_vault.engagement.vault_uri
# PAPERCLIP_SECRETS_STRICT_MODE = "true"
```

## References

- Key Vault network security — https://learn.microsoft.com/azure/key-vault/general/network-security
- Key Vault RBAC guide — https://learn.microsoft.com/azure/key-vault/general/rbac-guide
- Object naming rules — https://learn.microsoft.com/azure/key-vault/general/about-keys-secrets-certificates
- Keyless auth (ManagedIdentityCredential, user-assigned) — https://learn.microsoft.com/azure/developer/javascript/sdk/authentication/credential-chains
