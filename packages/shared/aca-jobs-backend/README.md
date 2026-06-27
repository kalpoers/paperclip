# @securityos/aca-jobs-backend

A **Paperclip execution backend** for SecurityOS that runs every agent run as an
**ephemeral Azure Container Apps (ACA) Job execution** instead of a subprocess on
the orchestrator host. This is the isolation-critical piece of the
[Paperclip → Azure fork plan](../../../docs/paperclip-azure-fork-plan.md) §3.7
and satisfies PRD R9 / §11.1 (private-by-default, keyless, deny-by-default
egress, immutable audit, per-engagement isolation).

It implements Paperclip's `invoke` / `status` / `cancel` execution contract as a
drop-in module — no upstream core patches required.

## Why ACA Jobs (not a subprocess)

Upstream Paperclip forks the agent as a subprocess on the server. That shares the
server's identity, network, and filesystem with every engagement — unacceptable
for T2 client-confidential security data. This backend moves each run into an
isolated, audited, egress-locked container that carries **only its engagement's**
managed identity and Key Vault scope.

## Security posture (non-negotiable, PRD §11.1)

| Control | How this module honors it |
|---|---|
| **Keyless** | ARM client uses `DefaultAzureCredential` (managed identity). No API keys, no secrets in code/config. |
| **Per-engagement isolation** | `engagementId` (== Paperclip `company_id`) resolves 1:1 to a pre-provisioned ACA Job whose `identity` is the engagement's **user-assigned managed identity**. `assertRunIsIsolated` fails closed if the engagement/identity binding is missing — an unscoped run is never dispatched. |
| **Keyless secret injection** | Secrets are injected by **reference** (`secretRef` → a Key Vault-backed secret defined on the Job). The literal value is resolved by the engagement's managed identity at container start; no secret material passes through this process. The run JWT defaults to a TTL-bounded by-value env, or a keyless `secretRef` via `jwtSecretName` (see [Run JWT exposure](#run-jwt-arm-plane-exposure)). |
| **Confirmed identity binding** | On `invoke` the backend does an **ARM GET** on the resolved job and refuses to start unless the job's bound `userAssignedIdentities` actually contains `run.managedIdentityResourceId`. Audit records the **confirmed** identity (`boundManagedIdentityResourceId` + `identityVerified`), not just the claimed one. |
| **Engagement id sanitization** | `engagementId` is validated against a strict DNS-label pattern (`assertValidEngagementId`) before being interpolated into the job name / ARM path — blocks path traversal, ARM-path injection, and name-collision tricks. |
| **Deny-by-default egress** | Enforced at the **Container Apps environment subnet (NSG)** / Azure Firewall level — see [Egress](#egress) — and asserted before dispatch: `egress.mode === "deny"` **and** every allow-list entry is a per-account FQDN (coarse service tags like `Storage`/`AzureCognitiveServices` are rejected, fail-closed). |
| **Immutable audit (fail-closed)** | The `audit` sink is **required** — the constructor throws if it is absent (no silent no-op). Every `invoke`/`status`/`cancel` emits an `AuditEvent`; a sink that throws propagates and aborts the action. Wire `audit` to Log Analytics / the Paperclip `activity` table for WORM export. |
| **Private-by-default** | The Container Apps environment is internal-only (no public ingress); the orchestrator reaches ARM/Key Vault/Foundry over Private Endpoints. |

## Identity model (per engagement)

```
Engagement (Paperclip company)
  └── ACA Job  caj-eng-<engagementId>          (pre-provisioned by Terraform)
        ├── identity: user-assigned MI  id-eng-<engagementId>   (scoped: KV prefix, Storage container, Search index, Foundry deployment)
        ├── configuration.secrets[]: keyVaultUrl + identity     (keyless KV refs)
        └── environment: deny-egress subnet, internal ingress

Run (this backend)
  └── jobs.beginStart(job, { template })       ← overrides per-run env only
        ├── PAPERCLIP_RUN_JWT     (short-lived bearer, by value)
        ├── PAPERCLIP_ENGAGEMENT_ID / PAPERCLIP_RUN_WORKSPACE
        ├── <model/lane env>      (non-secret, by value)
        └── <SECRET envs>         (secretRef → job KV secret, keyless)
```

The orchestrator process itself runs under its **own** managed identity holding
**Container Apps Jobs Contributor** scoped to the Container Apps *environment*
(so it can start/stop executions on the per-engagement jobs but nothing else).

## Usage

```ts
import {
  AcaJobsExecutionBackend,
  buildEgressPolicy,
  type ExecutionRun,
} from "@securityos/aca-jobs-backend";

const backend = new AcaJobsExecutionBackend({
  subscriptionId: process.env.AZURE_SUBSCRIPTION_ID!, // identity, not a secret
  resourceGroupName: "rg-securityos-orchestration",
  // engagementId -> ACA Job resource name (default: `caj-eng-<engagementId>`)
  resolveJobName: (eng) => `caj-eng-${eng}`,
  audit: (e) => logAnalytics.track(e), // REQUIRED — constructor throws if absent
  defaultImage: "myreg.azurecr.io/securityos/agent:1.2.3", // used if run.image unset
  maxJwtTtlSeconds: 600, // bound for a by-value run JWT (default 600)
});

const run: ExecutionRun = {
  runId: "run-123",
  engagementId: "eng-acme",                 // validated; == Paperclip company id
  agentId: "agent-7",
  managedIdentityResourceId: "/subscriptions/.../userAssignedIdentities/id-eng-acme",
  jwt: orchestratorMintedRunJwt,            // short-lived (exp <= maxJwtTtlSeconds)
  // OR, for zero ARM-plane exposure, inject by reference instead of value:
  // jwtSecretName: "run-jwt",
  secretRefs: [{ envName: "FOUNDRY_ENDPOINT", secretName: "foundry-endpoint" }],
  env: { MODEL_DEPLOYMENT: "gpt-firm-lane" },
  workspacePath: "/work/run-123",
  image: "myreg.azurecr.io/securityos/agent:1.2.3", // or rely on defaultImage
  egress: buildEgressPolicy({               // deny-by-default, per-account FQDNs
    keyVaultName: "kv-eng-acme",
    foundryAccountName: "aoai-eng-acme",
    enterpriseRagHost: "rag.enterprise.example.com",
  }),
};

const handle = await backend.invoke(run);   // start ephemeral execution
const status = await backend.status(handle); // "running" | "succeeded" | "failed" | "cancelled" | "pending" | "unknown"
await backend.cancel(handle);                // stop execution
```

### Wiring into Paperclip

Register `AcaJobsExecutionBackend` where Paperclip selects an execution backend
(the subprocess invoker seam). The contract is identical:

- `invoke(run) -> handle` — replaces subprocess spawn; returns a trackable handle.
- `status(handle) -> ExecutionStatus` — replaces process-exit polling; maps the
  ACA execution running-state to `running` / `succeeded` / `failed` / `cancelled`.
- `cancel(handle)` — replaces `SIGTERM`; stops the ACA Job execution.

Keep Paperclip's checkout/heartbeat loop unchanged; only the execution mechanism
moves into ACA Jobs.

## Run JWT (ARM-plane exposure)

An environment variable supplied as a plaintext `value` in an ACA Job
**execution template** is readable by any principal holding job-read RBAC
(`Microsoft.App/jobs/read` + `.../executions/read`) — `az containerapp job
execution show` returns the template. So echoing the run JWT as a `value` leaks
a bearer token to anyone who can read the job.

This backend handles that two ways:

1. **Keyless `secretRef` (preferred).** Set `run.jwtSecretName` to a secret
   pre-defined on the Job's `configuration.secrets`; the JWT is injected by
   reference and never appears in the execution template plaintext.
2. **TTL-bounded by-value (default).** If no `jwtSecretName` is given, the JWT is
   passed by value but the backend **refuses to dispatch** unless it carries an
   `exp` claim within `maxJwtTtlSeconds` (default 600s). A non-expiring or
   long-lived token is rejected (`assertShortLivedJwt`), bounding the exposure.

Regardless, scope job-read RBAC tightly: the orchestrator identity needs
**Container Apps Jobs Contributor** on the environment, but no broad reader
should hold job-execution read on the per-engagement jobs.

## Egress

Deny-by-default egress is a **network** control and lives on the Container Apps
environment, not in the start payload. The backend asserts the policy before
dispatch (`egress.mode === "deny"` and **no coarse service tags** in the
allow-list) but cannot itself open or close network paths.

Coarse Azure service tags (`Storage`, `AzureCognitiveServices`, …) are
**forbidden** in the allow-list: a service tag matches *every* such account in
the region/tenant, so it would let one engagement's agent reach another
engagement's storage / model account. Build a per-account FQDN allow-list with
`buildEgressPolicy({...})` (Key Vault, the engagement's Foundry account,
storage, search, and the external enterpriseRAG host).

### Representative NSG (deny-all egress; allow only the PE subnet)

NSGs match IP/service tags, not FQDNs. Per-account isolation is achieved by
routing the keyless Azure data plane through **private endpoints** in a dedicated
PE subnet and allowing egress *only* to that subnet — deny everything else:

```hcl
# Agent (job) environment subnet NSG: deny-by-default outbound.
resource "azurerm_network_security_group" "agent_egress" {
  name                = "nsg-agent-egress-${var.engagement_id}"
  location            = var.location
  resource_group_name = var.resource_group_name

  # 1) Allow only the private-endpoints subnet (KV/Foundry/Storage/Search PEs).
  security_rule {
    name                       = "allow-pe-subnet-out"
    priority                   = 100
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "VirtualNetwork"
    destination_address_prefixes = [var.private_endpoints_subnet_cidr]
  }

  # 2) Allow Azure Monitor (audit/telemetry) by service tag, 443 only.
  security_rule {
    name                       = "allow-azuremonitor-out"
    priority                   = 110
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "AzureMonitor"
  }

  # 3) DENY everything else outbound (deny-by-default; below platform 65000).
  security_rule {
    name                       = "deny-all-out"
    priority                   = 4000
    direction                  = "Outbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}
```

### enterpriseRAG (external FQDN) egress

If the enterpriseRAG host is **not** reachable via private endpoint, NSGs cannot
scope to its FQDN — route agent egress through **Azure Firewall** and allow only
that single hostname (an application rule), keeping deny-by-default for the rest:

```hcl
# Azure Firewall application rule: allow ONLY the enterpriseRAG host, 443.
resource "azurerm_firewall_application_rule_collection" "enterprise_rag" {
  name                = "allow-enterpriserag-${var.engagement_id}"
  azure_firewall_name = var.firewall_name
  resource_group_name = var.resource_group_name
  priority            = 200
  action              = "Allow"

  rule {
    name             = "enterpriserag-fqdn"
    source_addresses = [var.agent_subnet_cidr]
    target_fqdns     = [var.enterprise_rag_host] # e.g. rag.enterprise.example.com
    protocol {
      type = "Https"
      port = 443
    }
  }
}
```

References: [Container Apps custom VNet](https://learn.microsoft.com/en-us/azure/container-apps/vnet-custom) ·
[Container Apps secrets / Key Vault](https://learn.microsoft.com/en-us/azure/container-apps/manage-secrets) ·
[Managed identities overview](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview)

## RBAC required

The orchestrator's managed identity needs **Container Apps Jobs Contributor**
(`Microsoft.App` jobs management) **scoped to the Container Apps environment**
(least privilege — not subscription-wide). This grants start/stop on the
per-engagement jobs. Each engagement Job binds its **own** user-assigned identity
for data-plane access; the orchestrator identity never holds engagement data scopes.

## Terraform wiring snippet (do NOT edit the shared root)

Add to your environment composition (provider `azurerm ~> 4.0`). The per-engagement
Job + identity are typically produced by an `engagement` module; this snippet shows
the orchestrator role assignment and a representative per-engagement Job.

```hcl
# Orchestrator identity: Container Apps Jobs Contributor scoped to the ACA env.
resource "azurerm_role_assignment" "orchestrator_jobs_contributor" {
  scope                = azurerm_container_app_environment.main.id
  role_definition_name = "Container Apps Jobs Contributor"
  principal_id         = azurerm_user_assigned_identity.orchestrator.principal_id
}

# Per-engagement ephemeral job (one per engagement == Paperclip company).
resource "azurerm_container_app_job" "engagement" {
  name                         = "caj-eng-${var.engagement_id}"
  resource_group_name          = var.resource_group_name
  location                     = var.location
  container_app_environment_id = azurerm_container_app_environment.main.id
  replica_timeout_in_seconds   = 3600

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.engagement.id] # scoped MI
  }

  # Keyless Key Vault secret reference (resolved by the engagement MI).
  secret {
    name                = "foundry-endpoint"
    key_vault_secret_id = azurerm_key_vault_secret.foundry_endpoint.versionless_id
    identity            = azurerm_user_assigned_identity.engagement.id
  }

  manual_trigger_config {
    parallelism              = 1
    replica_completion_count = 1
  }

  template {
    container {
      # The name MUST be "agent" (== AGENT_CONTAINER_NAME). An ACA Start
      # template override REPLACES the container matched by name; a mismatch
      # would silently drop this container's env/secretRefs. The backend always
      # emits an image in the override too (it cannot inherit this one).
      name   = "agent"
      image  = var.agent_image
      cpu    = 0.5
      memory = "1Gi"
      # per-run env (JWT, secretRefs, workspace) is injected at start time by
      # @securityos/aca-jobs-backend via jobs.beginStart(template override).
    }
  }
}
```

Egress (deny-by-default) is configured on `azurerm_container_app_environment.main`
via its `infrastructure_subnet_id` + an `azurerm_network_security_group` that
denies outbound except the allowed Azure service tags. Keep that in the networking
module, not here.

## Develop

```bash
npm install
npm run typecheck
npm test          # vitest, ARM client mocked
npm run build
```

## Files

- `src/jobSpec.ts` — pure types + execution-template builder + isolation guards + status mapping.
- `src/executionBackend.ts` — `AcaJobsExecutionBackend` (invoke/status/cancel) over `@azure/arm-appcontainers`.
- `src/index.ts` — public API.
- `test/backend.test.ts` — vitest suite with a mocked ARM client.
