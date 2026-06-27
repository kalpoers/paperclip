/**
 * jobSpec.ts
 *
 * Pure (no I/O) types and helpers that translate a Paperclip agent *run* into
 * an Azure Container Apps Job **execution-template override** — the payload
 * passed to `jobs.beginStart(...)`.
 *
 * SecurityOS posture (PRD R9 / §11.1) honored here:
 *  - Keyless: secrets are injected by *reference* (`secretRef`), never as
 *    literal values. The literal value lives in Key Vault and is resolved by
 *    the Job's bound user-assigned managed identity. No secret material ever
 *    transits this module.
 *  - Per-engagement isolation: every run is bound to a single engagement; the
 *    engagement maps 1:1 to a pre-provisioned ACA Job whose `identity` is the
 *    engagement's user-assigned managed identity. This module refuses to build
 *    a template for a run whose engagement id is empty, so a run can never be
 *    dispatched onto an unscoped/shared job by accident.
 *  - Deny-by-default egress is a *network* control (NSG on the Container Apps
 *    environment subnet) and cannot be expressed in the execution template; it
 *    is enforced at the environment level and asserted by `EgressPolicy` below
 *    for documentation/validation, not configured here. See README §Egress.
 */

/** Lifecycle status of a single ACA Job execution, normalized for Paperclip. */
export type ExecutionStatus =
  | "pending"
  | "running"
  | "succeeded"
  | "failed"
  | "cancelled"
  | "unknown";

/**
 * Raw ACA Job execution running-state strings as returned by the ARM API
 * (`JobExecution.status`). Mapped to {@link ExecutionStatus} by
 * {@link mapAcaStatus}.
 */
export type AcaJobExecutionState =
  | "Running"
  | "Processing"
  | "Succeeded"
  | "Failed"
  | "Degraded"
  | "Stopped"
  | "Unknown";

/**
 * A reference to a Key Vault-backed secret, exposed to the container as an
 * environment variable. `secretName` MUST already exist on the target ACA Job
 * resource (provisioned by Terraform with `keyVaultUrl` + `identity`), so the
 * managed identity — not this process — performs the Key Vault read.
 */
export interface SecretEnvRef {
  /** Environment variable name seen by the agent process. */
  envName: string;
  /** Name of the secret defined on the ACA Job's `configuration.secrets`. */
  secretName: string;
}

/**
 * Egress posture for a run. Deny-by-default is mandatory for agent execution
 * (PRD §11.1). This is asserted/recorded here; the actual enforcement is the
 * NSG / Azure Firewall + Container Apps environment configuration (see README).
 *
 * The allow-list is expressed as **per-account fully-qualified hostnames**, NOT
 * coarse Azure service tags. A service tag like `Storage` or
 * `AzureCognitiveServices` resolves to every such account in the region/tenant,
 * so it would let one engagement's agent reach another engagement's storage /
 * model account — defeating per-engagement isolation. `assertEgressPolicy`
 * fails closed if a coarse tag (or wildcard) appears in the allow-list.
 */
export interface EgressPolicy {
  /** MUST be "deny" for any T1/T2 engagement run. */
  mode: "deny";
  /**
   * Per-account FQDNs the run may reach (e.g. `kv-eng-acme.vault.azure.net`,
   * the engagement's Foundry account, and the external enterpriseRAG host).
   * Empty = deny-all (the safest default). MUST NOT contain coarse service
   * tags or wildcards.
   */
  allowedFqdns: string[];
}

/**
 * Coarse Azure service tags / wildcards that permit region- or tenant-wide
 * egress. Their presence in an {@link EgressPolicy} allow-list is rejected
 * (fail-closed) because they cannot scope egress to a single engagement.
 */
export const FORBIDDEN_COARSE_EGRESS: ReadonlySet<string> = new Set([
  "*",
  "internet",
  "virtualnetwork",
  "azurecloud",
  "storage",
  "azurecognitiveservices",
  "cognitiveservices",
  "azurekeyvault",
  "keyvault",
  "azuremonitor",
  "azureopenai",
  "sql",
  "eventhub",
  "servicebus",
]);

/**
 * Default egress policy: **deny-all** (empty allow-list). A real deployment
 * MUST build a per-engagement allow-list with {@link buildEgressPolicy} so the
 * run can reach only its OWN Key Vault / Foundry account / storage / search and
 * the external enterpriseRAG host — nothing else.
 */
export const DEFAULT_EGRESS_POLICY: EgressPolicy = {
  mode: "deny",
  allowedFqdns: [],
};

/** Per-engagement, per-account egress targets used to build a scoped allow-list. */
export interface EgressTargets {
  /** Engagement Key Vault name → `${name}.vault.azure.net`. */
  keyVaultName: string;
  /** Engagement Azure AI Foundry / OpenAI account name. */
  foundryAccountName: string;
  /** External enterpriseRAG host (framework catalogs); keyless, allow-listed. */
  enterpriseRagHost: string;
  /** Optional engagement Storage account → `${name}.blob.core.windows.net`. */
  storageAccountName?: string;
  /** Optional engagement AI Search service → `${name}.search.windows.net`. */
  searchServiceName?: string;
  /** Any additional per-account FQDNs (e.g. Document Intelligence account). */
  extraFqdns?: string[];
}

/** Rough hostname shape: dotted, lowercase-able, no scheme/path/wildcard. */
const FQDN_PATTERN =
  /^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$/;

function assertScopedFqdn(fqdn: string): string {
  const host = fqdn.trim().toLowerCase();
  if (!host) {
    throw new InvalidRunError("egress allow-list entry is empty");
  }
  if (FORBIDDEN_COARSE_EGRESS.has(host)) {
    throw new InvalidRunError(
      `egress allow-list entry '${fqdn}' is a coarse service tag/wildcard — it permits tenant-wide egress and breaks per-engagement isolation (PRD §11.1). Use a per-account FQDN.`,
    );
  }
  if (!FQDN_PATTERN.test(host)) {
    throw new InvalidRunError(
      `egress allow-list entry '${fqdn}' is not a per-account FQDN (no scheme/port/path/wildcard; must be a dotted hostname)`,
    );
  }
  return host;
}

/**
 * Build a per-engagement, per-account FQDN allow-list. Every entry is a single
 * account/service host, so the resulting NSG/Firewall rules cannot reach a
 * different engagement's resources.
 */
export function buildEgressAllowlist(t: EgressTargets): string[] {
  if (!t.keyVaultName?.trim()) {
    throw new InvalidRunError("buildEgressAllowlist: keyVaultName is required");
  }
  if (!t.foundryAccountName?.trim()) {
    throw new InvalidRunError(
      "buildEgressAllowlist: foundryAccountName is required",
    );
  }
  if (!t.enterpriseRagHost?.trim()) {
    throw new InvalidRunError(
      "buildEgressAllowlist: enterpriseRagHost is required — the framework catalog API must be explicitly allow-listed (deny-by-default)",
    );
  }
  const fqdns = [
    `${t.keyVaultName}.vault.azure.net`,
    `${t.foundryAccountName}.openai.azure.com`,
    `${t.foundryAccountName}.cognitiveservices.azure.com`,
    t.enterpriseRagHost,
  ];
  if (t.storageAccountName?.trim()) {
    fqdns.push(`${t.storageAccountName}.blob.core.windows.net`);
  }
  if (t.searchServiceName?.trim()) {
    fqdns.push(`${t.searchServiceName}.search.windows.net`);
  }
  for (const extra of t.extraFqdns ?? []) fqdns.push(extra);
  // Validate + normalize every entry; dedupe.
  const normalized = fqdns.map((f) => assertScopedFqdn(f));
  return [...new Set(normalized)];
}

/** Build a deny-by-default {@link EgressPolicy} scoped to one engagement. */
export function buildEgressPolicy(t: EgressTargets): EgressPolicy {
  return { mode: "deny", allowedFqdns: buildEgressAllowlist(t) };
}

/**
 * Validate an egress policy: mode must be deny, and every allow-list entry must
 * be a per-account FQDN (no coarse service tags / wildcards). Fail-closed.
 */
export function assertEgressPolicy(egress: EgressPolicy): void {
  if (egress.mode !== "deny") {
    throw new InvalidRunError(
      "egress.mode must be 'deny' — deny-by-default egress is non-negotiable for agent execution (PRD §11.1)",
    );
  }
  for (const fqdn of egress.allowedFqdns ?? []) assertScopedFqdn(fqdn);
}

/**
 * A Paperclip agent run, enriched with the Azure binding metadata SecurityOS
 * needs to dispatch it as an isolated ACA Job execution.
 */
export interface ExecutionRun {
  /** Stable Paperclip run id (used to name + correlate the execution). */
  runId: string;
  /** Engagement id == Paperclip `company_id`. Drives job selection + isolation. */
  engagementId: string;
  /** Paperclip agent id (for audit/correlation). */
  agentId: string;
  /**
   * Resource id of the engagement's user-assigned managed identity. The target
   * Job MUST already be bound to this identity; supplied here for validation +
   * immutable audit, NOT to mutate identity at start time (the ARM start API
   * cannot change a job's identity).
   */
  managedIdentityResourceId: string;
  /**
   * Short-lived run JWT minted by the orchestrator so the agent can call back
   * into the Paperclip API.
   *
   * ARM-plane exposure: an env `value` in an ACA execution template is
   * retrievable by any principal with job-read RBAC (`Microsoft.App/jobs/read`
   * + executions). Therefore this token is NOT echoed as a plaintext `value`
   * unless it is verifiably short-lived: when passed by value the backend
   * enforces an `exp` claim within a tight TTL bound (see
   * {@link assertShortLivedJwt}). For zero ARM-plane exposure, pre-provision the
   * token as a Job secret and set {@link jwtSecretName} so it is injected by
   * `secretRef` instead.
   */
  jwt: string;
  /** Env var name for the run JWT. Default `PAPERCLIP_RUN_JWT`. */
  jwtEnvName?: string;
  /**
   * If set, the run JWT is injected by `secretRef` to this Job secret name
   * (keyless, never in the execution-template plaintext) instead of by value.
   * The secret MUST already be defined on the Job's `configuration.secrets`.
   */
  jwtSecretName?: string;
  /** Key Vault-backed secret references to expose as env vars (keyless). */
  secretRefs?: SecretEnvRef[];
  /** Non-secret environment for the run (model deployment name, lane, etc). */
  env?: Record<string, string>;
  /** Per-run ephemeral workspace path inside the container. */
  workspacePath?: string;
  /** Optional image override (else the job's template image is used). */
  image?: string;
  /** Optional command override. */
  command?: string[];
  /** Optional args override. */
  args?: string[];
  /** Egress policy; defaults to {@link DEFAULT_EGRESS_POLICY}. */
  egress?: EgressPolicy;
}

/** Env var injected so the agent knows its isolated, per-run workspace root. */
export const WORKSPACE_ENV_NAME = "PAPERCLIP_RUN_WORKSPACE";
/** Env var carrying the engagement id (for in-container scoping/asserts). */
export const ENGAGEMENT_ENV_NAME = "PAPERCLIP_ENGAGEMENT_ID";

/**
 * Minimal shape of a container env entry in an ACA Job execution template.
 * Mirrors `@azure/arm-appcontainers` `EnvironmentVar`.
 */
export interface ContainerEnvVar {
  name: string;
  value?: string;
  secretRef?: string;
}

/** Minimal shape of an execution-template container override. */
export interface ExecutionTemplateContainer {
  name: string;
  image?: string;
  command?: string[];
  args?: string[];
  env: ContainerEnvVar[];
}

/** Minimal shape of `JobExecutionTemplate` passed to `jobs.beginStart`. */
export interface ExecutionTemplate {
  containers: ExecutionTemplateContainer[];
}

/** Logical container name used for the single agent container in a run job. */
export const AGENT_CONTAINER_NAME = "agent";

/** Thrown when a run cannot be safely dispatched (isolation guard). */
export class InvalidRunError extends Error {
  override name = "InvalidRunError";
}

/**
 * Allowed shape for an `engagementId` so it is safe to interpolate into an ACA
 * Job resource name and an ARM path. ACA job names are DNS-label-like; we
 * additionally forbid leading/trailing hyphens and uppercase. This blocks path
 * traversal / ARM-path injection (`../`, `/`, `?`) and name-collision tricks.
 */
export const ENGAGEMENT_ID_PATTERN = /^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$/;

/**
 * Validate + return a sanitized engagementId. Fails closed: an id that is not a
 * safe job-name segment is rejected rather than silently stripped, so a
 * malformed id can never resolve to (or collide with) a different engagement's
 * job.
 */
export function assertValidEngagementId(engagementId: string): string {
  if (!engagementId?.trim()) {
    throw new InvalidRunError(
      "run.engagementId is required — refusing to dispatch an unscoped run (per-engagement isolation, PRD R1/R5)",
    );
  }
  if (!ENGAGEMENT_ID_PATTERN.test(engagementId)) {
    throw new InvalidRunError(
      `run.engagementId '${engagementId}' is not a safe job-name segment ` +
        "(lowercase alphanumeric + interior hyphens, <=32 chars) — refusing to " +
        "interpolate it into the ACA job name / ARM path (injection & collision guard)",
    );
  }
  return engagementId;
}

/** Max TTL (seconds) for a run JWT passed by value into the execution template. */
export const DEFAULT_MAX_JWT_TTL_SECONDS = 600;

/**
 * Decode a base64url segment to a (Latin1) string with no runtime dependency on
 * `Buffer`/`atob` (keeps the lib surface = ES2022 only).
 */
function base64UrlToString(input: string): string {
  const alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const lookup = new Map<string, number>();
  for (let i = 0; i < alphabet.length; i++) lookup.set(alphabet[i]!, i);
  const b64 = input.replace(/-/g, "+").replace(/_/g, "/");
  let bits = 0;
  let nbits = 0;
  let out = "";
  for (const ch of b64) {
    if (ch === "=") break;
    const v = lookup.get(ch);
    if (v === undefined) continue; // skip stray whitespace
    bits = (bits << 6) | v;
    nbits += 6;
    if (nbits >= 8) {
      nbits -= 8;
      out += String.fromCharCode((bits >> nbits) & 0xff);
    }
  }
  return out;
}

/** Extract the numeric `exp` (seconds since epoch) from a JWT, if present. */
export function decodeJwtExp(jwt: string): number | undefined {
  const parts = jwt.split(".");
  if (parts.length < 2 || !parts[1]) return undefined;
  try {
    const claims = JSON.parse(base64UrlToString(parts[1])) as {
      exp?: unknown;
    };
    return typeof claims.exp === "number" ? claims.exp : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Enforce that a JWT passed by value is verifiably short-lived. A non-expiring
 * or long-TTL token must NOT be echoed into the execution template (ARM-plane
 * exposure). Fail-closed: no readable `exp` ⇒ reject.
 */
export function assertShortLivedJwt(
  jwt: string,
  maxTtlSeconds: number,
  now: Date,
): void {
  const exp = decodeJwtExp(jwt);
  const nowSec = Math.floor(now.getTime() / 1000);
  if (exp === undefined) {
    throw new InvalidRunError(
      "run.jwt has no readable 'exp' claim — refusing to pass a non-expiring bearer token by value into the ACA execution template (retrievable via the ARM plane). Mint a short-TTL JWT or use run.jwtSecretName.",
    );
  }
  if (exp <= nowSec) {
    throw new InvalidRunError("run.jwt is already expired");
  }
  if (exp - nowSec > maxTtlSeconds) {
    throw new InvalidRunError(
      `run.jwt TTL ${exp - nowSec}s exceeds the max ${maxTtlSeconds}s allowed for a by-value run token (ARM-plane exposure). Shorten the TTL or use run.jwtSecretName.`,
    );
  }
}

/**
 * Validate isolation-critical invariants before a run is allowed to dispatch.
 * Fails closed: any missing binding aborts the run rather than falling back to
 * a shared/unscoped execution.
 */
export function assertRunIsIsolated(run: ExecutionRun): void {
  if (!run.runId?.trim()) throw new InvalidRunError("run.runId is required");
  assertValidEngagementId(run.engagementId);
  if (!run.managedIdentityResourceId?.trim()) {
    throw new InvalidRunError(
      "run.managedIdentityResourceId is required — every run must bind a per-engagement managed identity (PRD §3.6)",
    );
  }
  if (!run.jwt?.trim()) {
    throw new InvalidRunError("run.jwt is required");
  }
  assertEgressPolicy(run.egress ?? DEFAULT_EGRESS_POLICY);
}

/** Build the env-var list for the run, secrets-by-reference only. */
export function buildEnv(run: ExecutionRun): ContainerEnvVar[] {
  const env: ContainerEnvVar[] = [];

  // Non-secret scalars first.
  env.push({ name: ENGAGEMENT_ENV_NAME, value: run.engagementId });
  if (run.workspacePath) {
    env.push({ name: WORKSPACE_ENV_NAME, value: run.workspacePath });
  }
  for (const [name, value] of Object.entries(run.env ?? {})) {
    env.push({ name, value });
  }

  // Run JWT. Prefer a keyless secretRef (no ARM-plane plaintext). Only when no
  // jwtSecretName is supplied is it passed by value — and the backend enforces
  // a short TTL on that path (see assertShortLivedJwt) so the ARM-plane exposure
  // is bounded.
  const jwtEnvName = run.jwtEnvName ?? "PAPERCLIP_RUN_JWT";
  if (run.jwtSecretName?.trim()) {
    env.push({ name: jwtEnvName, secretRef: run.jwtSecretName });
  } else {
    env.push({ name: jwtEnvName, value: run.jwt });
  }

  // Key Vault-backed secrets: by REFERENCE only (keyless). Never a literal.
  for (const ref of run.secretRefs ?? []) {
    if (!ref.envName?.trim() || !ref.secretName?.trim()) {
      throw new InvalidRunError(
        `invalid secretRef: both envName and secretName are required (got ${JSON.stringify(ref)})`,
      );
    }
    env.push({ name: ref.envName, secretRef: ref.secretName });
  }

  return env;
}

/**
 * Build the ACA Job execution-template override for a run. This is the value
 * assigned to `JobsStartOptionalParams.template`.
 *
 * ACA Start override semantics: the supplied template **replaces** the matching
 * job container (matched by `name`) for that execution; it does not deep-merge
 * with the job-defined container. Two consequences enforced here:
 *  1. The container `name` MUST equal the job's container name
 *     ({@link AGENT_CONTAINER_NAME} = "agent") or the override is ignored and
 *     the run can start with no/wrong env — including dropping job-defined
 *     `secretRef` env. We always emit that exact name.
 *  2. An `image` MUST be set or the replaced container has no image and the
 *     start fails. We require `run.image` or a `defaultImage` from the backend.
 *
 * Note: identity, network/egress, and the Key Vault secret *definitions* live
 * on the Job resource (Terraform), not in this override.
 */
export function buildExecutionTemplate(
  run: ExecutionRun,
  opts: { defaultImage?: string | undefined } = {},
): ExecutionTemplate {
  assertRunIsIsolated(run);
  const image = run.image ?? opts.defaultImage;
  if (!image?.trim()) {
    throw new InvalidRunError(
      "no container image for the start override — set run.image or configure the backend's defaultImage. " +
        "An ACA Start template override REPLACES the job container by name, so omitting the image fails the start and drops job-defined secretRef env.",
    );
  }
  const container: ExecutionTemplateContainer = {
    name: AGENT_CONTAINER_NAME,
    image,
    env: buildEnv(run),
  };
  if (run.command) container.command = run.command;
  if (run.args) container.args = run.args;
  return { containers: [container] };
}

/** Map a raw ACA execution state to Paperclip's normalized status. */
export function mapAcaStatus(state: string | undefined): ExecutionStatus {
  switch (state) {
    case "Running":
    case "Processing":
      return "running";
    case "Succeeded":
      return "succeeded";
    case "Failed":
    case "Degraded":
      return "failed";
    case "Stopped":
      return "cancelled";
    case undefined:
    case "":
      return "pending";
    default:
      return "unknown";
  }
}
