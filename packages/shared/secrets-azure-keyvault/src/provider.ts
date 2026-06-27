/**
 * Azure Key Vault secrets provider for the Paperclip orchestration layer.
 *
 * Drop-in replacement for Paperclip's AWS Secrets Manager provider. Contract
 * (from the AWS impl we are mirroring, fork-plan §3.3 / PRD §11.1):
 *
 *   - The DB stores ONLY metadata + version references. Plaintext secret
 *     values NEVER touch the database — they live in Key Vault and are
 *     returned in-memory at runtime only.
 *   - Authentication is keyless: a Microsoft Entra managed identity via
 *     `ManagedIdentityCredential` pinned to an explicit `managedIdentityClientId`
 *     (NOT `DefaultAzureCredential`, whose chain could pick up a stray
 *     `AZURE_CLIENT_SECRET`). No API keys, no connection strings, no secrets in
 *     code or config.
 *   - Isolation is bound at the cloud boundary: the provider is tied to one
 *     engagement scope (from the run identity/env), and any operation whose
 *     caller-supplied scope does not match is denied (deny-by-default). The
 *     real boundary is one Key Vault per engagement / per-secret RBAC.
 *   - Audit is MANDATORY and fail-closed: the constructor throws without an
 *     audit hook, and every read/write/delete/list/getVersion event is awaited
 *     before a result is returned — a failing sink fails closed (no unaudited
 *     plaintext). The caller persists events (to `secret_access_events`,
 *     forwarded to Log Analytics). The provider does not own the audit store.
 *   - Strict mode (default ON; `PAPERCLIP_SECRETS_STRICT_MODE=false` to opt out)
 *     forbids resolving secrets from inline environment variables.
 */
import { ManagedIdentityCredential, type TokenCredential } from "@azure/identity";
import { SecretClient } from "@azure/keyvault-secrets";
import {
  type SecretScope,
  secretName as buildSecretName,
  scopeTags,
  logicalKeyFromTags,
} from "./naming.js";

export type { SecretScope } from "./naming.js";

/** Metadata safe to persist in the application database (no plaintext). */
export interface SecretMetadata {
  /** Logical key as supplied by the caller (e.g. "openai-api-key"). */
  key: string;
  /** Resolved Key Vault secret name (`paperclip-{deployment}-{engagement}-{key}`). */
  secretName: string;
  /** Key Vault version identifier — the version ref persisted in the DB. */
  version: string;
  scope: SecretScope;
  enabled?: boolean;
  createdOn?: Date;
  updatedOn?: Date;
}

/** Metadata plus the plaintext value. The `value` must NEVER be persisted. */
export interface SecretValue extends SecretMetadata {
  /** Plaintext secret material. In-memory, runtime-only. */
  value: string;
}

export type SecretAction = "get" | "set" | "list" | "delete" | "get-version" | "inline-env";
export type SecretOutcome = "success" | "denied" | "error";

/**
 * Audit event emitted on every secret-plane operation. Mirrors the AWS
 * provider's `secret_access_events` row. Contains identifiers only — no
 * plaintext secret material is ever placed in an audit event.
 */
export interface SecretAccessEvent {
  action: SecretAction;
  outcome: SecretOutcome;
  /** ISO-8601 timestamp. */
  timestamp: string;
  scope: SecretScope;
  /** Logical key, when known. */
  key?: string;
  /** Key Vault secret name, when resolved. */
  secretName?: string;
  /** Key Vault version ref, when applicable. */
  version?: string;
  /** Identity/principal performing the operation (agent run id, user, etc.). */
  caller?: string;
  /** Error class/message on failure (never includes secret values). */
  error?: string;
}

/** Hook invoked for every operation. Caller persists the event. */
export type AuditHook = (event: SecretAccessEvent) => void | Promise<void>;

/** The provider contract Paperclip binds against. */
export interface SecretsProvider {
  get(scope: SecretScope, key: string, caller?: string): Promise<SecretValue>;
  getVersion(
    scope: SecretScope,
    key: string,
    version: string,
    caller?: string,
  ): Promise<SecretValue>;
  set(scope: SecretScope, key: string, value: string, caller?: string): Promise<SecretMetadata>;
  list(scope: SecretScope, caller?: string): Promise<SecretMetadata[]>;
  delete(scope: SecretScope, key: string, caller?: string): Promise<void>;
}

/** Minimal surface of `@azure/keyvault-secrets` `SecretClient` we depend on. */
export interface KeyVaultSecretClientLike {
  setSecret(
    name: string,
    value: string,
    options?: { tags?: Record<string, string>; enabled?: boolean },
  ): Promise<{ value?: string; name: string; properties: SecretPropertiesLike }>;
  getSecret(
    name: string,
    options?: { version?: string },
  ): Promise<{ value?: string; name: string; properties: SecretPropertiesLike }>;
  beginDeleteSecret(name: string): Promise<{ pollUntilDone(): Promise<unknown> }>;
  listPropertiesOfSecrets(): AsyncIterable<SecretPropertiesLike>;
}

interface SecretPropertiesLike {
  name: string;
  version?: string;
  enabled?: boolean;
  createdOn?: Date;
  updatedOn?: Date;
  tags?: Record<string, string>;
}

export interface KeyVaultSecretsProviderOptions {
  /** Vault data-plane URL, e.g. https://kv-eng-001.vault.azure.net. Defaults to AZURE_KEYVAULT_URL. */
  vaultUrl?: string;
  /** Pre-built SecretClient (used in tests / advanced wiring). */
  client?: KeyVaultSecretClientLike;
  /**
   * Credential override. When omitted, a `ManagedIdentityCredential` is pinned
   * to {@link managedIdentityClientId} — we deliberately do NOT use
   * `DefaultAzureCredential`, whose chain could silently pick up a stray
   * `AZURE_CLIENT_SECRET`/env-var credential and violate the keyless posture.
   */
  credential?: TokenCredential;
  /**
   * Explicit user-assigned managed identity client id to pin the credential to.
   * Defaults to `AZURE_CLIENT_ID` / `AZURE_MANAGED_IDENTITY_CLIENT_ID`. Required
   * (unless a `client`/`credential` is injected) so the run can only authenticate
   * as its own engagement-scoped identity.
   */
  managedIdentityClientId?: string;
  /**
   * Audit sink — MANDATORY. The constructor throws if it is absent, and a
   * failing sink fails CLOSED (a secret read will not return plaintext that
   * could not be audited). The caller persists each event.
   */
  audit: AuditHook;
  /**
   * Engagement scope this provider instance is bound to (the cloud-boundary
   * isolation seam). When set, every operation's caller-supplied `scope` MUST
   * match it or the operation is denied (deny-by-default). Derived by default
   * from `PAPERCLIP_DEPLOYMENT_ID` + `PAPERCLIP_ENGAGEMENT_ID`, which the
   * per-engagement ACA Job sets from its bound managed identity — so the run
   * identity, not a caller arg, decides what it may touch. Leave unset only for
   * a trusted multi-engagement orchestrator that holds broad vault RBAC.
   */
  engagementBinding?: SecretScope;
  /**
   * Principal/identity attributed to operations that don't pass an explicit
   * `caller`. Defaults to `PAPERCLIP_PRINCIPAL` / the pinned managed-identity
   * client id, i.e. the authenticated identity. A caller is always required
   * (per-call or via this default); operations with no resolvable principal are
   * rejected so every audit event is attributable.
   */
  principal?: string;
  /**
   * Forbid resolving secrets from inline env vars. Defaults to TRUE
   * (deny inline-env secrets); set `PAPERCLIP_SECRETS_STRICT_MODE=false` or pass
   * `strictMode: false` to opt out.
   */
  strictMode?: boolean;
  /**
   * Permit operating WITHOUT an engagement binding (cross-engagement). Defaults
   * to FALSE — deny-by-default: an unbound provider refuses every operation
   * unless this is explicitly enabled (or `PAPERCLIP_ALLOW_MULTI_ENGAGEMENT=true`).
   * Only a trusted multi-engagement orchestrator that holds broad vault RBAC
   * should set this; per-engagement runs must instead pass `engagementBinding`.
   */
  allowMultiEngagement?: boolean;
  /** Block deletes from waiting on Key Vault's delete poller (faster path). Default false. */
  skipDeleteWait?: boolean;
}

export class StrictModeViolationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StrictModeViolationError";
  }
}

/** Thrown when a caller-supplied scope does not match the bound engagement scope. */
export class ScopeIsolationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ScopeIsolationError";
  }
}

/** Thrown when no principal/caller can be resolved for an operation. */
export class CallerRequiredError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CallerRequiredError";
  }
}

/** Thrown when the mandatory audit sink is missing at construction time. */
export class AuditRequiredError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuditRequiredError";
  }
}

/**
 * Thrown when the audit sink fails. The provider fails CLOSED on audit failure:
 * a secret read/write whose audit event could not be recorded surfaces this
 * error instead of returning unaudited plaintext.
 */
export class AuditSinkError extends Error {
  constructor(action: SecretAction, cause: unknown) {
    super(
      `audit sink failed for "${action}"; failing closed (no unaudited secret access): ` +
        (cause instanceof Error ? cause.message : String(cause)),
    );
    this.name = "AuditSinkError";
    (this as { cause?: unknown }).cause = cause;
  }
}

/**
 * Derive the engagement binding from the run environment. The per-engagement
 * ACA Job injects these (alongside its bound managed identity) so the run's
 * scope comes from the identity/platform, not from a caller arg.
 */
function scopeFromEnv(): SecretScope | undefined {
  const deploymentId = process.env.PAPERCLIP_DEPLOYMENT_ID;
  const engagementId = process.env.PAPERCLIP_ENGAGEMENT_ID;
  if (deploymentId && engagementId) {
    return { deploymentId, engagementId };
  }
  return undefined;
}

export class KeyVaultSecretsProvider implements SecretsProvider {
  private readonly client: KeyVaultSecretClientLike;
  private readonly audit: AuditHook;
  public readonly strictMode: boolean;
  private readonly skipDeleteWait: boolean;
  /** Engagement scope this instance is bound to; undefined => only valid if allowMultiEngagement. */
  public readonly engagementBinding?: SecretScope;
  /** Explicit opt-in to operate unbound (cross-engagement). Default false (deny-by-default). */
  public readonly allowMultiEngagement: boolean;
  private readonly principal?: string;

  constructor(options: KeyVaultSecretsProviderOptions) {
    // Immutable-audit posture: the audit sink is MANDATORY and fails closed.
    if (!options || typeof options.audit !== "function") {
      throw new AuditRequiredError(
        "KeyVaultSecretsProvider: an `audit` sink is required. Secret access must be " +
          "auditable; refusing to construct a provider that could read secrets unaudited.",
      );
    }
    this.audit = options.audit;

    // Default-deny inline env secrets (strict mode ON unless explicitly disabled).
    this.strictMode =
      options.strictMode ?? process.env.PAPERCLIP_SECRETS_STRICT_MODE !== "false";
    this.skipDeleteWait = options.skipDeleteWait ?? false;

    // Bind to the engagement scope carried by the run identity / environment.
    this.engagementBinding = options.engagementBinding ?? scopeFromEnv();
    // Deny-by-default: an unbound provider is inert unless multi-engagement is
    // explicitly opted into (never implied by a missing binding).
    this.allowMultiEngagement =
      options.allowMultiEngagement ??
      process.env.PAPERCLIP_ALLOW_MULTI_ENGAGEMENT === "true";

    // Pinned managed-identity client id (used both to pin the credential and as
    // the default attributed principal — i.e. the authenticated identity).
    const clientId =
      options.managedIdentityClientId ??
      process.env.AZURE_CLIENT_ID ??
      process.env.AZURE_MANAGED_IDENTITY_CLIENT_ID;
    this.principal = options.principal ?? process.env.PAPERCLIP_PRINCIPAL ?? clientId;

    if (options.client) {
      this.client = options.client;
    } else {
      const vaultUrl = options.vaultUrl ?? process.env.AZURE_KEYVAULT_URL;
      if (!vaultUrl) {
        throw new Error(
          "KeyVaultSecretsProvider: vaultUrl is required (set AZURE_KEYVAULT_URL or pass options.vaultUrl).",
        );
      }
      // Keyless: pin to the engagement's user-assigned managed identity. We do
      // NOT fall back to DefaultAzureCredential's chain, which could silently
      // authenticate with a stray AZURE_CLIENT_SECRET / env credential.
      let credential = options.credential;
      if (!credential) {
        if (!clientId) {
          throw new Error(
            "KeyVaultSecretsProvider: managedIdentityClientId is required (set AZURE_CLIENT_ID) " +
              "so the provider can only authenticate as its own engagement-scoped managed identity " +
              "and a stray AZURE_CLIENT_SECRET cannot be used.",
          );
        }
        credential = new ManagedIdentityCredential({ clientId });
      }
      this.client = new SecretClient(vaultUrl, credential) as unknown as KeyVaultSecretClientLike;
    }
  }

  /**
   * Emit an audit event. FAILS CLOSED: if the sink throws, this rethrows an
   * {@link AuditSinkError}, so a successful secret read whose access could not
   * be audited never returns plaintext to the caller.
   */
  private async emit(event: SecretAccessEvent): Promise<void> {
    try {
      await this.audit(event);
    } catch (cause) {
      throw new AuditSinkError(event.action, cause);
    }
  }

  /**
   * Resolve the attributed principal and enforce engagement-scope isolation
   * BEFORE any Key Vault call. On rejection a `denied` audit event is emitted
   * (best-effort) and the operation throws — deny-by-default on a missing or
   * mismatched scope. Returns the effective caller to attribute the operation.
   */
  private async authorize(
    action: SecretAction,
    scope: SecretScope,
    key: string | undefined,
    caller: string | undefined,
  ): Promise<string> {
    const principal = caller ?? this.principal;
    if (!principal || `${principal}`.trim() === "") {
      const err = new CallerRequiredError(
        `secret "${action}" requires a caller/principal; none supplied and no bound principal ` +
          "is configured (set options.principal / PAPERCLIP_PRINCIPAL / AZURE_CLIENT_ID).",
      );
      await this.emit({
        action,
        outcome: "denied",
        timestamp: new Date().toISOString(),
        scope,
        key,
        caller,
        error: err.message,
      });
      throw err;
    }

    // Deny-by-default: an unbound provider refuses unless multi-engagement was
    // explicitly enabled. A missing binding NEVER implies "allow all scopes".
    if (!this.engagementBinding && !this.allowMultiEngagement) {
      const err = new ScopeIsolationError(
        `deny-by-default: provider is not bound to an engagement scope and ` +
          `allowMultiEngagement is not enabled; refusing "${action}" on ` +
          `${scope?.deploymentId}/${scope?.engagementId}. Pass engagementBinding ` +
          `for per-engagement runs, or set allowMultiEngagement for a trusted orchestrator.`,
      );
      await this.emit({
        action,
        outcome: "denied",
        timestamp: new Date().toISOString(),
        scope,
        key,
        caller: principal,
        error: err.message,
      });
      throw err;
    }

    if (
      this.engagementBinding &&
      (scope.deploymentId !== this.engagementBinding.deploymentId ||
        scope.engagementId !== this.engagementBinding.engagementId)
    ) {
      const err = new ScopeIsolationError(
        `cross-engagement access denied: this run is bound to ` +
          `${this.engagementBinding.deploymentId}/${this.engagementBinding.engagementId} but the ` +
          `requested scope was ${scope?.deploymentId}/${scope?.engagementId}.`,
      );
      await this.emit({
        action,
        outcome: "denied",
        timestamp: new Date().toISOString(),
        scope,
        key,
        caller: principal,
        error: err.message,
      });
      throw err;
    }

    return principal;
  }

  async get(scope: SecretScope, key: string, caller?: string): Promise<SecretValue> {
    const principal = await this.authorize("get", scope, key, caller);
    const name = buildSecretName(scope, key);
    let value: SecretValue;
    try {
      const secret = await this.client.getSecret(name);
      value = this.toValue(scope, key, secret);
    } catch (err) {
      await this.emitError("get", scope, key, name, principal, err);
      throw err;
    }
    // Fail closed: only return plaintext once the access has been audited.
    await this.emit({
      action: "get",
      outcome: "success",
      timestamp: new Date().toISOString(),
      scope,
      key,
      secretName: name,
      version: value.version,
      caller: principal,
    });
    return value;
  }

  async getVersion(
    scope: SecretScope,
    key: string,
    version: string,
    caller?: string,
  ): Promise<SecretValue> {
    const principal = await this.authorize("get-version", scope, key, caller);
    const name = buildSecretName(scope, key);
    let value: SecretValue;
    try {
      const secret = await this.client.getSecret(name, { version });
      value = this.toValue(scope, key, secret);
    } catch (err) {
      await this.emitError("get-version", scope, key, name, principal, err, version);
      throw err;
    }
    // Fail closed: only return plaintext once the access has been audited.
    await this.emit({
      action: "get-version",
      outcome: "success",
      timestamp: new Date().toISOString(),
      scope,
      key,
      secretName: name,
      version: value.version,
      caller: principal,
    });
    return value;
  }

  async set(
    scope: SecretScope,
    key: string,
    value: string,
    caller?: string,
  ): Promise<SecretMetadata> {
    const principal = await this.authorize("set", scope, key, caller);
    const name = buildSecretName(scope, key);
    let meta: SecretMetadata;
    try {
      const secret = await this.client.setSecret(name, value, {
        tags: scopeTags(scope, key),
      });
      meta = this.toMetadata(scope, key, secret.properties);
    } catch (err) {
      await this.emitError("set", scope, key, name, principal, err);
      throw err;
    }
    // Fail closed: a write that could not be audited surfaces an error.
    await this.emit({
      action: "set",
      outcome: "success",
      timestamp: new Date().toISOString(),
      scope,
      key,
      secretName: name,
      version: meta.version,
      caller: principal,
    });
    return meta;
  }

  /**
   * List the calling engagement's secrets. NOTE: `listPropertiesOfSecrets`
   * enumerates the ENTIRE vault and we filter by tag in-process — so this
   * requires list permission over the whole vault and is O(all secrets). With a
   * shared vault that means the run can *enumerate* (names/tags of) other
   * engagements' secrets even though it cannot read their values; this is the
   * core reason the cloud-boundary design is ONE KEY VAULT PER ENGAGEMENT (or
   * per-secret RBAC), so a vault only ever contains a single engagement's secrets.
   */
  async list(scope: SecretScope, caller?: string): Promise<SecretMetadata[]> {
    const principal = await this.authorize("list", scope, undefined, caller);
    let results: SecretMetadata[];
    try {
      results = [];
      for await (const props of this.client.listPropertiesOfSecrets()) {
        const recovered = logicalKeyFromTags(props.tags);
        if (
          !recovered ||
          recovered.scope.deploymentId !== scope.deploymentId ||
          recovered.scope.engagementId !== scope.engagementId
        ) {
          continue; // Strictly scoped to this engagement — cross-scope is invisible.
        }
        results.push(this.toMetadata(scope, recovered.key, props));
      }
    } catch (err) {
      await this.emitError("list", scope, undefined, undefined, principal, err);
      throw err;
    }
    await this.emit({
      action: "list",
      outcome: "success",
      timestamp: new Date().toISOString(),
      scope,
      caller: principal,
    });
    return results;
  }

  async delete(scope: SecretScope, key: string, caller?: string): Promise<void> {
    const principal = await this.authorize("delete", scope, key, caller);
    const name = buildSecretName(scope, key);
    try {
      const poller = await this.client.beginDeleteSecret(name);
      if (!this.skipDeleteWait) {
        await poller.pollUntilDone();
      }
    } catch (err) {
      await this.emitError("delete", scope, key, name, principal, err);
      throw err;
    }
    await this.emit({
      action: "delete",
      outcome: "success",
      timestamp: new Date().toISOString(),
      scope,
      key,
      secretName: name,
      caller: principal,
    });
  }

  /**
   * Resolve a secret that some callers might want to read from an inline env
   * var. In strict mode this path is FORBIDDEN and throws — env-injected
   * plaintext secrets defeat private-by-default / keyless posture. Outside
   * strict mode it returns the env value and emits an audit event so the
   * insecure fallback is always visible.
   */
  async resolveInlineEnv(
    scope: SecretScope,
    key: string,
    envVarName: string,
    caller?: string,
  ): Promise<string> {
    const principal = await this.authorize("inline-env", scope, key, caller);
    if (this.strictMode) {
      await this.emit({
        action: "inline-env",
        outcome: "denied",
        timestamp: new Date().toISOString(),
        scope,
        key,
        caller: principal,
        error: `inline env secret "${envVarName}" forbidden in strict mode`,
      });
      throw new StrictModeViolationError(
        `Inline env secret "${envVarName}" is forbidden when PAPERCLIP_SECRETS_STRICT_MODE is enabled; ` +
          `store it in Key Vault and read it via the secrets provider.`,
      );
    }
    const value = process.env[envVarName];
    if (value === undefined) {
      await this.emitError(
        "inline-env",
        scope,
        key,
        undefined,
        principal,
        new Error(`env var "${envVarName}" is not set`),
      );
      throw new Error(`Inline env secret "${envVarName}" is not set.`);
    }
    await this.emit({
      action: "inline-env",
      outcome: "success",
      timestamp: new Date().toISOString(),
      scope,
      key,
      caller: principal,
    });
    return value;
  }

  private toValue(
    scope: SecretScope,
    key: string,
    secret: { value?: string; properties: SecretPropertiesLike },
  ): SecretValue {
    return {
      ...this.toMetadata(scope, key, secret.properties),
      value: secret.value ?? "",
    };
  }

  private toMetadata(
    scope: SecretScope,
    key: string,
    props: SecretPropertiesLike,
  ): SecretMetadata {
    return {
      key,
      secretName: props.name,
      version: props.version ?? "",
      scope,
      enabled: props.enabled,
      createdOn: props.createdOn,
      updatedOn: props.updatedOn,
    };
  }

  private async emitError(
    action: SecretAction,
    scope: SecretScope,
    key: string | undefined,
    secretName: string | undefined,
    caller: string | undefined,
    err: unknown,
    version?: string,
  ): Promise<void> {
    await this.emit({
      action,
      outcome: "error",
      timestamp: new Date().toISOString(),
      scope,
      key,
      secretName,
      version,
      caller,
      error: err instanceof Error ? `${err.name}: ${err.message}` : String(err),
    });
  }
}
