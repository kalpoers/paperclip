/**
 * @securityos/secrets-azure-keyvault
 *
 * Paperclip-compatible secrets provider backed by Azure Key Vault, using
 * keyless Microsoft Entra managed identity (DefaultAzureCredential).
 *
 * Public surface:
 *   - KeyVaultSecretsProvider — the provider implementation.
 *   - SecretsProvider          — the interface Paperclip binds to.
 *   - naming helpers           — deterministic KV-safe secret names.
 *   - audit event types        — caller persists SecretAccessEvent.
 */
export {
  KeyVaultSecretsProvider,
  StrictModeViolationError,
  ScopeIsolationError,
  CallerRequiredError,
  AuditRequiredError,
  AuditSinkError,
  type SecretsProvider,
  type SecretMetadata,
  type SecretValue,
  type SecretAccessEvent,
  type SecretAction,
  type SecretOutcome,
  type AuditHook,
  type KeyVaultSecretsProviderOptions,
  type KeyVaultSecretClientLike,
} from "./provider.js";

export {
  type SecretScope,
  secretName,
  sanitizeSegment,
  scopeTags,
  logicalKeyFromTags,
  KV_NAME_MAX,
  NAME_PREFIX,
} from "./naming.js";
