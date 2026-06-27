/**
 * Key Vault secret naming for the Paperclip Azure secrets provider.
 *
 * Mirrors the AWS Secrets Manager provider's naming contract
 * (`paperclip/{deploymentId}/{engagementId}/{key}`) but rewrites it to the
 * stricter Key Vault rule set:
 *
 *   - Key Vault object names match `^[0-9a-zA-Z-]{1,127}$`
 *     (alphanumerics and dashes only; max 127 chars).
 *     See: https://learn.microsoft.com/azure/key-vault/general/about-keys-secrets-certificates#vault-name-and-object-name
 *
 * Because `/`, `_`, `.` and other separators are illegal, the path-style name
 * becomes a dash-joined name: `paperclip-{deploymentId}-{engagementId}-{key}`.
 *
 * Sanitization is deterministic so the same logical secret always resolves to
 * the same Key Vault name.
 *
 * COLLISION SAFETY: sanitizing then dash-joining is ambiguous on its own —
 * `({engagementId:'a-b'}, 'c')` and `({engagementId:'a'}, 'b-c')` would both
 * render `paperclip-{dep}-a-b-c`. To guarantee distinct (deployment, engagement,
 * key) tuples NEVER map to the same Key Vault object name, every name carries a
 * fixed-length hash of the *canonical, length-unambiguous* tuple. The readable
 * dash-joined prefix is best-effort (and may be truncated to fit 127 chars); the
 * hash suffix is what actually disambiguates, so two tuples that sanitize to the
 * same prefix (or collide after truncation) still resolve to different names.
 */
import { createHash } from "node:crypto";

export const KV_NAME_MAX = 127;
export const NAME_PREFIX = "paperclip";

/** Hex length of the canonical-tuple hash. 48 bits — negligible collision risk. */
const HASH_HEX_LEN = 12;
/** Length of the hash suffix (`-` + HASH_HEX_LEN hex chars) appended to every name. */
const HASH_SUFFIX_LEN = HASH_HEX_LEN + 1;

export interface SecretScope {
  /** Paperclip deployment / instance identifier. */
  deploymentId: string;
  /** Engagement == Paperclip "company" identifier (isolation boundary). */
  engagementId: string;
}

/**
 * Replace every character that is not `[0-9a-zA-Z-]` with a dash, collapse
 * runs of dashes, and trim leading/trailing dashes. Empty input yields "".
 */
export function sanitizeSegment(segment: string): string {
  return segment
    .normalize("NFKD")
    .replace(/[^0-9a-zA-Z-]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function assertNonEmpty(name: string, value: string): void {
  if (value === undefined || value === null || `${value}`.trim() === "") {
    throw new Error(`secret naming: "${name}" must be a non-empty string`);
  }
}

/**
 * Length-unambiguous canonical encoding of the (deployment, engagement, key)
 * tuple, used as the hash input. Each raw segment is prefixed with its byte
 * length so no choice of separators inside a segment can be confused with the
 * boundary between segments. This is what makes the hash collision-free across
 * distinct tuples regardless of how they sanitize.
 */
function canonicalTuple(deploymentId: string, engagementId: string, key: string): string {
  const enc = (s: string) => `${Buffer.byteLength(s, "utf8")}:${s}`;
  return [enc(deploymentId), enc(engagementId), enc(key)].join("|");
}

/** Fixed-length hash of the canonical tuple — the disambiguating name suffix. */
function tupleHash(deploymentId: string, engagementId: string, key: string): string {
  return createHash("sha256")
    .update(canonicalTuple(deploymentId, engagementId, key))
    .digest("hex")
    .slice(0, HASH_HEX_LEN);
}

/**
 * Compute the Key Vault secret name for a logical key within an engagement
 * scope. Deterministic and idempotent.
 *
 * Shape: `paperclip-{dep}-{engagement}-{key}-{hash}` where `{hash}` is a
 * fixed-length hash of the canonical tuple. The readable prefix may be truncated
 * to keep the whole name <= 127 chars; the hash guarantees uniqueness so
 * distinct tuples never collide even when their readable prefixes are equal.
 */
export function secretName(scope: SecretScope, key: string): string {
  assertNonEmpty("deploymentId", scope?.deploymentId);
  assertNonEmpty("engagementId", scope?.engagementId);
  assertNonEmpty("key", key);

  const parts = [
    NAME_PREFIX,
    sanitizeSegment(scope.deploymentId),
    sanitizeSegment(scope.engagementId),
    sanitizeSegment(key),
  ];

  if (parts.slice(1).some((p) => p === "")) {
    throw new Error(
      `secret naming: a scope/key segment sanitized to empty (parts=${JSON.stringify(parts)})`,
    );
  }

  const hash = tupleHash(scope.deploymentId, scope.engagementId, key);
  const readable = parts.join("-");
  const budget = KV_NAME_MAX - HASH_SUFFIX_LEN;
  const head =
    readable.length <= budget ? readable : readable.slice(0, budget).replace(/-+$/g, "");
  return `${head}-${hash}`;
}

/**
 * Tags written onto every Key Vault secret so the logical scope/key can be
 * recovered on `list` without parsing the (possibly hash-truncated) name.
 * Tag values are not sensitive; they are identifiers only.
 */
export function scopeTags(scope: SecretScope, key: string): Record<string, string> {
  return {
    "paperclip-deployment": scope.deploymentId,
    "paperclip-engagement": scope.engagementId,
    "paperclip-key": key,
    "paperclip-managed": "true",
  };
}

/** Inverse of {@link scopeTags}: recover the logical key from a secret's tags. */
export function logicalKeyFromTags(
  tags: Record<string, string> | undefined,
): { scope: SecretScope; key: string } | undefined {
  if (!tags) return undefined;
  const deploymentId = tags["paperclip-deployment"];
  const engagementId = tags["paperclip-engagement"];
  const key = tags["paperclip-key"];
  if (!deploymentId || !engagementId || !key) return undefined;
  return { scope: { deploymentId, engagementId }, key };
}
