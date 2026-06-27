/**
 * @securityos/aca-jobs-backend
 *
 * Paperclip execution backend that runs each agent run as an ephemeral Azure
 * Container Apps Job. Drop-in for Paperclip's invoke/status/cancel contract.
 *
 * @example
 * ```ts
 * import { AcaJobsExecutionBackend } from "@securityos/aca-jobs-backend";
 *
 * const backend = new AcaJobsExecutionBackend({
 *   subscriptionId: process.env.AZURE_SUBSCRIPTION_ID!,
 *   resourceGroupName: "rg-securityos-orchestration",
 *   audit: (e) => logAnalytics.track(e),
 * });
 *
 * const handle = await backend.invoke(run);   // start ephemeral ACA Job exec
 * const s = await backend.status(handle);     // running | succeeded | failed | ...
 * await backend.cancel(handle);               // stop execution
 * ```
 */

export {
  AcaJobsExecutionBackend,
  type AcaJobResource,
  type AcaJobsBackendConfig,
  type AcaJobsClient,
  type AuditEvent,
  type AuditSink,
  type ExecutionHandle,
} from "./executionBackend.js";

export {
  assertRunIsIsolated,
  assertValidEngagementId,
  assertEgressPolicy,
  assertShortLivedJwt,
  decodeJwtExp,
  buildEnv,
  buildExecutionTemplate,
  buildEgressAllowlist,
  buildEgressPolicy,
  mapAcaStatus,
  DEFAULT_EGRESS_POLICY,
  DEFAULT_MAX_JWT_TTL_SECONDS,
  ENGAGEMENT_ID_PATTERN,
  FORBIDDEN_COARSE_EGRESS,
  InvalidRunError,
  AGENT_CONTAINER_NAME,
  ENGAGEMENT_ENV_NAME,
  WORKSPACE_ENV_NAME,
  type AcaJobExecutionState,
  type ContainerEnvVar,
  type EgressPolicy,
  type EgressTargets,
  type ExecutionRun,
  type ExecutionStatus,
  type ExecutionTemplate,
  type ExecutionTemplateContainer,
  type SecretEnvRef,
} from "./jobSpec.js";
