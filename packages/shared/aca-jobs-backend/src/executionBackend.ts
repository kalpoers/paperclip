/**
 * executionBackend.ts
 *
 * Paperclip EXECUTION BACKEND for SecurityOS. Implements the upstream
 * `invoke` / `status` / `cancel` execution contract, but instead of forking a
 * subprocess on the orchestrator host it dispatches each agent run as an
 * **ephemeral Azure Container Apps Job execution**, bound to the engagement's
 * user-assigned managed identity, with keyless Key Vault secret references and
 * deny-by-default egress (PRD R9 / §11.1, fork-plan §3.7).
 *
 * Keyless: the ARM client is constructed with `DefaultAzureCredential` — no API
 * keys, no secrets in code/config. In Azure the orchestrator runs under its own
 * user-assigned managed identity which holds **Container Apps Jobs Contributor**
 * scoped to the Container Apps environment (see README).
 */

import { DefaultAzureCredential, type TokenCredential } from "@azure/identity";
import { ContainerAppsAPIClient } from "@azure/arm-appcontainers";
import {
  assertRunIsIsolated,
  assertShortLivedJwt,
  assertValidEngagementId,
  buildExecutionTemplate,
  DEFAULT_MAX_JWT_TTL_SECONDS,
  mapAcaStatus,
  type ExecutionRun,
  type ExecutionStatus,
  type ExecutionTemplate,
} from "./jobSpec.js";

/**
 * The subset of `ContainerAppsAPIClient` this backend depends on. Declaring it
 * explicitly keeps the backend unit-testable (inject a fake) and tolerant of
 * non-breaking SDK shape changes.
 */
/**
 * Minimal shape of an ACA Job resource as returned by `jobs.get`, exposing the
 * bound managed identity so the backend can CONFIRM (not just claim) which
 * identity a run will actually execute under.
 */
export interface AcaJobResource {
  name?: string;
  id?: string;
  identity?: {
    type?: string;
    /** Keyed by user-assigned MI resource id (ARM, case-insensitive). */
    userAssignedIdentities?: Record<string, unknown> | null;
  } | null;
}

export interface AcaJobsClient {
  jobs: {
    get(resourceGroupName: string, jobName: string): Promise<AcaJobResource>;
    beginStartAndWait(
      resourceGroupName: string,
      jobName: string,
      options?: { template?: ExecutionTemplate },
    ): Promise<{ name?: string; id?: string }>;
    beginStopExecutionAndWait(
      resourceGroupName: string,
      jobName: string,
      jobExecutionName: string,
      options?: unknown,
    ): Promise<unknown>;
  };
  jobsExecutions: {
    list(
      resourceGroupName: string,
      jobName: string,
      options?: unknown,
    ): AsyncIterable<{ name?: string; status?: string }>;
  };
}

/** Immutable-audit event emitted for every backend action (PRD R9). */
export interface AuditEvent {
  action: "invoke" | "status" | "cancel";
  runId: string;
  engagementId: string;
  agentId: string;
  jobName: string;
  executionName?: string;
  /** Identity the caller CLAIMED for the run (from `ExecutionRun`). */
  managedIdentityResourceId: string;
  /**
   * Identity the run will ACTUALLY execute under, read back from ARM (`jobs.get`)
   * on invoke. Present (and == managedIdentityResourceId) only after the binding
   * was confirmed; absence/mismatch means the run was refused.
   */
  boundManagedIdentityResourceId?: string;
  /** True only when the ARM-confirmed bound identity matched the claim. */
  identityVerified?: boolean;
  status?: ExecutionStatus;
  at: string; // ISO-8601
  error?: string;
}

/** Sink for audit events. Wire to Log Analytics / `activity` table. */
export type AuditSink = (event: AuditEvent) => void;

export interface AcaJobsBackendConfig {
  /** Azure subscription id hosting the Container Apps environment. */
  subscriptionId: string;
  /** Resource group containing the per-engagement ACA Job resources. */
  resourceGroupName: string;
  /**
   * Resolve a Paperclip engagement id to the name of its pre-provisioned ACA
   * Job resource. Defaults to `${jobNamePrefix}${engagementId}`. The job MUST
   * already be bound (by Terraform) to the engagement's managed identity, its
   * Key Vault secret references, and the deny-egress environment.
   */
  resolveJobName?: (engagementId: string) => string;
  /** Prefix for the default job-name resolver. Default `caj-eng-`. */
  jobNamePrefix?: string;
  /** Credential override (tests / non-default identity). Default DAC. */
  credential?: TokenCredential;
  /** Pre-built ARM client override (tests). Bypasses credential/subscription. */
  client?: AcaJobsClient;
  /**
   * Immutable-audit sink. REQUIRED — the constructor throws if absent. Audit is
   * a non-negotiable, fail-closed control (PRD §11.1 posture #4); there is no
   * silent no-op fallback. A sink that throws propagates and aborts the action.
   */
  audit: AuditSink;
  /**
   * Default container image for the start-template override, used when a run
   * does not carry its own `image`. An ACA Start override REPLACES the job
   * container, so an image MUST always be present (see buildExecutionTemplate).
   */
  defaultImage?: string;
  /**
   * Max TTL (seconds) for a run JWT passed by value into the execution template
   * (ARM-plane exposure bound). Default {@link DEFAULT_MAX_JWT_TTL_SECONDS}.
   * Ignored when the run uses `jwtSecretName` (keyless secretRef).
   */
  maxJwtTtlSeconds?: number;
  /** Clock override for deterministic tests. */
  now?: () => Date;
}

/** Opaque handle returned by `invoke`, accepted by `status` / `cancel`. */
export interface ExecutionHandle {
  runId: string;
  engagementId: string;
  jobName: string;
  /** ACA Job execution name assigned by Azure at start time. */
  executionName: string;
}

const DEFAULT_JOB_PREFIX = "caj-eng-";

/**
 * Drop-in Paperclip execution backend backed by Azure Container Apps Jobs.
 */
export class AcaJobsExecutionBackend {
  private readonly client: AcaJobsClient;
  private readonly resourceGroupName: string;
  private readonly resolveJobName: (engagementId: string) => string;
  private readonly audit: AuditSink;
  private readonly defaultImage: string | undefined;
  private readonly maxJwtTtlSeconds: number;
  private readonly now: () => Date;

  constructor(config: AcaJobsBackendConfig) {
    // Audit fails CLOSED: refuse to construct a backend with no audit sink so a
    // security-relevant action can never run unaudited (PRD §11.1 posture #4).
    if (typeof config.audit !== "function") {
      throw new Error(
        "AcaJobsBackendConfig.audit is required: an immutable-audit sink must be provided. Audit is fail-closed and must not default to a silent no-op.",
      );
    }
    this.resourceGroupName = config.resourceGroupName;
    const prefix = config.jobNamePrefix ?? DEFAULT_JOB_PREFIX;
    this.resolveJobName =
      config.resolveJobName ?? ((engagementId) => `${prefix}${engagementId}`);
    this.audit = config.audit;
    this.defaultImage = config.defaultImage;
    this.maxJwtTtlSeconds =
      config.maxJwtTtlSeconds ?? DEFAULT_MAX_JWT_TTL_SECONDS;
    this.now = config.now ?? (() => new Date());

    if (config.client) {
      this.client = config.client;
    } else {
      const credential = config.credential ?? new DefaultAzureCredential();
      // Keyless: token-based ARM auth via managed identity. No API keys.
      this.client = new ContainerAppsAPIClient(
        credential,
        config.subscriptionId,
      ) as unknown as AcaJobsClient;
    }
  }

  /** Job resource name for a run's engagement (per-engagement isolation). */
  jobNameFor(run: Pick<ExecutionRun, "engagementId">): string {
    // Sanitize/validate before interpolating into the ARM job name so a crafted
    // engagementId cannot traverse to another engagement's job or inject ARM
    // path segments. Fail-closed on any unexpected character.
    const engagementId = assertValidEngagementId(run.engagementId);
    const name = this.resolveJobName(engagementId);
    if (!name?.trim()) {
      throw new Error(
        `resolveJobName returned empty for engagement '${engagementId}'`,
      );
    }
    return name;
  }

  /**
   * CONFIRM, via an ARM GET, that the resolved job is actually bound to the
   * managed identity the run claims. Audit logging the *claimed* identity is
   * false assurance; an attacker who can influence `resolveJobName` or the
   * claimed id must not be able to land a run on a job bound to a different
   * (e.g. more privileged, or another engagement's) identity. Fail-closed.
   */
  private async confirmBoundIdentity(
    jobName: string,
    expectedMiResourceId: string,
  ): Promise<void> {
    const job = await this.client.jobs.get(this.resourceGroupName, jobName);
    const ids = job.identity?.userAssignedIdentities ?? {};
    const bound = Object.keys(ids).map((k) => k.toLowerCase());
    const expected = expectedMiResourceId.trim().toLowerCase();
    if (!bound.includes(expected)) {
      throw new Error(
        `identity binding mismatch: job '${jobName}' is bound to [${bound.join(", ") || "<none>"}] ` +
          `but the run claims managed identity '${expectedMiResourceId}'. Refusing to dispatch (per-engagement isolation, PRD R1/R9).`,
      );
    }
  }

  /**
   * invoke(run): start an ephemeral ACA Job execution for the run.
   *
   * The execution inherits the Job resource's user-assigned managed identity,
   * Key Vault secret bindings, and deny-egress environment. This call only
   * overrides the per-run container env (run JWT + secret *references* +
   * workspace) and optional command/image.
   */
  async invoke(run: ExecutionRun): Promise<ExecutionHandle> {
    assertRunIsIsolated(run);
    // Bound the ARM-plane exposure of a by-value run JWT (keyless secretRef path
    // — jwtSecretName — needs no TTL check since it is never plaintext).
    if (!run.jwtSecretName?.trim()) {
      assertShortLivedJwt(run.jwt, this.maxJwtTtlSeconds, this.now());
    }
    const jobName = this.jobNameFor(run);
    const template: ExecutionTemplate = buildExecutionTemplate(run, {
      defaultImage: this.defaultImage,
    });

    try {
      // Confirm the job's bound identity BEFORE starting (real assurance, not a
      // claimed value). Throws and audits on mismatch; never dispatches.
      await this.confirmBoundIdentity(jobName, run.managedIdentityResourceId);

      const started = await this.client.jobs.beginStartAndWait(
        this.resourceGroupName,
        jobName,
        { template },
      );
      const executionName = started.name ?? "";
      if (!executionName) {
        throw new Error(
          "ACA job start returned no execution name; cannot track run",
        );
      }
      const handle: ExecutionHandle = {
        runId: run.runId,
        engagementId: run.engagementId,
        jobName,
        executionName,
      };
      this.emit("invoke", run, jobName, {
        executionName,
        boundManagedIdentityResourceId: run.managedIdentityResourceId,
        identityVerified: true,
      });
      return handle;
    } catch (err) {
      this.emit("invoke", run, jobName, {
        error: errMsg(err),
        identityVerified: false,
      });
      throw err;
    }
  }

  /**
   * status(run): poll the execution and return a normalized status. Accepts
   * either the original run or the `ExecutionHandle` from `invoke`.
   */
  async status(
    ref: ExecutionHandle | (ExecutionRun & { executionName: string }),
  ): Promise<ExecutionStatus> {
    const jobName = this.jobNameFor(ref);
    let status: ExecutionStatus = "unknown";
    try {
      for await (const exec of this.client.jobsExecutions.list(
        this.resourceGroupName,
        jobName,
      )) {
        if (exec.name === ref.executionName) {
          status = mapAcaStatus(exec.status);
          break;
        }
      }
      this.emitRef("status", ref, jobName, { status });
      return status;
    } catch (err) {
      this.emitRef("status", ref, jobName, { error: errMsg(err) });
      throw err;
    }
  }

  /** cancel(run): stop the running ACA Job execution. Idempotent-ish. */
  async cancel(
    ref: ExecutionHandle | (ExecutionRun & { executionName: string }),
  ): Promise<void> {
    const jobName = this.jobNameFor(ref);
    try {
      await this.client.jobs.beginStopExecutionAndWait(
        this.resourceGroupName,
        jobName,
        ref.executionName,
      );
      this.emitRef("cancel", ref, jobName, { status: "cancelled" });
    } catch (err) {
      this.emitRef("cancel", ref, jobName, { error: errMsg(err) });
      throw err;
    }
  }

  private emit(
    action: AuditEvent["action"],
    run: ExecutionRun,
    jobName: string,
    extra: Partial<AuditEvent>,
  ): void {
    this.audit({
      action,
      runId: run.runId,
      engagementId: run.engagementId,
      agentId: run.agentId,
      managedIdentityResourceId: run.managedIdentityResourceId,
      jobName,
      at: this.now().toISOString(),
      ...extra,
    });
  }

  private emitRef(
    action: AuditEvent["action"],
    ref: ExecutionHandle | (ExecutionRun & { executionName: string }),
    jobName: string,
    extra: Partial<AuditEvent>,
  ): void {
    this.audit({
      action,
      runId: ref.runId,
      engagementId: ref.engagementId,
      agentId: "agentId" in ref ? ref.agentId : "",
      managedIdentityResourceId:
        "managedIdentityResourceId" in ref ? ref.managedIdentityResourceId : "",
      jobName,
      executionName: ref.executionName,
      at: this.now().toISOString(),
      ...extra,
    });
  }
}

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
