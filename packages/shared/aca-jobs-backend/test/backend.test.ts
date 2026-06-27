import { describe, it, expect, vi } from "vitest";
import {
  AcaJobsExecutionBackend,
  type AcaJobsClient,
  type AuditEvent,
} from "../src/executionBackend.js";
import {
  assertRunIsIsolated,
  assertValidEngagementId,
  assertEgressPolicy,
  assertShortLivedJwt,
  buildEgressAllowlist,
  buildExecutionTemplate,
  mapAcaStatus,
  InvalidRunError,
  ENGAGEMENT_ENV_NAME,
  WORKSPACE_ENV_NAME,
  type ExecutionRun,
} from "../src/jobSpec.js";

const ENG_MI =
  "/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-eng-acme";

/** base64url-encode without Node Buffer typing assumptions. */
function b64url(s: string): string {
  const alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const at = (n: number): string => alphabet[n]!;
  let out = "";
  let i = 0;
  for (; i + 2 < s.length; i += 3) {
    const n =
      (s.charCodeAt(i) << 16) | (s.charCodeAt(i + 1) << 8) | s.charCodeAt(i + 2);
    out += at((n >> 18) & 63) + at((n >> 12) & 63) + at((n >> 6) & 63) + at(n & 63);
  }
  if (i < s.length) {
    const rem = s.length - i;
    const b0 = s.charCodeAt(i);
    const b1 = rem > 1 ? s.charCodeAt(i + 1) : 0;
    const n = (b0 << 16) | (b1 << 8);
    out += at((n >> 18) & 63) + at((n >> 12) & 63);
    if (rem > 1) out += at((n >> 6) & 63);
  }
  return out.replace(/\+/g, "-").replace(/\//g, "_");
}

/** Mint a syntactically valid JWT whose exp is `ttlSec` from now. */
function makeJwt(ttlSec = 300): string {
  const exp = Math.floor(Date.now() / 1000) + ttlSec;
  return `${b64url(JSON.stringify({ alg: "none" }))}.${b64url(
    JSON.stringify({ exp, sub: "run-123" }),
  )}.sig`;
}

function makeRun(overrides: Partial<ExecutionRun> = {}): ExecutionRun {
  return {
    runId: "run-123",
    engagementId: "eng-acme",
    agentId: "agent-7",
    managedIdentityResourceId: ENG_MI,
    jwt: makeJwt(),
    image: "examplereg.azurecr.io/securityos/agent:1.2.3",
    secretRefs: [{ envName: "FOUNDRY_ENDPOINT", secretName: "foundry-endpoint" }],
    env: { MODEL_DEPLOYMENT: "gpt-firm-lane" },
    workspacePath: "/work/run-123",
    ...overrides,
  };
}

/** A fake ARM client capturing calls and returning scripted execution state. */
function makeFakeClient(execState = "Running", boundMi: string = ENG_MI) {
  const calls = {
    get: [] as Array<{ rg: string; job: string }>,
    start: [] as Array<{ rg: string; job: string; options: unknown }>,
    stop: [] as Array<{ rg: string; job: string; exec: string }>,
    list: [] as Array<{ rg: string; job: string }>,
  };
  const client: AcaJobsClient = {
    jobs: {
      get: vi.fn(async (rg, job) => {
        calls.get.push({ rg, job });
        return {
          name: job,
          identity: {
            type: "UserAssigned",
            userAssignedIdentities: { [boundMi]: {} },
          },
        };
      }),
      beginStartAndWait: vi.fn(async (rg, job, options) => {
        calls.start.push({ rg, job, options });
        return { name: "exec-abc", id: `/.../${job}/executions/exec-abc` };
      }),
      beginStopExecutionAndWait: vi.fn(async (rg, job, exec) => {
        calls.stop.push({ rg, job, exec });
        return {};
      }),
    },
    jobsExecutions: {
      list: vi.fn((rg, job) => {
        calls.list.push({ rg, job });
        return (async function* () {
          yield { name: "exec-other", status: "Succeeded" };
          yield { name: "exec-abc", status: execState };
        })();
      }),
    },
  };
  return { client, calls };
}

const noopAudit = () => {};

describe("jobSpec", () => {
  it("maps ACA execution states to normalized status", () => {
    expect(mapAcaStatus("Running")).toBe("running");
    expect(mapAcaStatus("Processing")).toBe("running");
    expect(mapAcaStatus("Succeeded")).toBe("succeeded");
    expect(mapAcaStatus("Failed")).toBe("failed");
    expect(mapAcaStatus("Degraded")).toBe("failed");
    expect(mapAcaStatus("Stopped")).toBe("cancelled");
    expect(mapAcaStatus(undefined)).toBe("pending");
    expect(mapAcaStatus("Weird")).toBe("unknown");
  });

  it("injects engagement id, workspace, env, and jwt; secrets by reference only", () => {
    const run = makeRun();
    const tpl = buildExecutionTemplate(run);
    const env = tpl.containers[0]!.env;
    const byName = Object.fromEntries(env.map((e) => [e.name, e]));

    // Container name + image are always present (ACA Start replaces by name).
    expect(tpl.containers[0]!.name).toBe("agent");
    expect(tpl.containers[0]!.image).toBe(run.image);

    expect(byName[ENGAGEMENT_ENV_NAME]!.value).toBe("eng-acme");
    expect(byName[WORKSPACE_ENV_NAME]!.value).toBe("/work/run-123");
    expect(byName["MODEL_DEPLOYMENT"]!.value).toBe("gpt-firm-lane");
    expect(byName["PAPERCLIP_RUN_JWT"]!.value).toBe(run.jwt);

    // Keyless: the KV-backed secret is a reference, never a literal value.
    expect(byName["FOUNDRY_ENDPOINT"]!.secretRef).toBe("foundry-endpoint");
    expect(byName["FOUNDRY_ENDPOINT"]!.value).toBeUndefined();
  });

  it("injects the run JWT by secretRef (keyless) when jwtSecretName is set", () => {
    const tpl = buildExecutionTemplate(
      makeRun({ jwtSecretName: "run-jwt", jwt: makeJwt() }),
    );
    const jwtEnv = tpl.containers[0]!.env.find(
      (e) => e.name === "PAPERCLIP_RUN_JWT",
    )!;
    expect(jwtEnv.secretRef).toBe("run-jwt");
    expect(jwtEnv.value).toBeUndefined(); // never plaintext in the ARM template
  });

  it("requires a container image in the start override (else secretRef env drops)", () => {
    const { image: _omit, ...noImage } = makeRun();
    expect(() => buildExecutionTemplate(noImage as ExecutionRun)).toThrow(
      /image/i,
    );
    // a backend defaultImage satisfies it
    expect(
      buildExecutionTemplate(noImage as ExecutionRun, {
        defaultImage: "reg/agent:def",
      }).containers[0]!.image,
    ).toBe("reg/agent:def");
  });

  it("never emits a secret literal value anywhere in the template", () => {
    const tpl = buildExecutionTemplate(makeRun());
    const serialized = JSON.stringify(tpl);
    for (const e of tpl.containers[0]!.env) {
      if (e.secretRef) expect(e.value).toBeUndefined();
    }
    expect(serialized).not.toContain('"value":"foundry-endpoint"');
  });

  it("fails closed when isolation invariants are missing", () => {
    expect(() => assertRunIsIsolated(makeRun({ engagementId: "" }))).toThrow(
      InvalidRunError,
    );
    expect(() =>
      assertRunIsIsolated(makeRun({ managedIdentityResourceId: "" })),
    ).toThrow(/managed identity/i);
    expect(() => assertRunIsIsolated(makeRun({ jwt: "" }))).toThrow(InvalidRunError);
    expect(() =>
      assertRunIsIsolated(
        makeRun({ egress: { mode: "deny" as const, allowedFqdns: [] } }),
      ),
    ).not.toThrow();
  });

  it("validates/sanitizes engagementId (injection & collision guard)", () => {
    expect(assertValidEngagementId("eng-acme")).toBe("eng-acme");
    for (const bad of [
      "",
      "ENG-ACME", // uppercase
      "../other", // path traversal
      "eng/acme", // slash
      "-eng", // leading hyphen
      "eng-", // trailing hyphen
      "eng acme", // space
      "a".repeat(33), // too long
    ]) {
      expect(() => assertValidEngagementId(bad)).toThrow(InvalidRunError);
    }
  });

  it("rejects coarse service tags / wildcards in the egress allow-list", () => {
    for (const tag of ["Storage", "AzureCognitiveServices", "*", "Internet"]) {
      expect(() =>
        assertEgressPolicy({ mode: "deny", allowedFqdns: [tag] }),
      ).toThrow(InvalidRunError);
    }
    // per-account FQDNs are accepted
    expect(() =>
      assertEgressPolicy({
        mode: "deny",
        allowedFqdns: ["kv-eng-acme.vault.azure.net", "rag.internal.example.com"],
      }),
    ).not.toThrow();
  });

  it("buildEgressAllowlist scopes to per-account FQDNs incl. enterpriseRAG", () => {
    const list = buildEgressAllowlist({
      keyVaultName: "kv-eng-acme",
      foundryAccountName: "aoai-eng-acme",
      storageAccountName: "stengacme",
      searchServiceName: "srch-eng-acme",
      enterpriseRagHost: "rag.enterprise.example.com",
    });
    expect(list).toContain("kv-eng-acme.vault.azure.net");
    expect(list).toContain("aoai-eng-acme.openai.azure.com");
    expect(list).toContain("stengacme.blob.core.windows.net");
    expect(list).toContain("srch-eng-acme.search.windows.net");
    expect(list).toContain("rag.enterprise.example.com");
    // No coarse tags leaked in.
    expect(list).not.toContain("Storage");
    expect(list).not.toContain("AzureCognitiveServices");
  });

  it("enforces a short TTL on a by-value run JWT", () => {
    const now = new Date();
    const soon = `${b64url(JSON.stringify({}))}.${b64url(
      JSON.stringify({ exp: Math.floor(now.getTime() / 1000) + 120 }),
    )}.s`;
    expect(() => assertShortLivedJwt(soon, 600, now)).not.toThrow();

    const tooLong = `${b64url(JSON.stringify({}))}.${b64url(
      JSON.stringify({ exp: Math.floor(now.getTime() / 1000) + 86400 }),
    )}.s`;
    expect(() => assertShortLivedJwt(tooLong, 600, now)).toThrow(/TTL/);

    const noExp = `${b64url(JSON.stringify({}))}.${b64url(
      JSON.stringify({ sub: "x" }),
    )}.s`;
    expect(() => assertShortLivedJwt(noExp, 600, now)).toThrow(/exp/);
  });
});

describe("AcaJobsExecutionBackend", () => {
  it("invoke starts the per-engagement job with the run template and audits", async () => {
    const { client, calls } = makeFakeClient();
    const audit: AuditEvent[] = [];
    const backend = new AcaJobsExecutionBackend({
      subscriptionId: "sub-1",
      resourceGroupName: "rg-orch",
      client,
      audit: (e) => audit.push(e),
    });

    const handle = await backend.invoke(makeRun());

    expect(handle.executionName).toBe("exec-abc");
    expect(handle.jobName).toBe("caj-eng-eng-acme"); // default per-engagement resolver
    expect(calls.start).toHaveLength(1);
    expect(calls.start[0]!.rg).toBe("rg-orch");
    expect(calls.start[0]!.job).toBe("caj-eng-eng-acme");

    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({
      action: "invoke",
      runId: "run-123",
      engagementId: "eng-acme",
      executionName: "exec-abc",
      identityVerified: true,
      boundManagedIdentityResourceId: ENG_MI,
    });
    expect(audit[0]!.at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    // Identity was CONFIRMED via ARM GET before starting.
    expect(calls.get).toHaveLength(1);
    expect(calls.get[0]!.job).toBe("caj-eng-eng-acme");
  });

  it("constructor throws (fail-closed) when no audit sink is provided", () => {
    expect(
      () =>
        new AcaJobsExecutionBackend({
          subscriptionId: "sub-1",
          resourceGroupName: "rg-orch",
          client: makeFakeClient().client,
          // audit intentionally omitted
        } as unknown as ConstructorParameters<
          typeof AcaJobsExecutionBackend
        >[0]),
    ).toThrow(/audit/i);
  });

  it("refuses to dispatch when the job's bound identity != claimed identity", async () => {
    const { client, calls } = makeFakeClient(
      "Running",
      "/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-OTHER",
    );
    const audit: AuditEvent[] = [];
    const backend = new AcaJobsExecutionBackend({
      subscriptionId: "sub-1",
      resourceGroupName: "rg-orch",
      client,
      audit: (e) => audit.push(e),
    });
    await expect(backend.invoke(makeRun())).rejects.toThrow(/identity binding/i);
    expect(calls.start).toHaveLength(0); // never dispatched
    expect(audit[0]).toMatchObject({ action: "invoke", identityVerified: false });
  });

  it("refuses to dispatch a long-lived run JWT passed by value", async () => {
    const { client, calls } = makeFakeClient();
    const backend = new AcaJobsExecutionBackend({
      subscriptionId: "sub-1",
      resourceGroupName: "rg-orch",
      client,
      audit: noopAudit,
    });
    await expect(
      backend.invoke(makeRun({ jwt: makeJwt(86400) })),
    ).rejects.toThrow(/TTL/);
    expect(calls.get).toHaveLength(0);
    expect(calls.start).toHaveLength(0);
  });

  it("uses a custom job-name resolver for engagement isolation", async () => {
    const { client } = makeFakeClient();
    const backend = new AcaJobsExecutionBackend({
      subscriptionId: "sub-1",
      resourceGroupName: "rg-orch",
      client,
      audit: noopAudit,
      resolveJobName: (eng) => `job-${eng}-isolated`,
    });
    const handle = await backend.invoke(makeRun());
    expect(handle.jobName).toBe("job-eng-acme-isolated");
  });

  it("refuses to invoke an unscoped run (no engagement)", async () => {
    const { client, calls } = makeFakeClient();
    const backend = new AcaJobsExecutionBackend({
      subscriptionId: "sub-1",
      resourceGroupName: "rg-orch",
      client,
      audit: noopAudit,
    });
    await expect(backend.invoke(makeRun({ engagementId: "" }))).rejects.toThrow(
      InvalidRunError,
    );
    expect(calls.start).toHaveLength(0); // never dispatched
  });

  it("status polls the named execution and normalizes the state", async () => {
    const { client, calls } = makeFakeClient("Succeeded");
    const backend = new AcaJobsExecutionBackend({
      subscriptionId: "sub-1",
      resourceGroupName: "rg-orch",
      client,
      audit: noopAudit,
    });
    const status = await backend.status({
      runId: "run-123",
      engagementId: "eng-acme",
      jobName: "caj-eng-eng-acme",
      executionName: "exec-abc",
    });
    expect(status).toBe("succeeded");
    expect(calls.list[0]!.job).toBe("caj-eng-eng-acme");
  });

  it("status returns running for an in-flight execution", async () => {
    const { client } = makeFakeClient("Running");
    const backend = new AcaJobsExecutionBackend({
      subscriptionId: "sub-1",
      resourceGroupName: "rg-orch",
      client,
      audit: noopAudit,
    });
    const status = await backend.status({
      runId: "run-123",
      engagementId: "eng-acme",
      jobName: "caj-eng-eng-acme",
      executionName: "exec-abc",
    });
    expect(status).toBe("running");
  });

  it("cancel stops the execution and audits cancellation", async () => {
    const { client, calls } = makeFakeClient();
    const audit: AuditEvent[] = [];
    const backend = new AcaJobsExecutionBackend({
      subscriptionId: "sub-1",
      resourceGroupName: "rg-orch",
      client,
      audit: (e) => audit.push(e),
    });
    await backend.cancel({
      runId: "run-123",
      engagementId: "eng-acme",
      jobName: "caj-eng-eng-acme",
      executionName: "exec-abc",
    });
    expect(calls.stop).toHaveLength(1);
    expect(calls.stop[0]).toMatchObject({
      rg: "rg-orch",
      job: "caj-eng-eng-acme",
      exec: "exec-abc",
    });
    expect(audit[0]).toMatchObject({ action: "cancel", status: "cancelled" });
  });

  it("audits and rethrows when the ARM start call fails", async () => {
    const audit: AuditEvent[] = [];
    const client: AcaJobsClient = {
      jobs: {
        get: vi.fn(async (_rg, job) => ({
          name: job,
          identity: {
            type: "UserAssigned",
            userAssignedIdentities: { [ENG_MI]: {} },
          },
        })),
        beginStartAndWait: vi.fn(async () => {
          throw new Error("Forbidden: missing role");
        }),
        beginStopExecutionAndWait: vi.fn(),
      },
      jobsExecutions: { list: vi.fn() },
    };
    const backend = new AcaJobsExecutionBackend({
      subscriptionId: "sub-1",
      resourceGroupName: "rg-orch",
      client,
      audit: (e) => audit.push(e),
    });
    await expect(backend.invoke(makeRun())).rejects.toThrow(/Forbidden/);
    expect(audit[0]).toMatchObject({ action: "invoke", error: "Forbidden: missing role" });
  });
});
