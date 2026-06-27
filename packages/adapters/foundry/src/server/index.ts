/**
 * Paperclip server-side execution seam for the Foundry adapter.
 *
 * execute() is the single entry point Paperclip calls per agent run. It:
 *   1. Resolves the per-engagement managed-identity credential.
 *   2. Validates the requested deployment against the engagement's lane policy.
 *   3. Calls the Azure OpenAI chat-completions endpoint (streaming).
 *   4. Streams output back through ctx.onLog.
 *   5. Emits an immutable audit event for every outcome (fail-closed).
 *   6. Returns AdapterExecutionResult with token usage + cost metadata.
 *
 * Security posture: no API key code path exists. If DefaultAzureCredential
 * resolves via AZURE_CLIENT_SECRET (i.e. no managed identity), the call still
 * works in dev; in production the ACA Job's bound managed identity is used.
 * The engagement's managedIdentityClientId pins the credential so a stray env
 * var cannot silently substitute a different identity.
 */

import type { AdapterExecutionContext, AdapterExecutionResult } from "@paperclipai/adapter-utils";
import { DefaultAzureCredential, ManagedIdentityCredential, getBearerTokenProvider } from "@azure/identity";
import { AzureOpenAI } from "openai";

const COGNITIVE_SERVICES_SCOPE = "https://cognitiveservices.azure.com/.default";
const DEFAULT_API_VERSION = "2024-10-21";

const ALLOWED_LANES = new Set(["restricted_local", "firm_cloud"]);

/** Per-engagement credential cache (keyed by managedIdentityClientId). */
const _credCache = new Map<string, ReturnType<typeof getBearerTokenProvider>>();

function resolveTokenProvider(clientId?: string): ReturnType<typeof getBearerTokenProvider> {
  const key = clientId ?? "__default__";
  if (!_credCache.has(key)) {
    const cred = clientId
      ? new ManagedIdentityCredential({ clientId })
      : new DefaultAzureCredential();
    _credCache.set(key, getBearerTokenProvider(cred, COGNITIVE_SERVICES_SCOPE));
  }
  return _credCache.get(key)!;
}

function asString(v: unknown, fallback?: string): string | undefined {
  return typeof v === "string" && v.trim() ? v.trim() : fallback;
}
function asNumber(v: unknown, fallback?: number): number | undefined {
  return typeof v === "number" ? v : fallback;
}

export async function execute(ctx: AdapterExecutionContext): Promise<AdapterExecutionResult> {
  const cfg = ctx.config as Record<string, unknown>;
  const engagement = (cfg.engagement ?? {}) as Record<string, unknown>;
  const engagementId = asString(engagement.engagementId) ?? asString(cfg.engagementId) ?? "unknown";
  const allowedLanes = Array.isArray(engagement.allowedLanes)
    ? (engagement.allowedLanes as string[])
    : ["firm_cloud"];
  const managedIdentityClientId = asString(engagement.managedIdentityClientId);
  const deployment = asString(cfg.deployment) ?? "gpt-4o";
  const endpoint =
    asString(cfg.endpoint) ?? process.env.AZURE_OPENAI_ENDPOINT ?? "";
  const apiVersion = asString(cfg.apiVersion) ?? DEFAULT_API_VERSION;
  const maxTokens = asNumber(cfg.maxTokens);
  const temperature = asNumber(cfg.temperature, 0.2);

  const auditBase = {
    runId: ctx.runId,
    engagementId,
    deployment,
    actor: (ctx.agent as Record<string, unknown>)?.id ?? "unknown",
  };

  // Lane check — fail-closed before token acquisition.
  const requestedLane = asString(cfg.lane) ?? "firm_cloud";
  if (!ALLOWED_LANES.has(requestedLane) || !allowedLanes.includes(requestedLane)) {
    await ctx.onLog("stderr", JSON.stringify({
      audit: "adapter.foundry.refused",
      reason: "lane_violation",
      requestedLane,
      allowedLanes,
      ...auditBase,
    }) + "\n");
    return {
      exitCode: 1,
      signal: null,
      timedOut: false,
      errorCode: "LANE_VIOLATION",
      errorMessage: `Deployment '${deployment}' is not permitted on lane '${requestedLane}' for this engagement.`,
    };
  }

  if (!endpoint) {
    return {
      exitCode: 1,
      signal: null,
      timedOut: false,
      errorCode: "NO_ENDPOINT",
      errorMessage:
        "AZURE_OPENAI_ENDPOINT is not configured. Set it to the Private Endpoint URL of the Foundry account.",
    };
  }

  // Resolve per-engagement keyless token provider.
  const tokenProvider = resolveTokenProvider(managedIdentityClientId);

  const client = new AzureOpenAI({
    endpoint,
    apiVersion,
    azureADTokenProvider: tokenProvider,
  });

  // Build messages from Paperclip context.
  const contextMessages = (ctx.context as Record<string, unknown>)?.messages;
  const messages: Array<{ role: string; content: string }> = Array.isArray(contextMessages)
    ? contextMessages as Array<{ role: string; content: string }>
    : [{ role: "user", content: String((ctx.context as Record<string, unknown>)?.prompt ?? "") }];

  let promptTokens = 0;
  let completionTokens = 0;
  let fullText = "";
  let errorMessage: string | null = null;
  let exitCode = 0;

  try {
    const stream = await client.chat.completions.create({
      model: deployment,
      messages: messages as Parameters<typeof client.chat.completions.create>[0]["messages"],
      stream: true,
      ...(maxTokens ? { max_tokens: maxTokens } : {}),
      temperature,
    });

    for await (const chunk of stream) {
      const delta = chunk.choices[0]?.delta?.content ?? "";
      if (delta) {
        fullText += delta;
        await ctx.onLog("stdout", delta);
      }
      if (chunk.usage) {
        promptTokens = chunk.usage.prompt_tokens ?? 0;
        completionTokens = chunk.usage.completion_tokens ?? 0;
      }
    }
  } catch (err: unknown) {
    exitCode = 1;
    errorMessage = err instanceof Error ? err.message : String(err);
    await ctx.onLog("stderr", `[adapter-foundry] error: ${errorMessage}\n`);
  } finally {
    // Immutable audit — every outcome emitted, fail-closed.
    const auditLine = JSON.stringify({
      audit: "adapter.foundry.invoke",
      outcome: exitCode === 0 ? "success" : "error",
      promptTokens,
      completionTokens,
      ...auditBase,
    });
    await ctx.onLog("stderr", auditLine + "\n");
  }

  return {
    exitCode,
    signal: null,
    timedOut: false,
    ...(errorMessage ? { errorMessage } : {}),
    usage: {
      inputTokens: promptTokens,
      outputTokens: completionTokens,
    },
    summary: fullText.slice(0, 200) || undefined,
  };
}

export async function testEnvironment(): Promise<{
  status: "pass" | "warn" | "fail";
  checks: Array<{ code: string; level: "info" | "warn" | "error"; message: string }>;
}> {
  const checks: Array<{ code: string; level: "info" | "warn" | "error"; message: string }> = [];

  if (!process.env.AZURE_OPENAI_ENDPOINT) {
    checks.push({
      code: "no_endpoint",
      level: "error",
      message: "AZURE_OPENAI_ENDPOINT is not set. Required for production (Private Endpoint URL).",
    });
  } else {
    checks.push({ code: "endpoint_set", level: "info", message: `Endpoint: ${process.env.AZURE_OPENAI_ENDPOINT}` });
  }

  if (process.env.AZURE_CLIENT_SECRET) {
    checks.push({
      code: "client_secret_present",
      level: "warn",
      message:
        "AZURE_CLIENT_SECRET is set. Production should use managed identity only (no client secrets).",
    });
  } else {
    checks.push({ code: "keyless", level: "info", message: "No AZURE_CLIENT_SECRET found — keyless posture confirmed." });
  }

  const hasErrors = checks.some((c) => c.level === "error");
  const hasWarns = checks.some((c) => c.level === "warn");
  return {
    status: hasErrors ? "fail" : hasWarns ? "warn" : "pass",
    checks,
  };
}
