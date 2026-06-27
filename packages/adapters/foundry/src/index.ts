/**
 * adapter-foundry — Paperclip model-adapter for Azure OpenAI / AI Foundry.
 *
 * Security posture (SecurityOS PRD R5/R9 §11.1):
 *   - Keyless: authentication is exclusively a Microsoft Entra bearer token
 *     acquired via managed identity. No API key is accepted or forwarded.
 *   - Per-engagement: the Entra credential is resolved per engagement's
 *     managed-identity client id; process-wide credential reuse is not allowed.
 *   - Private-by-default: the endpoint MUST be a Private Endpoint URL.
 *   - Lane allowlist: deployment is validated against the engagement's lane
 *     policy before any token acquisition or request.
 *   - Fail-closed audit: every outcome (success/cancel/fail/refused) emits
 *     exactly one audit event in a finally{} block.
 *
 * External adapter registration: the main entry exports createServerAdapter()
 * so Paperclip's plugin-loader can hot-load this package from the adapter-plugin
 * store (~/.paperclip/adapter-plugins.json) without a server restart.
 *
 * Register in Paperclip's adapter registry as type = "foundry".
 */

import type { AdapterModelProfileDefinition, ServerAdapterModule } from "@paperclipai/adapter-utils";
import { execute, testEnvironment } from "./server/index.js";

export const type = "foundry";
export const label = "Azure OpenAI / Foundry (keyless)";

/** Model ids must match deployed Foundry deployment names. */
export const models = [
  { id: "gpt-4o", label: "GPT-4o (2024-11-20)" },
  { id: "text-embedding-3-large", label: "text-embedding-3-large (embedding)" },
];

export const modelProfiles: AdapterModelProfileDefinition[] = [
  {
    key: "cheap",
    label: "GPT-4o (standard capacity)",
    description:
      "Use the GPT-4o Standard deployment for cost-efficient drafting while preserving the security posture.",
    adapterConfig: {
      deployment: "gpt-4o",
      lane: "firm_cloud",
    },
    source: "adapter_default",
  },
];

export const agentConfigurationDoc = `# foundry agent configuration

Adapter: foundry (Azure OpenAI / Azure AI Foundry, keyless)

Required fields (set via Paperclip company/engagement config):
- engagement.engagementId (string): SecurityOS engagement id.
- engagement.allowedLanes (string[]): permitted lanes, e.g. ["firm_cloud"].
- engagement.managedIdentityClientId (string): client id of the per-engagement
  managed identity bound to the ACA Job. Drives per-engagement credential.

Optional fields:
- deployment (string, default "gpt-4o"): Foundry deployment name.
- endpoint (string): Azure OpenAI PE URL. Defaults to AZURE_OPENAI_ENDPOINT env.
- apiVersion (string): defaults to "2024-10-21".
- maxTokens (number): max completion tokens.
- temperature (number): sampling temperature.

Audit:
- Every invoke emits an audit event regardless of outcome (success/fail/refused).
- Set SECURITYOS_AUDIT_LOG_LEVEL=info to see audit events in structured JSON.

Lane policy:
- Deployments are checked against engagement.allowedLanes before any token is
  acquired. A deployment not in the allowlist is refused with a LaneViolationError.
- public_non_sensitive lane is never allowed for Confidential engagements.
`;

/**
 * createServerAdapter() — entry point for Paperclip's external adapter plugin loader.
 *
 * The plugin loader (server/src/adapters/plugin-loader.ts) imports the main
 * entry of each plugin and calls createServerAdapter(). This returns a
 * ServerAdapterModule that Paperclip registers under type "foundry".
 *
 * Registration:
 *   1. Build this package: `pnpm build` in packages/adapters/foundry/
 *   2. Add to ~/.paperclip/adapter-plugins.json:
 *        { "packageName": "@securityos/adapter-foundry",
 *          "localPath": "/path/to/paperclip/packages/adapters/foundry",
 *          "type": "foundry", "installedAt": "..." }
 *   3. Restart Paperclip server. The adapter appears in the adapter list as "foundry".
 */
export function createServerAdapter(): ServerAdapterModule {
  return {
    type,
    execute,
    testEnvironment,
    models,
    modelProfiles,
    agentConfigurationDoc,
  };
}
