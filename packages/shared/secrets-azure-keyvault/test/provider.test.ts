import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  KeyVaultSecretsProvider,
  StrictModeViolationError,
  ScopeIsolationError,
  CallerRequiredError,
  AuditRequiredError,
  AuditSinkError,
  type SecretAccessEvent,
  type KeyVaultSecretClientLike,
} from "../src/provider.js";
import { secretName, sanitizeSegment, KV_NAME_MAX } from "../src/naming.js";

/**
 * In-memory fake of `@azure/keyvault-secrets` SecretClient. Models versions,
 * tags, and soft-delete just enough to exercise the provider contract.
 */
class FakeSecretClient implements KeyVaultSecretClientLike {
  // name -> ordered versions (last is current)
  store = new Map<
    string,
    Array<{
      value: string;
      version: string;
      tags?: Record<string, string>;
      enabled: boolean;
      createdOn: Date;
      updatedOn: Date;
    }>
  >();
  private counter = 0;

  async setSecret(
    name: string,
    value: string,
    options?: { tags?: Record<string, string>; enabled?: boolean },
  ) {
    const version = `v${++this.counter}`;
    const now = new Date();
    const rec = {
      value,
      version,
      tags: options?.tags,
      enabled: options?.enabled ?? true,
      createdOn: now,
      updatedOn: now,
    };
    const versions = this.store.get(name) ?? [];
    versions.push(rec);
    this.store.set(name, versions);
    return { value, name, properties: { name, ...rec } };
  }

  async getSecret(name: string, options?: { version?: string }) {
    const versions = this.store.get(name);
    if (!versions || versions.length === 0) {
      throw Object.assign(new Error(`Secret not found: ${name}`), {
        name: "RestError",
        statusCode: 404,
      });
    }
    const rec = options?.version
      ? versions.find((v) => v.version === options.version)
      : versions[versions.length - 1];
    if (!rec) {
      throw Object.assign(new Error(`Version not found: ${options?.version}`), {
        name: "RestError",
        statusCode: 404,
      });
    }
    return { value: rec.value, name, properties: { name, ...rec } };
  }

  async beginDeleteSecret(name: string) {
    if (!this.store.has(name)) {
      throw Object.assign(new Error(`Secret not found: ${name}`), {
        name: "RestError",
        statusCode: 404,
      });
    }
    this.store.delete(name);
    return { pollUntilDone: async () => undefined };
  }

  async *listPropertiesOfSecrets() {
    for (const [name, versions] of this.store) {
      const rec = versions[versions.length - 1]!;
      yield { name, ...rec };
    }
  }
}

const SCOPE = { deploymentId: "dep01", engagementId: "eng-acme" };
const PRINCIPAL = "test-principal";

/** Construct a provider wired with an in-memory client, capturing audit events. */
function makeProvider(
  client: FakeSecretClient,
  events: SecretAccessEvent[],
  overrides: Partial<{
    strictMode: boolean;
    engagementBinding: { deploymentId: string; engagementId: string };
    allowMultiEngagement: boolean;
    principal: string;
  }> = {},
) {
  return new KeyVaultSecretsProvider({
    client,
    principal: PRINCIPAL,
    // Default test instance models a per-engagement run. Tests that need broad
    // scope must explicitly opt into allowMultiEngagement.
    engagementBinding: overrides.allowMultiEngagement ? undefined : SCOPE,
    audit: (e) => {
      events.push(e);
    },
    ...overrides,
  });
}

describe("naming", () => {
  it("builds a KV-rule-compliant, deterministic, hash-suffixed name", () => {
    const n = secretName(SCOPE, "openai_api_key");
    // Readable prefix + a fixed-length disambiguating hash suffix.
    expect(n).toMatch(/^paperclip-dep01-eng-acme-openai-api-key-[0-9a-f]{12}$/);
    expect(n).toMatch(/^[0-9a-zA-Z-]{1,127}$/);
    expect(secretName(SCOPE, "openai_api_key")).toBe(n); // deterministic
  });

  it("sanitizes illegal characters to dashes and collapses runs", () => {
    expect(sanitizeSegment("a/b_c.d")).toBe("a-b-c-d");
    expect(sanitizeSegment("--lead--trail--")).toBe("lead-trail");
  });

  it("never collides on ambiguous segment boundaries (P0 collision fix)", () => {
    // The historical bug: ('a-b','c') and ('a','b-c') rendered the same name.
    const a = secretName({ deploymentId: "dep01", engagementId: "a-b" }, "c");
    const b = secretName({ deploymentId: "dep01", engagementId: "a" }, "b-c");
    expect(a).not.toBe(b);
    // Same hazard between deployment/engagement boundary.
    const c = secretName({ deploymentId: "x-y", engagementId: "z" }, "k");
    const d = secretName({ deploymentId: "x", engagementId: "y-z" }, "k");
    expect(c).not.toBe(d);
  });

  it("stays <=127 chars with a collision-safe hash on overflow", () => {
    const longKey = "k".repeat(200);
    const a = secretName(SCOPE, longKey);
    const b = secretName(SCOPE, longKey + "different");
    expect(a.length).toBeLessThanOrEqual(KV_NAME_MAX);
    expect(b.length).toBeLessThanOrEqual(KV_NAME_MAX);
    expect(a).not.toBe(b); // no truncation collision
  });

  it("rejects empty scope/key segments", () => {
    expect(() => secretName({ deploymentId: "", engagementId: "e" }, "k")).toThrow();
    expect(() => secretName(SCOPE, "")).toThrow();
  });
});

describe("KeyVaultSecretsProvider", () => {
  let client: FakeSecretClient;
  let events: SecretAccessEvent[];
  let provider: KeyVaultSecretsProvider;

  beforeEach(() => {
    client = new FakeSecretClient();
    events = [];
    provider = makeProvider(client, events);
  });

  it("set returns metadata with a version ref and never leaks plaintext into metadata", async () => {
    const meta = await provider.set(SCOPE, "db-password", "s3cr3t", "agent-run-1");
    expect(meta.secretName).toBe(secretName(SCOPE, "db-password"));
    expect(meta.version).toBe("v1");
    expect(meta.scope).toEqual(SCOPE);
    // SecretMetadata must not carry a value field.
    expect((meta as Record<string, unknown>).value).toBeUndefined();
    expect(events.at(-1)).toMatchObject({ action: "set", outcome: "success", version: "v1" });
  });

  it("get returns the plaintext value only at runtime", async () => {
    await provider.set(SCOPE, "db-password", "s3cr3t");
    const got = await provider.get(SCOPE, "db-password", "agent-run-1");
    expect(got.value).toBe("s3cr3t");
    expect(got.version).toBe("v1");
    expect(events.at(-1)).toMatchObject({
      action: "get",
      outcome: "success",
      caller: "agent-run-1",
    });
  });

  it("attributes operations to the bound principal when no caller is passed", async () => {
    await provider.set(SCOPE, "k", "v");
    expect(events.at(-1)).toMatchObject({ action: "set", caller: PRINCIPAL });
  });

  it("getVersion fetches a specific historical version", async () => {
    await provider.set(SCOPE, "rotating", "old");
    await provider.set(SCOPE, "rotating", "new");
    const current = await provider.get(SCOPE, "rotating");
    expect(current.value).toBe("new");
    const old = await provider.getVersion(SCOPE, "rotating", "v1");
    expect(old.value).toBe("old");
    expect(events.at(-1)).toMatchObject({ action: "get-version", version: "v1" });
  });

  it("list returns only secrets within the engagement scope", async () => {
    await provider.set(SCOPE, "key-a", "1");
    await provider.set(SCOPE, "key-b", "2");
    // A secret belonging to a different engagement must be invisible.
    const trustedSeeder = makeProvider(client, events, {
      allowMultiEngagement: true,
    });
    await trustedSeeder.set(
      { deploymentId: "dep01", engagementId: "eng-other" },
      "key-a",
      "x",
    );

    const listed = await provider.list(SCOPE);
    const keys = listed.map((m) => m.key).sort();
    expect(keys).toEqual(["key-a", "key-b"]);
    expect(listed.every((m) => m.scope.engagementId === "eng-acme")).toBe(true);
    expect(events.at(-1)).toMatchObject({ action: "list", outcome: "success" });
  });

  it("denies by default when unbound and multi-engagement is not enabled", async () => {
    const denied = new KeyVaultSecretsProvider({
      client,
      principal: PRINCIPAL,
      audit: (e) => events.push(e),
    });
    await expect(denied.get(SCOPE, "anything")).rejects.toThrow(/deny-by-default/);
    expect(events.at(-1)).toMatchObject({ outcome: "denied" });
  });

  it("delete removes the secret and emits an audit event", async () => {
    await provider.set(SCOPE, "temp", "x");
    await provider.delete(SCOPE, "temp", "agent-run-1");
    await expect(provider.get(SCOPE, "temp")).rejects.toThrow();
    expect(events.some((e) => e.action === "delete" && e.outcome === "success")).toBe(true);
  });

  it("emits an error audit event and rethrows on a missing secret", async () => {
    await expect(provider.get(SCOPE, "absent")).rejects.toThrow();
    expect(events.at(-1)).toMatchObject({ action: "get", outcome: "error", key: "absent" });
    expect(events.at(-1)?.error).toContain("Secret not found");
  });

  it("never places plaintext into any audit event", async () => {
    await provider.set(SCOPE, "db-password", "TOP-SECRET-VALUE");
    await provider.get(SCOPE, "db-password");
    const serialized = JSON.stringify(events);
    expect(serialized).not.toContain("TOP-SECRET-VALUE");
  });

  it("requires a vault URL when no client is injected", () => {
    const prev = process.env.AZURE_KEYVAULT_URL;
    delete process.env.AZURE_KEYVAULT_URL;
    expect(() => new KeyVaultSecretsProvider({ audit: () => {} })).toThrow(/AZURE_KEYVAULT_URL/);
    if (prev !== undefined) process.env.AZURE_KEYVAULT_URL = prev;
  });
});

describe("audit is mandatory and fails closed (immutable-audit posture)", () => {
  it("constructor throws when no audit sink is provided", () => {
    expect(
      () => new KeyVaultSecretsProvider({ client: new FakeSecretClient() } as never),
    ).toThrow(AuditRequiredError);
  });

  it("a failing audit sink on get fails closed — no unaudited plaintext is returned", async () => {
    const client = new FakeSecretClient();
    // Seed a secret using a provider with a working sink.
    await makeProvider(client, []).set(SCOPE, "db-password", "PLAINTEXT");

    const failing = new KeyVaultSecretsProvider({
      client,
      principal: PRINCIPAL,
      engagementBinding: SCOPE,
      audit: () => {
        throw new Error("audit sink down");
      },
    });
    await expect(failing.get(SCOPE, "db-password")).rejects.toBeInstanceOf(AuditSinkError);
  });

  it("a failing audit sink on set surfaces the failure (write not silently unaudited)", async () => {
    const failing = new KeyVaultSecretsProvider({
      client: new FakeSecretClient(),
      principal: PRINCIPAL,
      engagementBinding: SCOPE,
      audit: () => {
        throw new Error("audit sink down");
      },
    });
    await expect(failing.set(SCOPE, "k", "v")).rejects.toBeInstanceOf(AuditSinkError);
  });
});

describe("engagement-scope isolation (cloud-boundary binding)", () => {
  it("denies a caller-supplied scope that does not match the bound engagement", async () => {
    const client = new FakeSecretClient();
    const events: SecretAccessEvent[] = [];
    const provider = makeProvider(client, events, { engagementBinding: SCOPE });

    const otherScope = { deploymentId: "dep01", engagementId: "eng-evil" };
    await expect(provider.get(otherScope, "db-password")).rejects.toBeInstanceOf(
      ScopeIsolationError,
    );
    expect(events.at(-1)).toMatchObject({ action: "get", outcome: "denied" });
  });

  it("allows operations whose scope matches the bound engagement", async () => {
    const client = new FakeSecretClient();
    const events: SecretAccessEvent[] = [];
    const provider = makeProvider(client, events, { engagementBinding: SCOPE });
    await expect(provider.set(SCOPE, "k", "v")).resolves.toMatchObject({ version: "v1" });
  });

  it("requires a caller/principal and denies when none can be resolved", async () => {
    const client = new FakeSecretClient();
    const events: SecretAccessEvent[] = [];
    // No principal bound and no per-call caller -> deny-by-default.
    const provider = new KeyVaultSecretsProvider({
      client,
      audit: (e) => {
        events.push(e);
      },
    });
    await expect(provider.get(SCOPE, "k")).rejects.toBeInstanceOf(CallerRequiredError);
    expect(events.at(-1)).toMatchObject({ outcome: "denied" });
  });
});

describe("strict mode (forbids inline env secrets)", () => {
  const SCOPE2 = { deploymentId: "dep01", engagementId: "eng-acme" };

  it("defaults strictMode to true", () => {
    const prev = process.env.PAPERCLIP_SECRETS_STRICT_MODE;
    delete process.env.PAPERCLIP_SECRETS_STRICT_MODE;
    const p = makeProvider(new FakeSecretClient(), []);
    expect(p.strictMode).toBe(true);
    if (prev !== undefined) process.env.PAPERCLIP_SECRETS_STRICT_MODE = prev;
  });

  it("denies inline env resolution and emits a denied audit event when strict", async () => {
    const client = new FakeSecretClient();
    const events: SecretAccessEvent[] = [];
    const provider = makeProvider(client, events, { strictMode: true });
    process.env.SOME_INLINE_SECRET = "leaked";
    await expect(
      provider.resolveInlineEnv(SCOPE2, "k", "SOME_INLINE_SECRET"),
    ).rejects.toBeInstanceOf(StrictModeViolationError);
    expect(events.at(-1)).toMatchObject({ action: "inline-env", outcome: "denied" });
    delete process.env.SOME_INLINE_SECRET;
  });

  it("allows inline env resolution but audits it when strict mode is off", async () => {
    const client = new FakeSecretClient();
    const events: SecretAccessEvent[] = [];
    const provider = makeProvider(client, events, { strictMode: false });
    process.env.SOME_INLINE_SECRET = "present";
    await expect(provider.resolveInlineEnv(SCOPE2, "k", "SOME_INLINE_SECRET")).resolves.toBe(
      "present",
    );
    expect(events.at(-1)).toMatchObject({ action: "inline-env", outcome: "success" });
    delete process.env.SOME_INLINE_SECRET;
  });

  it("honors PAPERCLIP_SECRETS_STRICT_MODE=false to opt out", () => {
    const prev = process.env.PAPERCLIP_SECRETS_STRICT_MODE;
    process.env.PAPERCLIP_SECRETS_STRICT_MODE = "false";
    const p = makeProvider(new FakeSecretClient(), []);
    expect(p.strictMode).toBe(false);
    if (prev === undefined) delete process.env.PAPERCLIP_SECRETS_STRICT_MODE;
    else process.env.PAPERCLIP_SECRETS_STRICT_MODE = prev;
  });
});

// Demonstrates module-level mocking of the real SecretClient for callers who
// construct the provider by URL rather than by injection.
vi.mock("@azure/identity", () => ({
  ManagedIdentityCredential: class {
    constructor(public options: unknown) {}
  },
}));

describe("construction via vault URL (mocked SDK)", () => {
  it("builds with a pinned managed identity when AZURE_KEYVAULT_URL is set", async () => {
    vi.doMock("@azure/keyvault-secrets", () => ({
      SecretClient: class {
        constructor(
          public url: string,
          public cred: unknown,
        ) {}
      },
    }));
    const { KeyVaultSecretsProvider: Fresh } = await import("../src/provider.js");
    const p = new Fresh({
      vaultUrl: "https://kv-eng-001.vault.azure.net",
      managedIdentityClientId: "00000000-0000-0000-0000-000000000000",
      audit: () => {},
    });
    expect(p).toBeInstanceOf(Fresh);
  });

  it("throws when no managed identity client id can be pinned", async () => {
    const prevClient = process.env.AZURE_CLIENT_ID;
    const prevMi = process.env.AZURE_MANAGED_IDENTITY_CLIENT_ID;
    delete process.env.AZURE_CLIENT_ID;
    delete process.env.AZURE_MANAGED_IDENTITY_CLIENT_ID;
    const { KeyVaultSecretsProvider: Fresh } = await import("../src/provider.js");
    expect(
      () =>
        new Fresh({
          vaultUrl: "https://kv-eng-001.vault.azure.net",
          audit: () => {},
        }),
    ).toThrow(/managedIdentityClientId/);
    if (prevClient !== undefined) process.env.AZURE_CLIENT_ID = prevClient;
    if (prevMi !== undefined) process.env.AZURE_MANAGED_IDENTITY_CLIENT_ID = prevMi;
  });
});
