import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ExtensionAPI, InlineExtension } from "@earendil-works/pi-coding-agent";
import {
  createAgentSession,
  DefaultResourceLoader,
  ModelRuntime,
  SessionManager,
  SettingsManager,
} from "@earendil-works/pi-coding-agent";
import { fauxAssistantMessage, fauxProvider, fauxToolCall } from "@earendil-works/pi-ai";
import piSecret from "../../src/index.ts";

export interface SecureSessionOptions {
  responses: Parameters<ReturnType<typeof fauxProvider>["setResponses"]>[0];
  tools?: string[];
  cwd?: string;
  /**
   * Written to <agentDir>/settings.json before the loader runs.
   *
   * Needed by the compaction scenario: `compact()` bails with "Nothing to compact
   * (session too small)" unless the cut point leaves at least one message to
   * summarise, and that cut point comes from `keepRecentTokens` (default 20000).
   * Lowering it is the difference between exercising pi's real compaction path and
   * skipping it — and skipping it is exactly what this scenario exists to prevent.
   */
  settings?: Record<string, unknown>;
  /**
   * Extra extension factories, registered AROUND pi-secret in the order given:
   * anything before it observes the payload as the agent produced it, anything after
   * it observes what actually leaves the machine. That ordering is the only honest way
   * to assert on the wire in a test — asserting on our own hook's return value would
   * be asserting that a function returns its argument.
   */
  probeExtensionFactories?: InlineExtension[];
  /**
   * Record every payload handed to the provider-level `onPayload` callback — i.e. the
   * exact bytes `before_provider_request` gets to rewrite.
   *
   * This exists because the faux provider NEVER calls `options.onPayload`, while every
   * real provider does (pi-ai/dist/api/openai-completions.js:204 and its siblings).
   * So without this shim, pi's `before_provider_request` hook — which pi-secret treats
   * as its last mile — silently never fires under the canary suite. Measured: with the
   * faux provider, `agent_start`, `context`, `message_end`, `tool_call` and
   * `tool_result` all fire, and `before_provider_request` fires ZERO times. The suite
   * was therefore asserting file-level safety only, while the README claimed the
   * bytes leaving the machine were covered.
   */
  onProviderPayload?: (payload: unknown, model: unknown) => void;
}

export async function makeSecureSession(options: SecureSessionOptions) {
  const faux = fauxProvider({ models: [{ id: "canary-model", name: "Canary", contextWindow: 100_000, maxTokens: 4096 }] });
  faux.setResponses(options.responses);
  const runtime = await ModelRuntime.create({ allowModelNetwork: false, refreshOnCreate: false });
  // Wrap the faux provider so it behaves like a real one at the one point that
  // matters here: it invokes options.onPayload, threading a possibly-REWRITTEN payload
  // into the call, exactly as openai-completions.js and the other api/*.js do.
  // Wrap the faux provider so it behaves like a real one at the one point that matters
  // here: it invokes options.onPayload and threads a possibly-REWRITTEN payload into the
  // call, exactly as pi-ai/dist/api/openai-completions.js:204 and its siblings do.
  //
  // pi-ai's faux .d.ts types `api` as `string` (a broken declaration), so the shape is
  // recovered with a cast and then CHECKED — a silent shape change must fail loudly
  // here, because the failure mode is a last-mile check that quietly stops running.
  const model = faux.getModel("canary-model") ?? faux.getModel();
  const record = options.onProviderPayload;
  let provider: unknown = faux.provider;
  if (record) {
    // createProvider() hoists the api bag onto the provider itself (its own keys are
    // id/name/baseUrl/headers/auth/getModels/... then stream/streamSimple/...), so
    // that is where the two entry points live — not on `faux.api`, which is the api
    // IDENTIFIER string.
    const api = faux.provider as unknown as { stream?: unknown; streamSimple?: unknown };
    if (typeof api.stream !== "function" || typeof api.streamSimple !== "function") {
      throw new Error(
        "canary harness: the faux provider no longer exposes callable stream/streamSimple, " +
          "so onProviderPayload cannot be injected and before_provider_request would go untested",
      );
    }
    // The wrapper stays SYNCHRONOUS and does not await onPayload: ModelRuntime hands
    // provider.streamSimple's return value straight to lazyStream, so returning a
    // promise here would change the stream type. What the assertion needs is the value
    // the hook RETURNED — that is the payload pi would put on the wire — so the
    // resolved result is recorded, while faux keeps receiving its original context
    // (it ignores content entirely). A hook that never fires records nothing, and the
    // scenario's "at least one payload" assertion fails loudly.
    const wrap = (inner: (model: unknown, context: unknown, opts?: unknown) => unknown) =>
      (model: unknown, context: unknown, opts?: { onPayload?: (p: unknown, m: unknown) => unknown }) => {
        const onPayload = opts?.onPayload;
        if (!onPayload) return inner(model, context, opts);
        const payload = (context as { messages?: unknown }).messages ?? context;
        const outcome = onPayload(payload, model);
        if (outcome && typeof (outcome as Promise<unknown>).then === "function") {
          void (outcome as Promise<unknown>).then((next) => record(next ?? payload, model));
        } else {
          record(outcome ?? payload, model);
        }
        return inner(model, context, opts);
      };
    provider = { ...faux.provider, stream: wrap(api.stream as never), streamSimple: wrap(api.streamSimple as never) };
  }
  const cwd = options.cwd ?? mkdtempSync(join(tmpdir(), "pi-secret-cwd-"));
  // An explicit sessionDir keeps every artifact inside a temp dir the sweep can
  // scan; the default resolves under the real ~/.pi/agent/sessions.
  const sessionDir = mkdtempSync(join(tmpdir(), "pi-secret-sessions-"));
  // DefaultResourceLoaderOptions requires agentDir; a fresh temp one keeps the
  // real user config/extensions out of the sweep.
  const agentDir = mkdtempSync(join(tmpdir(), "pi-secret-agent-"));
  if (options.settings) writeFileSync(join(agentDir, "settings.json"), JSON.stringify(options.settings));
  // The SettingsManager must be bound to the SAME temp agentDir, or it silently
  // defaults to the real ~/.pi/agent and the suite inherits the developer's own
  // settings.json — compaction thresholds, model defaults, whatever is in there.
  // Found while adding the compaction scenario: keepRecentTokens came back 20000
  // despite the file above.
  const settingsManager = SettingsManager.create(cwd, agentDir);
  const loader = new DefaultResourceLoader({
    cwd,
    agentDir,
    extensionFactories: [
      { name: "pi-secret-faux-provider", factory: (pi) => pi.registerProvider(provider as never) },
      ...(options.probeExtensionFactories ?? []).slice(0, 1),
      { name: "pi-secret", factory: piSecret },
      ...(options.probeExtensionFactories ?? []).slice(1),
    ],
  });
  await loader.reload();
  const sessionManager = SessionManager.create(cwd, sessionDir);
  // Snapshot pi-bash* names already on disk so this run's artifacts() only
  // reports snapshots THIS session could have written (stale ones from earlier
  // runs/processes otherwise poison every scenario).
  const bashTempBaseline = new Set(safeReaddir(tmpdir()).filter((n) => n.startsWith("pi-bash")));
  const { session } = await createAgentSession({
    cwd,
    model,
    modelRuntime: runtime,
    sessionManager,
    resourceLoader: loader,
    settingsManager,
    tools: options.tools ?? ["bash", "read", "write", "edit"],
  });
  return {
    session,
    faux,
    cwd,
    sessionDir,
    model,
    sessionFile: () => session.sessionFile,
    bashTempBaseline,
    dispose: () => session.dispose(),
  };
}

/** Every session and temp file this run may have written. */
export function artifacts(sessionDir: string, bashTempBaseline?: Set<string>): string[] {
  const files: string[] = [];
  const walk = (dir: string, depth = 0) => {
    if (depth > 6) return;
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) walk(full, depth + 1);
      else files.push(full);
    }
  };
  try {
    walk(sessionDir);
  } catch {
    /* no session dir yet */
  }
  // pi's bash truncation writes raw snapshots here — spec §4 row 7.
  for (const entry of safeReaddir(tmpdir())) {
    if (entry.startsWith("pi-bash") && !bashTempBaseline?.has(entry)) files.push(join(tmpdir(), entry));
  }
  return files;
}

function safeReaddir(dir: string): string[] {
  try {
    return readdirSync(dir);
  } catch {
    return [];
  }
}

export function readAll(files: string[]): string {
  return files.map((f) => readFileSync(f, "utf8")).join("\n");
}
