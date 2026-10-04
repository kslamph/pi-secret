import { mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createAgentSession,
  DefaultResourceLoader,
  ModelRuntime,
  SessionManager,
} from "@earendil-works/pi-coding-agent";
import { fauxAssistantMessage, fauxProvider, fauxToolCall } from "@earendil-works/pi-ai";
import piSecure from "../../src/index.ts";

export interface SecureSessionOptions {
  responses: Parameters<ReturnType<typeof fauxProvider>["setResponses"]>[0];
  tools?: string[];
  cwd?: string;
}

export async function makeSecureSession(options: SecureSessionOptions) {
  const faux = fauxProvider({ models: [{ id: "canary-model", name: "Canary", contextWindow: 100_000, maxTokens: 4096 }] });
  faux.setResponses(options.responses);
  const runtime = await ModelRuntime.create({ allowModelNetwork: false, refreshOnCreate: false });
  // ModelRuntime.registerProvider takes (id, config), NOT a Provider object, so
  // the faux Provider is registered through the extension API (which does accept
  // a full pi-ai Provider) via a named inline factory below.
  const model = faux.getModel("canary-model") ?? faux.getModel();
  const cwd = options.cwd ?? mkdtempSync(join(tmpdir(), "pi-secure-cwd-"));
  // An explicit sessionDir keeps every artifact inside a temp dir the sweep can
  // scan; the default resolves under the real ~/.pi/agent/sessions.
  const sessionDir = mkdtempSync(join(tmpdir(), "pi-secure-sessions-"));
  // DefaultResourceLoaderOptions requires agentDir; a fresh temp one keeps the
  // real user config/extensions out of the sweep.
  const agentDir = mkdtempSync(join(tmpdir(), "pi-secure-agent-"));
  const loader = new DefaultResourceLoader({
    cwd,
    agentDir,
    extensionFactories: [
      { name: "pi-secure-faux-provider", factory: (pi) => pi.registerProvider(faux.provider) },
      { name: "pi-secure", factory: piSecure },
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
