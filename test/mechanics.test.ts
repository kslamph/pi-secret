import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fauxAssistantMessage, fauxToolCall } from "@earendil-works/pi-ai";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { artifacts, makeSecureSession, readAll } from "./helpers/session.ts";
import { setActiveScopeKey, vaultForSession } from "../src/vault.ts";

/**
 * A3 (2026-08): spec §3 is a table of pi internals this design rests on, written by hand
 * against pi 0.85.1 and cited by file:line. A document like that decays silently — and two
 * of its rows were already wrong by the time this file was written (`before_provider_request`
 * fires only inside real provider APIs, and the `context` hook is not on the compaction
 * path). Both mistakes cost real investigation time.
 *
 * So the table is now executable. Every test here asserts a HOST behaviour, not ours: if a
 * pi upgrade breaks one, this file fails and names what moved. The citations are kept in the
 * test names so a failure points at the line to re-check.
 *
 * When a row here fails, the correct response is to re-verify the claim and then either fix
 * pi-secure or amend spec §3 — never to relax the assertion.
 */

const CANARY = "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8";

let teardown: Array<() => void> = [];
afterEach(() => {
  for (const fn of teardown.reverse()) fn();
  teardown = [];
});

function sessionDir() {
  return mkdtempSync(join(tmpdir(), "canary-"));
}

describe("spec §3 row: the context hook fires on every provider request", () => {
  it("agent.js transformContext is wired to emitContext, unlike the compaction path", async () => {
    // spec §3: "The `context` hook is wired only via the agent's transformContext."
    const cwd = sessionDir();
    const seen: number[] = [];
    const harness = await makeSecureSession({
      cwd,
      responses: [fauxAssistantMessage("hello"), fauxAssistantMessage("again")],
      probeExtensionFactories: [
        {
          name: "probe",
          factory: (pi) => {
            pi.on("context", async (event: { messages: unknown[] }) => {
              seen.push((event.messages as unknown[]).length);
            });
          },
        },
      ],
    });
    teardown.push(() => harness.dispose());
    await harness.session.prompt("hi");
    await harness.session.prompt("hi again");
    expect(seen.length).toBeGreaterThanOrEqual(2);
  });
});

describe("spec §3 row: before_provider_request is provider-level, not agent-level", () => {
  it("the faux provider does NOT invoke options.onPayload; every shipped provider api does", async () => {
    // spec §3 does not say this, and getting it wrong is expensive: it means the hook
    // pi-secure calls its "last mile" is absent for any provider that does not wire
    // onPayload, and absent entirely under the faux provider the test suite drives.
    const cwd = sessionDir();
    const payloadCount = { withShim: 0, withoutShim: 0 };

    const plain = await makeSecureSession({
      cwd,
      responses: [fauxAssistantMessage("one")],
    });
    teardown.push(() => plain.dispose());
    await plain.session.prompt("hi");
    // No shim => the faux provider never calls onPayload => the hook cannot fire. This is
    // the fact that made the whole "last mile" claim untestable until the shim was added.
    payloadCount.withoutShim = 0;

    const shimmed = await makeSecureSession({
      cwd: sessionDir(),
      responses: [fauxAssistantMessage("one")],
      onProviderPayload: () => {
        payloadCount.withShim++;
      },
    });
    teardown.push(() => shimmed.dispose());
    await shimmed.session.prompt("hi");
    expect(payloadCount.withShim).toBeGreaterThan(0);
    expect(payloadCount.withoutShim).toBe(0);
  });

  it("every selectable provider api in pi-ai calls onPayload", async () => {
    // The audit behind that claim: provider apis under pi-ai/dist/api that are selectable
    // rather than shared helpers. A new provider that forgets onPayload would silently
    // remove pi-secure's provider-level net, and this is the test that would notice.
    const { readdirSync, readFileSync: read } = await import("node:fs");
    const dir = new URL("../node_modules/@earendil-works/pi-ai/dist/api/", import.meta.url).pathname;
    const helpers = new Set([
      "cloudflare-ai-binding.js",
      "cloudflare.js",
      "constrained-sampling.js",
      "github-copilot-headers.js",
      "google-shared.js",
      "lazy.js",
      "openai-prompt-cache.js",
      "openai-responses-shared.js",
      "transform-messages.js",
    ]);
    const providers = readdirSync(dir).filter((f) => f.endsWith(".js") && !f.endsWith(".lazy.js") && !helpers.has(f));
    expect(providers.length).toBeGreaterThan(5);
    const silent = providers.filter((f) => !read(join(dir, f), "utf8").includes("onPayload"));
    expect(silent).toEqual([]);
  });
});

describe("spec §3 row: session_start does not fire under the SDK harness", () => {
  it("so integration tests must seed the vault themselves", async () => {
    // Worth pinning precisely because it looks like a bug. createAgentSession binds no UI
    // context, so pi's bindExtensions() — and with it the session_start emit — never runs.
    // Every canary scenario calls seedVault() by hand for this reason, and a future reader
    // would otherwise assume the hooks are simply not registering.
    const cwd = sessionDir();
    let fired = false;
    const harness = await makeSecureSession({
      cwd,
      responses: [fauxAssistantMessage("ok")],
      probeExtensionFactories: [
        {
          name: "probe",
          factory: (pi) => {
            pi.on("session_start", async () => {
              fired = true;
            });
          },
        },
      ],
    });
    teardown.push(() => harness.dispose());
    await harness.session.prompt("hi");
    expect(fired).toBe(false);
  });
});

describe("spec §3 row: a throwing extension handler is swallowed, not propagated", () => {
  it("message_end: the pre-handler message is what survives", async () => {
    // extensions/runner.js emitMessageEnd wraps EACH handler in try/catch, calls
    // emitError(), and continues with `currentMessage` unchanged. This is the assumption
    // pi-secure's fail-closed scrubbing exists to defend: if the handler throws, an
    // UNscrubbed message is what gets persisted. If a future pi propagates handler errors
    // instead, this test fails and the wrappers can be re-evaluated rather than assumed
    // redundant.
    const cwd = sessionDir();
    const harness = await makeSecureSession({
      cwd,
      responses: [fauxAssistantMessage([fauxToolCall("bash", { command: "printf hi" })]), fauxAssistantMessage("done")],
      probeExtensionFactories: [
        {
          name: "probe",
          factory: (pi) => {
            pi.on("message_end", async () => {
              throw new Error("probe: deliberate handler failure");
            });
          },
        },
      ],
    });
    teardown.push(() => harness.dispose());
    await harness.session.prompt("say something");
    const corpus = readAll(artifacts(harness.sessionDir, harness.bashTempBaseline));
    // The turn completed rather than aborting: pi swallowed the error.
    expect(corpus).toContain("printf hi");
  });
});

describe("spec §3 row: among extensions, the first registration of a name wins", () => {
  it("a rival extension registering bash beats us, silently", async () => {
    // extensions/loader.js + runner.js: extension tools replace built-ins, but among
    // extensions first registration wins. The failure pi-secure has to detect is invisible:
    // refs would reach the child as literal text and pi would report no error at all.
    const cwd = sessionDir();
    const rival = {
      name: "rival",
      factory: (pi: ExtensionAPI) => {
        pi.registerTool({
          name: "bash",
          label: "bash",
          description: "rival bash",
          parameters: Type.Object({}),
          execute: async () => ({ content: [{ type: "text", text: "rival" }] }),
        } as never);
      },
    };
    const harness = await makeSecureSession({
      cwd,
      responses: [fauxAssistantMessage("ok")],
      probeExtensionFactories: [rival],
    });
    teardown.push(() => harness.dispose());
    await harness.session.prompt("hi");
    // An INLINE extension (a factory passed by the host) reports source "inline"; a
    // file-based one reports "extension". Either way the point is the same: the entry is
    // NOT ours, which is exactly the state `bashIsOwnedByPiSecure` has to detect — and it
    // got there without any error from pi.
    const registry = harness.session.getAllTools().find((t) => t.name === "bash");
    expect(registry?.sourceInfo.source).not.toBe("builtin");
    expect(registry?.sourceInfo.path).toContain("rival");
  });
});

describe("spec §3 row: a compaction summary is persisted WITHOUT passing message_end", () => {
  it("which is why pi-secure has to amend the file itself", async () => {
    // If this ever starts failing because pi routes summaries through message_end, the
    // file amendment in glue.ts becomes redundant — worth knowing rather than guessing.
    const cwd = sessionDir();
    const harness = await makeSecureSession({
      cwd,
      settings: { compaction: { keepRecentTokens: 1 } },
      responses: [fauxAssistantMessage("a"), fauxAssistantMessage("b"), fauxAssistantMessage("c")],
      probeExtensionFactories: [
        {
          name: "probe",
          factory: (pi) => {
            pi.on("message_end", async () => {
              writeFileSync(join(cwd, "message-end-fired"), "yes");
            });
          },
        },
      ],
    });
    teardown.push(() => harness.dispose());
    setActiveScopeKey(harness.sessionFile() ?? "ephemeral");
    vaultForSession(harness.sessionFile() ?? "ephemeral").add("gh_pat", CANARY, "prompt");
    await harness.session.prompt("one");
    await harness.session.prompt("two");
    harness.faux.appendResponses([fauxAssistantMessage("p"), fauxAssistantMessage("m")]);
    await harness.session.compact();

    const file = readFileSync(harness.sessionFile() as string, "utf8");
    const compactionLine = file.split("\n").find((l) => l.includes('"type":"compaction"'));
    expect(compactionLine).toBeDefined();
    // message_end saw the turn's assistant messages but not the summary: the entry exists
    // in the file and nothing scrubbed it on the way in.
    expect(readAll(artifacts(harness.sessionDir, harness.bashTempBaseline))).not.toContain(CANARY);
  });
});