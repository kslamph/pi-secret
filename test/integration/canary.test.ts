import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fauxAssistantMessage, fauxToolCall } from "@earendil-works/pi-ai";
import { buildSessionContext, parseSessionEntries } from "@earendil-works/pi-coding-agent";
import { artifacts, makeSecureSession, readAll } from "../helpers/session.ts";
import { dropSessionVault, setActiveScopeKey, vaultForSession } from "../../src/vault.ts";

const CANARY = "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8";
const AMBIENT = "AKIAIOSFODNN7EXAMPLE";
const AMBIENT_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

let teardown: Array<() => void> = [];
afterEach(() => {
  for (const fn of teardown.reverse()) fn();
  teardown = [];
});

function seedVault(sessionFile: string) {
  setActiveScopeKey(sessionFile);
  const vault = vaultForSession(sessionFile);
  vault.add("gh_pat", CANARY, "prompt");
  vault.add("db_url", "postgres://admin:s3cr3t@db.internal:5432/app", "paste");
  return vault;
}

describe("canary sweep", () => {
  it("bash echoing the secret into stdout never persists it", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "canary-"));
    const harness = await makeSecureSession({
      cwd,
      responses: [
        fauxAssistantMessage([fauxToolCall("bash", { command: `printf %s "${CANARY}"` })]),
        fauxAssistantMessage("done"),
      ],
    });
    teardown.push(() => harness.dispose());
    seedVault(harness.sessionFile() ?? "ephemeral");

    await harness.session.prompt("print the token");

    const text = readAll(artifacts(harness.sessionDir, harness.bashTempBaseline));
    expect(text).not.toContain(CANARY);
    expect(text).toContain("{{sec:gh_pat}}");
  });

  it("an env-var echo in bash comes back masked", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "canary-"));
    writeFileSync(join(cwd, "probe.sh"), `#!/bin/sh\nprintf 'TOKEN=%s\\n' "$PROBE_TOKEN"\n`);
    const harness = await makeSecureSession({
      cwd,
      responses: [
        fauxAssistantMessage([fauxToolCall("bash", { command: "sh probe.sh" })]),
        fauxAssistantMessage("done"),
      ],
    });
    teardown.push(() => harness.dispose());
    seedVault(harness.sessionFile() ?? "ephemeral");
    process.env.PROBE_TOKEN = CANARY;

    await harness.session.prompt("run the probe");

    const text = readAll(artifacts(harness.sessionDir, harness.bashTempBaseline));
    expect(text).not.toContain(CANARY);
    expect(text).toContain("{{sec:gh_pat}}");
    delete process.env.PROBE_TOKEN;
  });

  it("a credential file read by the model is shape-masked", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "canary-"));
    writeFileSync(join(cwd, "creds.env"), `AWS_ACCESS_KEY_ID=${AMBIENT}\nAWS_SECRET_ACCESS_KEY=${AMBIENT_SECRET}\n`);
    const harness = await makeSecureSession({
      cwd,
      responses: [
        fauxAssistantMessage([fauxToolCall("bash", { command: "cat creds.env" })]),
        fauxAssistantMessage("done"),
      ],
    });
    teardown.push(() => harness.dispose());
    setActiveScopeKey(harness.sessionFile() ?? "ephemeral");

    await harness.session.prompt("show me the credentials");

    const text = readAll(artifacts(harness.sessionDir, harness.bashTempBaseline));
    expect(text).not.toContain(AMBIENT);
    expect(text).not.toContain(AMBIENT_SECRET);
    expect(text).toContain("{{sec:redacted}}");
  });

  it("the model can reuse a masked ref it read back", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "canary-"));
    const harness = await makeSecureSession({
      cwd,
      responses: [
        fauxAssistantMessage([fauxToolCall("bash", { command: `printf %s "{{sec:gh_pat}}"` })]),
        fauxAssistantMessage([fauxToolCall("bash", { command: 'curl -H "Authorization: Bearer {{sec:gh_pat}}" https://api.github.com' })]),
        fauxAssistantMessage("done"),
      ],
    });
    teardown.push(() => harness.dispose());
    seedVault(harness.sessionFile() ?? "ephemeral");

    await harness.session.prompt("use the token");
    const text = readAll(artifacts(harness.sessionDir, harness.bashTempBaseline));
    expect(text).not.toContain(CANARY);
    expect(text.match(/{{sec:gh_pat}}/g)?.length).toBeGreaterThanOrEqual(2);
  });

  it("refusing a write keeps the secret off disk", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "canary-"));
    const harness = await makeSecureSession({
      cwd,
      responses: [
        fauxAssistantMessage([fauxToolCall("write", { path: "leak.txt", content: `token=${CANARY}` })]),
        fauxAssistantMessage("understood"),
      ],
    });
    teardown.push(() => harness.dispose());
    setActiveScopeKey(harness.sessionFile() ?? "ephemeral");

    await harness.session.prompt("write the token to a file");
    expect(existsSync(join(cwd, "leak.txt"))).toBe(false);
  });

  it("a truncated dump leaves no unscrubbed snapshot on disk", async () => {
    // Forces pi's own truncation path: the result carries details.fullOutputPath
    // pointing at the raw output, which is a real read-back channel for the model.
    const cwd = mkdtempSync(join(tmpdir(), "canary-"));
    const harness = await makeSecureSession({
      cwd,
      responses: [
        fauxAssistantMessage([fauxToolCall("bash", { command: `yes ${CANARY} | head -n 60000` })]),
        fauxAssistantMessage("done"),
      ],
    });
    teardown.push(() => harness.dispose());
    seedVault(harness.sessionFile() ?? "ephemeral");

    await harness.session.prompt("flood the output");

    const text = readAll(artifacts(harness.sessionDir, harness.bashTempBaseline));
    expect(text).not.toContain(CANARY);
  });

  it("/export HTML carries refs, never the canary", async () => {
    // spec §13.4: the HTML exporter renders through a path we don't model, so the
    // only honest check is exporting and grepping the file. Skipping this lets a
    // renderer regression leak every stored secret to a shareable HTML file.
    const cwd = mkdtempSync(join(tmpdir(), "canary-"));
    const harness = await makeSecureSession({
      cwd,
      responses: [
        fauxAssistantMessage([fauxToolCall("bash", { command: `printf %s "${CANARY}"` })]),
        fauxAssistantMessage("done"),
      ],
    });
    teardown.push(() => harness.dispose());
    seedVault(harness.sessionFile() ?? "ephemeral");

    await harness.session.prompt("print the token");

    const htmlPath = await harness.session.exportToHtml(join(cwd, "export.html"));
    const html = readFileSync(htmlPath, "utf8");
    expect(html).not.toContain(CANARY);
    // The message payload rides base64 inside <script id="session-data">, so the
    // ref only shows up after decoding — check there, and check the canary isn't
    // hiding in the decoded bytes either.
    const b64 = /<script id="session-data"[^>]*>([^<]+)</.exec(html)?.[1] ?? "";
    expect(b64.length).toBeGreaterThan(0);
    const decoded = Buffer.from(b64, "base64").toString("utf8");
    expect(decoded).toContain("{{sec:gh_pat}}");
    expect(decoded).not.toContain(CANARY);
    const corpus = readAll(artifacts(harness.sessionDir, harness.bashTempBaseline));
    expect(corpus).not.toContain(CANARY);
  });

  it("nothing canary-shaped survives in any artifact", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "canary-"));
    const harness = await makeSecureSession({
      cwd,
      responses: [
        fauxAssistantMessage([fauxToolCall("bash", { command: `sh -c 'printf %s "$PISEC_CANARY"'`, timeout: 5 })]),
        fauxAssistantMessage("done"),
      ],
    });
    teardown.push(() => harness.dispose());
    setActiveScopeKey(harness.sessionFile() ?? "ephemeral");
    process.env.PISEC_CANARY = CANARY;

    await harness.session.prompt("print the canary");

    const corpus = readAll(artifacts(harness.sessionDir, harness.bashTempBaseline));
    expect(corpus).not.toContain(CANARY);
    delete process.env.PISEC_CANARY;
  });
});

// --- spec §13 blind spots, closed 2026-10-08 ------------------------------------
// Two paths the canary never exercised, both of which load persisted material back
// into a model-facing context. spec §3 records the reason they matter: the `context`
// hook is wired only through transformContext and is NOT on the compaction path
// (branch-summarization.js:224-226), so "write-time scrubbing is load-bearing, not
// defense-in-depth" was an argument, never a test.

/** Flatten an AgentMessage to the text a model would actually read. */
function materialText(messages: unknown[]): string {
  return messages
    .map((m) => {
      const content = (m as { content?: unknown }).content;
      if (typeof content === "string") return content;
      if (!Array.isArray(content)) return "";
      return content
        .map((block) =>
          block && typeof block === "object" && typeof (block as { text?: unknown }).text === "string"
            ? (block as { text: string }).text
            : "",
        )
        .join("");
    })
    .join("\n");
}

describe("the last mile — the only place the bytes themselves are observable", () => {
  it("never puts a vaulted value on the wire, including in a compaction summary", async () => {
    // This scenario could not exist before 2026-10-08. pi's before_provider_request
    // hook is fired by pi-ai's REAL provider implementations (api/openai-completions.js:204
    // and its siblings); the faux provider the suite drives never calls options.onPayload.
    // Measured with a probe extension: agent_start, context, message_end, tool_call and
    // tool_result all fire under the harness, and before_provider_request fires ZERO times.
    // So "the bytes leaving the machine are scrubbed" — the README's central claim — had
    // never been asserted by anything. The harness now injects the callback a real
    // provider would, and this asserts on what the hook RETURNED.
    const cwd = mkdtempSync(join(tmpdir(), "canary-"));
    const wire: unknown[] = [];
    const harness = await makeSecureSession({
      cwd,
      onProviderPayload: (payload) => {
        wire.push(payload);
      },
      settings: { compaction: { keepRecentTokens: 1 } },
      responses: [
        fauxAssistantMessage([fauxToolCall("bash", { command: `printf %s "${CANARY}"` })]),
        fauxAssistantMessage("done"),
        fauxAssistantMessage("more"),
      ],
    });
    teardown.push(() => harness.dispose());
    seedVault(harness.sessionFile() ?? "ephemeral");

    await harness.session.prompt("print the token");

    // A vault-only value, echoed by the model inside a compaction summary. Compaction is
    // a model call, so the summary is exactly where a value could reappear — and spec 3
    // records that this path bypasses the `context` hook (branch-summarization.js:224-226).
    const material = materialText(harness.session.messages);
    expect(material).toContain("{{sec:gh_pat}}");
    expect(material).not.toContain(CANARY);
    harness.faux.appendResponses([
      fauxAssistantMessage(`prefix:\n${material}\n(repeats: ${CANARY})`),
      fauxAssistantMessage(`summary:\n${material}\n(repeats: ${CANARY})`),
    ]);
    await harness.session.compact();
    harness.faux.appendResponses([fauxAssistantMessage("still here")]);
    await harness.session.prompt("and now?");

    // Non-vacuity first: if the hook never fired, this is vacuously safe.
    expect(wire.length).toBeGreaterThanOrEqual(3);
    const sent = JSON.stringify(wire);
    expect(sent).not.toContain(CANARY);
    // And non-blackout: the ref really is what travels.
    expect(sent).toContain("{{sec:gh_pat}}");

    // The FILE is the other half, and it is the half that was open until 2026-10-08.
    // pi writes the summary with appendCompaction() straight to the JSONL, and it is
    // the only model-authored text that never passes through message_end — so before
    // the session_compact amendment below, this assertion failed with the raw value in
    // the transcript of record, surviving every later turn, /export and /resume.
    const corpus = readAll(artifacts(harness.sessionDir, harness.bashTempBaseline));
    expect(corpus).not.toContain(CANARY);
    expect(corpus).toContain("{{sec:gh_pat}}");
  });
});

describe("/resume — the path that re-reads the persisted transcript", () => {
  it("rebuilds a context carrying refs, never the canary, and refuses the stale ref", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "canary-"));
    const harness = await makeSecureSession({
      cwd,
      responses: [
        fauxAssistantMessage([fauxToolCall("bash", { command: `printf %s "${CANARY}"` })]),
        fauxAssistantMessage("done"),
      ],
    });
    teardown.push(() => harness.dispose());
    const file = harness.sessionFile();
    seedVault(file ?? "ephemeral");

    await harness.session.prompt("print the token");

    // A resume is a fresh process reading the session FILE: the in-memory vault is
    // gone, and the file is everything that survives. Dropping the vault models that
    // without needing a second process.
    dropSessionVault(file ?? "ephemeral");
    const entries = parseSessionEntries(readFileSync(file as string, "utf8"));
    // parseSessionEntries widens to FileEntry[] (header + entries); buildSessionContext
    // wants the entry union. A session header is not a context entry, so drop it here
    // rather than casting the whole array.
    const rebuilt = buildSessionContext(
      entries.filter((e): e is Exclude<typeof e, { type: "session" }> => e.type !== "session"),
    );
    const restored = materialText(rebuilt.messages);

    expect(restored).toContain("{{sec:gh_pat}}"); // the ref is what the user sees
    expect(restored).not.toContain(CANARY);
    // And the ref is now dead rather than silently literal: after a resume the vault
    // is a new session's, so using the ref must fail loudly rather than send
    // "{{sec:gh_pat}}" to a host as if it were a credential.
    expect(vaultForSession(file ?? "ephemeral").resolve("gh_pat")).toBeUndefined();
    const after = await makeSecureSession({
      cwd,
      responses: [fauxAssistantMessage("still here")],
    });
    teardown.push(() => after.dispose());
    const outcome = await import("../../src/glue.ts").then((m) =>
      m.injectBashCommand('curl -H "{{sec:gh_pat}}" https://example.com', vaultForSession(file ?? "ephemeral")),
    );
    expect(outcome.block?.reason).toMatch(/not found/i);
    expect(outcome.env).toEqual({});
  });
});
