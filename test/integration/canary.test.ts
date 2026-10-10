import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fauxAssistantMessage, fauxToolCall } from "@earendil-works/pi-ai";
import { buildSessionContext, parseSessionEntries } from "@earendil-works/pi-coding-agent";
import { artifacts, makeSecureSession, readAll, readNonModel } from "../helpers/session.ts";
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
  it("a literal the MODEL wrote stays in the transcript, and never comes back", async () => {
    // The one-directional contract, pinned. pi-secret filters what goes TO the endpoint and
    // nothing else, so text the model produced is persisted exactly as produced: there is no
    // `message_end` rewrite and no compaction-summary amendment any more. The model can only
    // know this canary because the script handed it to the model, which is exactly the upstream
    // leak these assertions are about surviving.
    const cwd = mkdtempSync(join(tmpdir(), "canary-"));
    const harness = await makeSecureSession({
      cwd,
      responses: [
        fauxAssistantMessage([fauxToolCall("bash", { command: 'printf %s "$' + CANARY + '"' })]),
        fauxAssistantMessage("done"),
      ],
    });
    teardown.push(() => harness.dispose());
    seedVault(harness.sessionFile() ?? "ephemeral");

    await harness.session.prompt("print the token");

    const files = artifacts(harness.sessionDir, harness.bashTempBaseline);
    // NOT filtered: the model's own message is on disk verbatim...
    expect(readAll(files)).toContain(CANARY);
    // ...but everything pi-secret still owns (user text, tool results, snapshots) is not.
    expect(readNonModel(files)).not.toContain(CANARY);
    // And it never re-enters a model-facing context, which is the half that matters.
    const material = materialText(harness.session.messages);
    expect(material).not.toContain(CANARY);
    expect(material).toContain("{{" + "sec:gh_pat" + "}}");
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
        fauxAssistantMessage([fauxToolCall("write", { path: "leak.txt", content: `token={{sec:redacted}}` })]),
        fauxAssistantMessage("understood"),
      ],
    });
    teardown.push(() => harness.dispose());
    // Seeded, deliberately. The refusal is `tool_call`'s job: it fires because the value is
    // VAULTED, not because `message_end` sanitised the argument first (it no longer does).
    // Without a vault entry the argument holds a value pi-secret has no business
    // recognising, and the write is allowed.
    seedVault(harness.sessionFile() ?? "ephemeral");

    await harness.session.prompt("write the token to a file");
    expect(existsSync(join(cwd, "leak.txt"))).toBe(false);
  });

  it("a truncated dump leaves no unscrubbed snapshot on disk", async () => {
    // Forces pi's own truncation path: the result carries details.fullOutputPath pointing at
    // the raw output, which is a real read-back channel for the model. The value arrives
    // through the ENVIRONMENT rather than the command, because a literal in the command is
    // refused by `tool_call` (the model cannot know a vaulted value) — which would skip the
    // truncation path entirely and make this vacuous.
    const cwd = mkdtempSync(join(tmpdir(), "canary-"));
    const harness = await makeSecureSession({
      cwd,
      responses: [
        fauxAssistantMessage([fauxToolCall("bash", { command: 'yes "$PROBE_TOKEN" | head -n 8000' })]),
        fauxAssistantMessage("done"),
      ],
    });
    teardown.push(() => harness.dispose());
    seedVault(harness.sessionFile() ?? "ephemeral");
    process.env.PROBE_TOKEN = CANARY;

    await harness.session.prompt("flood the output");
    delete process.env.PROBE_TOKEN;

    const files = artifacts(harness.sessionDir, harness.bashTempBaseline);
    // Non-vacuity: pi really did spill a snapshot, so the rewrite had something to do.
    expect(files.some((f) => f.includes("pi-bash"))).toBe(true);
    const text = readNonModel(files);
    expect(text).not.toContain(CANARY);
    expect(text).toContain("{{" + "sec:gh_pat" + "}}");
  });

  it("/export HTML carries refs, never the canary", async () => {
    // spec §13.4: the HTML exporter renders through a path we don't model, so the
    // only honest check is exporting and grepping the file. Skipping this lets a
    // renderer regression leak every stored secret to a shareable HTML file.
    //
    // The canary reaches the transcript through the ENVIRONMENT, not through the model's
    // own message: text the model wrote is deliberately left verbatim, so asserting on the
    // export would be asserting that the exporter rewrites the model — which is exactly what
    // this extension no longer does. What must hold is that the part pi-secret DOES own,
    // the scrubbed tool result, stays scrubbed through the export path.
    const cwd = mkdtempSync(join(tmpdir(), "canary-"));
    writeFileSync(join(cwd, "probe.sh"), '#!/bin/sh\nprintf "TOKEN=%s\\n" "$PROBE_TOKEN"\n');
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
    delete process.env.PROBE_TOKEN;

    const htmlPath = await harness.session.exportToHtml(join(cwd, "export.html"));
    const html = readFileSync(htmlPath, "utf8");
    expect(html).not.toContain(CANARY);
    // The message payload rides base64 inside <script id="session-data">, so the
    // ref only shows up after decoding — check there, and check the canary isn't
    // hiding in the decoded bytes either.
    const b64 = /<script id="session-data"[^>]*>([^<]+)</.exec(html)?.[1] ?? "";
    expect(b64.length).toBeGreaterThan(0);
    const decoded = Buffer.from(b64, "base64").toString("utf8");
    expect(decoded).toContain("{{" + "sec:gh_pat" + "}}");
    expect(decoded).not.toContain(CANARY);
    const corpus = readNonModel(artifacts(harness.sessionDir, harness.bashTempBaseline));
    expect(corpus).not.toContain(CANARY);
  });

  // Regression, 2026-10-10: reading a PNG produced "masked 4 secret occurrence(s) in
  // read output" and the NEXT provider request came back 400 invalid_request. The AWS
  // prefix rule matched case-insensitively inside the base64 payload, and the rewrite
  // left data that no longer decoded — so the provider was handed a broken image.
  //
  // The fixture is built so the bug is REACHABLE: the 15 bytes encoding the AWS key
  // shape are appended at a 3-aligned offset, so their base64 spelling survives as a
  // literal in the payload. Verified with the guard disabled: this test fails there,
  // which is the only reason to believe it.
  it("hands the provider an image that still decodes", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "canary-"));
    const png = Buffer.from(
      "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
      "base64",
    );
    // base64 emits whole 4-char groups per 3 input bytes; pad so the appended 15 bytes
    // start on a group boundary and encode to the literal string, not a shifted one.
    const pad = (3 - (png.length % 3)) % 3;
    const awsShape = "AkIA8BxxiyzGikq3xhqm";
    const fixture = Buffer.concat([png, Buffer.alloc(pad), Buffer.from(awsShape, "base64")]);
    expect(fixture.toString("base64")).toContain(awsShape);
    writeFileSync(join(cwd, "shot.png"), fixture);

    const wire: unknown[] = [];
    const harness = await makeSecureSession({
      cwd,
      onProviderPayload: (payload) => {
        wire.push(payload);
      },
      responses: [
        fauxAssistantMessage([fauxToolCall("read", { path: "shot.png" })]),
        fauxAssistantMessage("done"),
      ],
    });
    teardown.push(() => harness.dispose());
    seedVault(harness.sessionFile() ?? "ephemeral");

    await harness.session.prompt("look at the screenshot");

    const json = JSON.stringify(wire);
    // Non-vacuity, stated as the precondition it is: the shape that used to corrupt the
    // payload really is in there, byte for byte.
    expect(json).toContain(awsShape);
    expect(json).toContain('"mimeType":"image/png"');
    const data = /"data":"([A-Za-z0-9+/=]+)"/.exec(json)?.[1] ?? "";
    expect(data.length).toBeGreaterThan(0);
    expect(data).toContain(awsShape);
    const bytes = Buffer.from(data, "base64");
    expect(bytes.subarray(0, 8).toString("hex")).toBe("89504e470d0a1a0a");
    expect(bytes.equals(fixture)).toBe(true);
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

/**
 * spec §12g — the file-import flow, under the sweep that does not care which path leaked.
 *
 * The import is a NEW ingest route, and a new route is exactly when a canary run earns its keep:
 * the property worth pinning is not only "the value stays out" but "the import leaves no trace in
 * the transcript at all" — no receipt carrying values, no entry recording the file.
 */
describe("/sec add-from-file under the canary sweep", () => {
  it("puts the value in the vault and nothing whatsoever in the transcript", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "canary-"));
    // The fixture is SUPPOSED to contain the canary, so it lives outside every swept root
    // (the sweep enumerates `pi-secret-sessions-*`, `pi-secret-cwd-*` and `pi-bash*`).
    const source = mkdtempSync(join(tmpdir(), "pi-secret-import-src-"));
    const file = join(source, ".env");
    writeFileSync(file, `IMPORTED_KEY=${CANARY}\nPORT=8080\n`);

    const harness = await makeSecureSession({ cwd, responses: [fauxAssistantMessage("done")] });
    teardown.push(() => harness.dispose());
    const sessionFile = harness.sessionFile()!;
    // One turn first, so the transcript exists and the "nothing was appended" check below has
    // something to be about.
    await harness.session.prompt("hello");
    setActiveScopeKey(sessionFile);

    const { runSecCommand } = await import("../../src/commands.ts");
    const notified: string[] = [];
    await runSecCommand(`add-from-file ${file}`, vaultForSession(sessionFile), {
      mode: "tui",
      hasUI: true,
      cwd,
      ui: {
        notify: (message: string) => void notified.push(message),
        // Both rows are ticked; the sort is credential-first, then stable.
        custom: async () => [0, 1],
      },
    } as never);

    // The vault really did receive it, so the assertions below are not vacuous.
    expect(vaultForSession(sessionFile).resolve("imported_key")).toBe(CANARY);
    expect(vaultForSession(sessionFile).entries().map((e) => e.source)).toEqual(["file", "file"]);

    // The receipt names the key and its length; it must not name the value.
    expect(notified.join("\n")).toContain("imported_key");
    expect(notified.join("\n")).not.toContain(CANARY);

    const corpus = readAll(artifacts(harness.sessionDir, harness.bashTempBaseline));
    expect(corpus).not.toContain(CANARY);
    // Neither the value nor the imported NAME reaches the transcript: nothing was appended.
    expect(readFileSync(sessionFile, "utf8")).not.toContain("imported_key");
  });
});

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

    // The FILE is no longer half the contract. A compaction summary is model-authored
    // text, and model-authored text is deliberately NOT filtered — there is no
    // `session_compact` amendment and no `message_end` rewrite. So the summary keeps the
    // literal the model wrote, on disk, in the transcript of record. What still holds is
    // the direction that matters: the wire never carried it, and the non-model half of
    // every artifact still does not.
    const files = artifacts(harness.sessionDir, harness.bashTempBaseline);
    expect(readAll(files)).toContain(CANARY);
    const corpus = readNonModel(files);
    expect(corpus).not.toContain(CANARY);
    expect(corpus).toContain("{{" + "sec:gh_pat" + "}}");
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
