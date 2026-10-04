import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fauxAssistantMessage, fauxToolCall } from "@earendil-works/pi-ai";
import { artifacts, makeSecureSession, readAll } from "../helpers/session.ts";
import { setActiveScopeKey, vaultForSession } from "../../src/vault.ts";

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
