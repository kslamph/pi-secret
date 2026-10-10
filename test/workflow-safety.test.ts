import { describe, expect, it } from "vitest";
import { maskShapes, redactAllText, scrubDeep, scrubText } from "../src/scrub.ts";
import { injectBashCommand } from "../src/glue.ts";
import { bashRefIssues } from "../src/substitute/guard.ts";
import { Vault } from "../src/vault.ts";

// Assembled, never written literally: the scrubber's own marker is a moving part in
// this repo, and a test that greps for it must not depend on how it is spelled here.
const MARKER = "{{" + "sec:redacted" + "}}";
/** A vaulted value masks to its OWN ref, not to the generic marker. */
const REF = "{{" + "sec:gh_pat" + "}}";
const GH = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";

function vault() {
  const v = new Vault("t");
  v.add("gh_pat", GH, "prompt");
  return v;
}

// --- F3 ---------------------------------------------------------------------------
// Measured 2026-10-10: 8000 hits took 623ms and 60000 hits took 32.6 SECONDS, because
// the accepted-span list was scanned linearly per candidate. That is a stall on the
// outbound path — a 4MB log repeating a vaulted value froze the turn for half a minute,
// in tool_result, in context, and in the streaming bash display.
describe("masking many occurrences stays linear enough to be usable", () => {
  it("masks 60000 occurrences well inside a test timeout", () => {
    const text = Array.from({ length: 60_000 }, () => GH).join("\n");
    const started = performance.now();
    const out = scrubText(text, vault(), { shapes: true });
    const elapsed = performance.now() - started;
    expect(out.hits).toBe(60_000);
    expect(out.text).not.toContain(GH);
    expect(out.text.split(REF).length - 1).toBe(60_000);
    // 32.6s before the fix; ~0.1s after. The bound is loose on purpose — it is here to
    // catch a return to quadratic, not to measure the machine.
    expect(elapsed).toBeLessThan(3000);
  }, 20_000);

  it("still prefers the longest span on overlap after the rewrite", () => {
    // The old linear scan implemented "longest wins"; the fast path must agree.
    const v = new Vault("t");
    v.add("short", "abcdefgh", "prompt"); // 8 chars, the scrub floor
    v.add("long", "abcdefghijkl", "prompt");
    const out = scrubDeep({ memo: "value=abcdefghijkl" }, v, { shapes: true });
    // The 12-char value must win over the 8-char prefix of it, once, not twice.
    expect((out.value as { memo: string }).memo).toBe("value={{sec:long}}");
  });
});

// --- F1 ---------------------------------------------------------------------------
// The walk treated anything that is an object as a container and shallow-cloned it.
// A Buffer, TypedArray or Date in a tool result therefore came back as
// {0:.., 1:..} / {} — silent corruption of data we have no business rewriting, on the
// same path that must never produce an invalid request.
describe("the walk leaves non-plain values alone", () => {
  it("does not explode a Buffer into an object of numeric keys", () => {
    const buf = Buffer.from("binary\x00payload\xff");
    const out = scrubDeep({ blob: buf }, vault(), { shapes: true });
    const got = (out.value as { blob: unknown }).blob;
    expect(Buffer.isBuffer(got)).toBe(true);
    expect((got as Buffer).equals(buf)).toBe(true);
  });

  it("does not turn a Date into an empty object", () => {
    const when = new Date("2026-10-10T00:00:00Z");
    const out = scrubDeep({ when }, vault(), { shapes: true });
    // The SAME instance: untouched, not a copy that has lost its Date-ness.
    expect((out.value as { when: unknown }).when).toBe(when);
  });

  it("keeps a Uint8Array, and its bytes", () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 255]);
    const out = scrubDeep({ bytes }, vault(), { shapes: true });
    const got = (out.value as { bytes: unknown }).bytes;
    expect(got).toBeInstanceOf(Uint8Array);
    expect(Array.from(got as Uint8Array)).toEqual([0, 1, 2, 250, 255]);
  });

  it("still masks plain strings beside them", () => {
    const out = scrubDeep({ blob: Buffer.from("x"), note: `token=${GH}` }, vault(), { shapes: true });
    expect((out.value as { note: string }).note).toBe("token={{sec:gh_pat}}");
  });
});

// --- F2 ---------------------------------------------------------------------------
// redactAllText is the fail-closed path for the context and before_provider_request
// hooks. It replaced EVERY string leaf, including the fields the provider validates —
// so the one time it fires it would hand the provider a request with role={{sec:...}}
// and mimeType={{sec:...}}, i.e. a guaranteed 400 instead of a redaction.
describe("fail-closed redaction keeps the request structurally valid", () => {
  const payload = () => ({
    model: "canary-model",
    messages: [
      { role: "user", content: [{ type: "text", text: `my token is ${GH}` }] },
      { role: "assistant", content: [{ type: "toolCall", id: "call_1", name: "bash", arguments: { command: "ls" } }] },
      { role: "tool", toolCallId: "call_1", content: [{ type: "text", text: "out" }] },
      { role: "user", content: [{ type: "image", mimeType: "image/png", data: "QUJD" }] },
    ],
  });

  it("preserves the keys the provider validates", () => {
    const out = redactAllText(payload()) as typeof payload extends () => infer T ? T : never;
    const msgs = (out as { messages: Array<Record<string, unknown>> }).messages;
    expect(msgs.map((m) => m.role)).toEqual(["user", "assistant", "tool", "user"]);
    expect(msgs[2]!.toolCallId).toBe("call_1");
    const blocks = msgs.map((m) => m.content as Array<Record<string, unknown>>);
    expect(blocks[0]![0]!.type).toBe("text");
    expect(blocks[1]![0]!.name).toBe("bash");
    expect(blocks[1]![0]!.id).toBe("call_1");
    expect(blocks[3]![0]!.mimeType).toBe("image/png");
  });

  it("still redacts the prose, which is the part that can carry a secret", () => {
    const out = redactAllText(payload());
    const text = JSON.stringify(out);
    expect(text).not.toContain(GH);
    expect(text).toContain(MARKER);
  });

  it("keeps image data intact, as the binary rule requires", () => {
    const out = redactAllText(payload()) as { messages: Array<{ content: Array<Record<string, unknown>> }> };
    expect(out.messages[3]!.content[0]!.data).toBe("QUJD");
  });

  it("never leaves a JSON-string field unparseable", () => {
    const out = redactAllText({ messages: [{ role: "assistant", arguments: `{"command":"echo ${GH}"}` }] });
    const args = (out as { messages: Array<{ arguments: string }> }).messages[0]!.arguments;
    expect(() => JSON.parse(args)).not.toThrow();
    expect(args).not.toContain(GH);
  });
});

// --- F4 ---------------------------------------------------------------------------
// The marker means "a value was masked here". There is never a value BEHIND it, so
// blocking a command that merely contains it protects nothing and refuses ordinary
// work — including patching this project's own docs and tests, which are full of it.
// Measured: two of my own tool calls were refused outright on 2026-10-10.
describe("the reserved marker is text, not a denied value", () => {
  it("runs a quoted heredoc carrying the marker instead of refusing the command", () => {
    const out = injectBashCommand(`cat <<'EOF'\n${MARKER}\nEOF`, vault());
    expect(out.block).toBeUndefined();
    expect(out.command).toContain(MARKER);
  });

  it("does not report the marker as an unusable ref", () => {
    const issues = bashRefIssues(`grep -n '${MARKER}' README.md`, vault());
    expect(issues).toEqual([]);
  });

  it("still refuses a REAL vaulted value in a context that cannot expand it", () => {
    // The mandate: a value that would silently not be delivered must stop the command,
    // because the model would read the placeholder back as a working credential.
    const out = injectBashCommand("cat <<'EOF'\n{{sec:gh_pat}}\nEOF", vault());
    expect(out.block?.reason).toMatch(/will not expand it/);
  });

  it("still reports an unknown name in a quoted heredoc as prose, not an error", () => {
    const out = injectBashCommand("cat <<'EOF'\n{{sec:not_in_the_vault}}\nEOF", vault());
    expect(out.block).toBeUndefined();
  });
});

// --- F5/F6 -------------------------------------------------------------------------
// Two more ways pi-secret stopped the world, both found by measuring rather than reading.
//
// F5: the KV patterns began with an unbounded `[A-Za-z0-9_-]*`, which is O(n²) in the
// length of one word-character run — at every start position the engine ate the whole run
// and backtracked character by character looking for a keyword that was not there.
// Measured: `maskShapes` on 1MB of `a` did not finish in 6s, and the capture pass on the
// same input did not finish in 240s. Reachable from any tool result or paste containing one
// long unbroken word — a minified bundle on a single line, a hex dump, a token blob.
//
// F6: the entropy fallback called `text.indexOf(raw)` per token, restarting from position 0
// every time, so the cost was O(tokens × length). Measured: a 414KB pasted prompt took 2.6
// SECONDS to examine, on every submission, through the `input` hook.
describe("long inputs cannot freeze the turn", () => {
  it("examines a 1MB single-character run without hanging", () => {
    const started = performance.now();
    // A single long word-character run: this is the exact shape that hung.
    expect(maskShapes("a".repeat(1_000_000)).text.length).toBe(1_000_000);
    expect(performance.now() - started).toBeLessThan(5000);
  }, 20_000);

  it("captures candidates from the same shape without hanging", async () => {
    const { findCandidates } = await import("../src/capture.ts");
    const started = performance.now();
    findCandidates("a".repeat(1_000_000));
    // >240s before the bounds; ~24ms after.
    expect(performance.now() - started).toBeLessThan(5000);
  }, 20_000);

  it("examines a large multi-line paste in linear-ish time", async () => {
    const { findCandidates } = await import("../src/capture.ts");
    const paste = (n: number) =>
      Array.from({ length: n }, (_, i) => `line ${i}: key=value path=/tmp/x/${i} url=https://e.com/${i}`).join("\n");
    findCandidates(paste(1500)); // warm
    const t1 = performance.now();
    findCandidates(paste(1500));
    const small = performance.now() - t1;
    const t2 = performance.now();
    findCandidates(paste(12_000));
    const large = performance.now() - t2;
    // 8x the input. Linear gives ~8x, quadratic ~64x. Before F6 this was ~1800ms for 6000
    // lines; the bound is deliberately loose and only there to catch a return to quadratic.
    expect(large).toBeLessThan(Math.max(small, 30) * 24);
    expect(large).toBeLessThan(4000);
  }, 30_000);

  it("still detects the secrets it always did inside those shapes", async () => {
    const { findCandidates } = await import("../src/capture.ts");
    // Non-vacuity: the run bounds must not have made the patterns miss a real find, and a
    // compound key name longer than the bound must still be recognised as a key at all.
    const found = findCandidates("a".repeat(500_000) + "\nDB_PASSWORD=Tr0ub4dor&3x\n");
    expect(found.map((c) => c.value)).toContain("Tr0ub4dor&3x");
  }, 20_000);
});
