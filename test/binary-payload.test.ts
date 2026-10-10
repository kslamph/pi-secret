import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { redactAllText, scrubDeep } from "../src/scrub.ts";
import { scrubToolResult } from "../src/glue.ts";
import { Vault } from "../src/vault.ts";

const GH = "{{" + "sec:redacted" + "}}";
const REF = "{{" + "sec:gh_pat" + "}}";
const PREFIX = "{{" + "sec:redacted" + "}}";

function vault() {
  const v = new Vault("t");
  v.add("gh_pat", GH, "prompt");
  return v;
}

/**
 * A base64 run that contains the AWS access-key shape by accident, not by design —
 * spliced in by hand, because base64-ENCODING that text would not contain it.
 */
function base64WithAWSPrefixShape(): string {
  const filler = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5";
  const head = filler.repeat(60).slice(0, 4000);
  const data = head + "AkIA8BxxiyzGikq3xhqm" + filler.repeat(4);
  expect(data.length % 4).toBe(0);
  return data;
}

describe("binary payloads must survive scrubbing byte-identical", () => {
  // Regression, measured 2026-10-10: reading a PNG produced
  //   "pi-secret masked 4 secret occurrence(s) in read output"
  // and the next provider request failed with 400 invalid_request. pi's read tool
  // returns {type:"image", data:<base64>, mimeType}; maskShapes' AWS prefix rule
  // matched a case-insensitive `AkIA…` run INSIDE the base64 and rewrote it. The
  // string no longer decoded (272079 bytes vs 272106) and the provider rejected the
  // image. Masking cannot redact pixels, so the only correct behaviour is to leave
  // the payload alone.
  it("leaves an image block's base64 untouched while masking its prose note", () => {
    const data = base64WithAWSPrefixShape();
    const out = scrubDeep(
      [{ type: "image", data, mimeType: "image/png", note: `Read image file password=${GH}` }],
      vault(),
      { shapes: true },
    );
    const block = (out.value as Array<Record<string, unknown>>)[0]!;
    expect(block.data).toBe(data);
    expect(block.note).toBe(`Read image file password=${REF}`);
  });

  it("leaves an audio block alone too", () => {
    const data = base64WithAWSPrefixShape();
    const out = scrubDeep({ type: "audio", data, mimeType: "audio/wav" }, vault(), { shapes: true });
    expect((out.value as Record<string, unknown>).data).toBe(data);
  });

  it("leaves any non-text mimeType payload alone, whatever the block is called", () => {
    const data = base64WithAWSPrefixShape();
    const out = scrubDeep({ data, mimeType: "application/pdf" }, vault(), { shapes: true });
    expect((out.value as Record<string, unknown>).data).toBe(data);
  });

  it("still scrubs a text/plain payload — the mimeType is what decides, not the key", () => {
    const out = scrubDeep({ data: `password=${GH}`, mimeType: "text/plain" }, vault(), { shapes: true });
    expect((out.value as Record<string, unknown>).data).toBe(`password=${REF}`);
  });

  // The structural rule above keys off a sibling mimeType. This is the backstop for
  // producers we do not model: a long unbroken base64 run is a data payload, never
  // prose, and rewriting it corrupts whatever it encodes.
  it("leaves a long unbroken base64 string alone even with no mimeType in sight", () => {
    const data = base64WithAWSPrefixShape();
    const out = scrubDeep({ payload: data }, vault(), { shapes: true });
    expect((out.value as Record<string, unknown>).payload).toBe(data);
  });

  it("still scrubs ordinary prose and short base64-ish tokens", () => {
    // 64 chars is not a payload — a key hash, a git SHA, a truncated token. The
    // backstop must not become a way to smuggle a secret past the shape pass.
    const short = "AKIAIOSFODNN7EXAMPLE";
    const out = scrubDeep({ note: `key ${short}` }, vault(), { shapes: true });
    expect((out.value as Record<string, unknown>).note).toBe(`key ${PREFIX}`);
  });

  it("scrubToolResult passes an image block through unchanged", () => {
    const data = base64WithAWSPrefixShape();
    const out = scrubToolResult(
      { toolName: "read", content: [{ type: "image", data, mimeType: "image/png", note: "hi" }], details: {} },
      vault(),
      { fileReads: true },
    );
    expect((out.content as Array<Record<string, unknown>>)[0]!.data).toBe(data);
  });

  // Fail-closed must not become corrupt-closed: redacting every string is correct for
  // prose and catastrophic for an image, and the fail-closed path is the one that
  // runs when the vault itself has thrown.
  it("redactAllText also leaves a binary payload intact", () => {
    const data = base64WithAWSPrefixShape();
    const out = redactAllText([{ type: "image", data, note: "x" }]);
    const block = (out as Array<Record<string, unknown>>)[0]!;
    expect(block.data).toBe(data);
    expect(block.note).toBe(PREFIX);
  });

  it("a real PNG from the reported incident round-trips byte-identical", () => {
    const png = readFileSync(
      "/home/kslam/.cache/browser-use/01a1255f-7954-744b-a1fe-5ff30c88c9b0/shots/cp-desktop-top.png",
    );
    const data = png.toString("base64");
    const out = scrubToolResult(
      { toolName: "read", content: [{ type: "image", data, mimeType: "image/png", note: "x" }], details: {} },
      vault(),
      { fileReads: true },
    );
    const after = (out.content as Array<Record<string, unknown>>)[0]!.data as string;
    expect(after).toBe(data);
    expect(Buffer.from(after, "base64").equals(png)).toBe(true);
  });
});