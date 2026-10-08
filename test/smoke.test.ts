import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import piSecure, { VERSION } from "../src/index.ts";

/**
 * A stub ExtensionAPI that records what the factory asks pi to do. Its purpose is
 * to make the factory's *registration surface* an assertion: a refactor that drops
 * a hook, the flag, a tool or the receipt renderer used to pass this file, because
 * `typeof piSecure === "function"` says nothing about what the factory does when
 * called. Nothing here is applied to a real session — pi-secure's effect on
 * credentials is covered by the canary gate, not by this unit.
 */
function stubPi() {
  const calls: { method: string; arg: unknown }[] = [];
  const record =
    (method: string) =>
    (...args: unknown[]) => {
      calls.push({ method, arg: args[0] });
    };
  const api = {
    registerFlag: vi.fn(record("registerFlag")),
    registerTool: vi.fn(record("registerTool")),
    registerCommand: vi.fn(record("registerCommand")),
    registerEntryRenderer: vi.fn(record("registerEntryRenderer")),
    on: vi.fn(record("on")),
  } as never;
  return { api, calls };
}

const hookNames = (calls: { method: string; arg: unknown }[]): string[] =>
  calls.filter((c) => c.method === "on").map((c) => c.arg as string);

describe("extension entry", () => {
  it("exports a zero-arg-style factory taking ExtensionAPI", () => {
    expect(typeof piSecure).toBe("function");
    expect(piSecure.length).toBe(1);
  });

  it("reports its version", () => {
    expect(VERSION).toMatch(/^\d+\.\d+\.\d+/);
  });

  it("does not drift from package.json", () => {
    // VERSION was hand-copied out of package.json, so the two could disagree for
    // ever. /sec has no version subcommand, which makes the copy invisible in
    // normal use — it only shows up in a bug report.
    const pkg = JSON.parse(
      readFileSync(fileURLToPath(new URL("../package.json", import.meta.url)), "utf8"),
    ) as { version: string };
    expect(VERSION).toBe(pkg.version);
  });

  it("registers every hook the design depends on, at factory time", () => {
    // session_compact is in this list because a compaction summary is the only
    // model-authored text pi persists WITHOUT passing it through message_end — see
    // src/index.ts. A refactor that dropped it would put summaries back on disk raw.
    const { api, calls } = stubPi();
    piSecure(api);
    expect(hookNames(calls).sort()).toEqual(
      [
        "before_provider_request",
        "context",
        "input",
        "message_end",
        "session_shutdown",
        "session_compact",
        "session_start",
        "tool_call",
        "tool_result",
      ].sort(),
    );
    expect(calls.map((c) => c.method)).toContain("registerFlag");
    expect(calls.map((c) => c.method)).toContain("registerEntryRenderer");
    // /sec is ONE command with eight verbs; more than one command here would mean
    // the dispatcher moved out of src/commands.ts.
    expect(calls.filter((c) => c.method === "registerCommand")).toHaveLength(1);
  });

  it("does not register the wrapped bash tool until a session starts", () => {
    // The wrapper needs ctx.cwd, so it is registered in session_start rather than
    // at factory time. Asserting that keeps it from being hoisted into the
    // factory, where `cwd` does not exist yet.
    const { api, calls } = stubPi();
    piSecure(api);
    expect(calls.filter((c) => c.method === "registerTool")).toHaveLength(0);
  });
});