import { describe, expect, it } from "vitest";
import {
  envVarName,
  expandRefs,
  findRefs,
  quoteForPosix,
  type Ref,
} from "../src/substitute.ts";
import { refToken } from "../src/refs.ts";

const GH = "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8";
const DB = "postgres://admin:s3cr3t@db.internal:5432/app";
const resolve = (name: string): string | undefined =>
  name === "gh_pat" ? GH : name === "db_url" ? DB : undefined;

describe("findRefs", () => {
  it("finds every ref with offsets, in order", () => {
    const text = `curl ${refToken("gh_pat")} and ${refToken("db_url")}`;
    const expected: Array<Pick<Ref, "raw" | "name">> = [
      { raw: "{{sec:gh_pat}}", name: "gh_pat" },
      { raw: "{{sec:db_url}}", name: "db_url" },
    ];
    expect(findRefs(text).map((r) => ({ raw: r.raw, name: r.name }))).toEqual(expected);
  });

  it("ignores malformed or uppercase names", () => {
    expect(findRefs("{{sec:GH_PAT}} {{sec:}} {{ sec:x }} {{sec:ok-name}}")).toHaveLength(1);
  });

  it("finds the inner well-formed ref inside a malformed outer token", () => {
    // REF_RE rescans past the malformed prefix, so the inner token matches.
    // findRefs must report it: expandRefs (same regex) will replace it, and
    // the two must agree on what a ref is.
    expect(findRefs("{{sec:{{sec:gh}}}}")).toEqual([
      { raw: "{{sec:gh}}", name: "gh", start: 6, end: 16 },
    ]);
  });

  it("returns nothing for plain text", () => {
    expect(findRefs("no refs here")).toEqual([]);
  });
});

describe("expandRefs", () => {
  it("replaces each ref and records what it used", () => {
    const out = expandRefs(`-H "Authorization: Bearer ${refToken("gh_pat")}"`, resolve);
    expect(out.text).toBe(`-H "Authorization: Bearer ${GH}"`);
    expect(out.used).toEqual(["gh_pat"]);
    expect(out.missing).toEqual([]);
  });

  it("leaves missing refs in place and reports them", () => {
    const out = expandRefs(`${refToken("gh_pat")} ${refToken("nope")}`, resolve);
    expect(out.text).toBe(`${GH} ${refToken("nope")}`);
    expect(out.used).toEqual(["gh_pat"]);
    expect(out.missing).toEqual(["nope"]);
  });

  it("is idempotent on already-expanded text", () => {
    const once = expandRefs(refToken("gh_pat"), resolve).text;
    expect(expandRefs(once, resolve).text).toBe(once);
  });
});

describe("envVarName", () => {
  it("maps a secret name to a distinct shell identifier", () => {
    expect(envVarName("gh_pat")).toMatch(/^__PISEC_GH_PAT_[0-9a-f]{16}$/);
    expect(envVarName("db_url-v2")).toMatch(/^__PISEC_DB_URL_V2_[0-9a-f]{16}$/);
  });

  it("is deterministic", () => {
    expect(envVarName("gh_pat")).toBe(envVarName("gh_pat"));
  });

  it("is always a valid POSIX env var name", () => {
    for (const name of ["gh", "a", "z".repeat(64), "with-dash", "with.dot"]) {
      expect(envVarName(name)).toMatch(/^[A-Za-z_][A-Za-z0-9_]*$/);
    }
  });

  it("differs for names that sanitize alike and for long shared prefixes", () => {
    expect(envVarName("a-b")).not.toBe(envVarName("a_b"));
    // No truncation plus a 64-bit tag: names differing anywhere in their first 64
    // chars already differ here, and the 32-bit-tag birthday walk is closed.
    const long = "x".repeat(45);
    expect(envVarName(long + "_a")).not.toBe(envVarName(long + "_b"));
  });

  it("stays a valid identifier and within bounds for a maximum-length name", () => {
    const name = "a".repeat(64);
    expect(envVarName(name)).toMatch(/^[A-Za-z_][A-Za-z0-9_]*$/);
    expect(envVarName(name).length).toBeLessThanOrEqual(89);
  });
});

describe("quoteForPosix", () => {
  it("wraps ordinary values in single quotes", () => {
    expect(quoteForPosix(GH)).toBe(`'${GH}'`);
  });

  it("escapes embedded single quotes", () => {
    // Canonical ANSI quoting: each ' becomes '\'' (close, escaped, reopen).
    // Both outputs round-trip through /bin/sh; the raw literals without the
    // doubled quote are unterminated shell strings.
    expect(quoteForPosix("it's")).toBe(`'it'\\''s'`);
    expect(quoteForPosix("'")).toBe(`''\\'''`);
  });

  it("round-trips through the shell", async () => {
    const { execFile } = await import("node:child_process");
    const { promisify } = await import("node:util");
    const run = promisify(execFile);
    for (const value of ["plain", "with space", "it's", '$(echo pwned)', "new\nline", "a;b c|d"]) {
      const { stdout } = await run("/bin/sh", ["-c", `printf %s ${quoteForPosix(value)}`]);
      expect(stdout).toBe(value);
    }
  });
});
