import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import { expandBash, type BashExpansion } from "../src/substitute.ts";
import { bashCases, DB, DB_ENV, GH, GH_ENV, SPACED, SPACED_ENV } from "./bash-quote-table.ts";

/** A value every shell metacharacter; delivered verbatim, it must never touch argv or shell syntax. */
const HOSTILE = "tok_en;$(reboot)' | rm -rf *";

const resolve = (name: string): string | undefined =>
  name === "gh_pat" ? "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
  : name === "db_url" ? "postgres://admin:s3cr3t@db.internal:5432/app"
  : name === "spaced" ? "a b 'c' $(echo pwned)"
  : name === "hostile" ? HOSTILE
  : undefined;

/** Which ref name each table env var was derived from, for the `used` assertion. */
const NAME_OF_ENV: Record<string, string> = {
  [GH_ENV]: "gh_pat",
  [DB_ENV]: "db_url",
  [SPACED_ENV]: "spaced",
};

describe("expandBash — shape", () => {
  for (const c of bashCases) {
    it(c.it, () => {
      const out = expandBash(c.input, resolve);
      expect(out.command).toBe(c.command);
      expect(out.env).toEqual(c.env);
      expect(out.missing).toEqual(c.missing ?? []);
      // `used` names exactly the refs that got bound into `env`.
      expect([...out.used].sort()).toEqual(
        Object.keys(c.env).map((v) => NAME_OF_ENV[v] as string).sort(),
      );
    });
  }
});

describe("expandBash — never emits the value", () => {
  // Every resolved value the suite knows about, checked against every expansion:
  // the three env-less cases (unknown ref, uppercase ref, no ref) otherwise
  // generate no-op loops.
  const ALL_VALUES = [GH, DB, SPACED, HOSTILE];
  for (const c of bashCases) {
    it(`${c.it}: no resolved value in the command text`, () => {
      const out = expandBash(c.input, resolve);
      for (const value of ALL_VALUES) expect(out.command).not.toContain(value);
    });
  }
});

const run = promisify(execFile);

/**
 * Every runtime case goes through here so the env reaches the child exactly the
 * way the wrapped bash tool will deliver it: as spawned env, never as argv.
 */
async function bashRun(expansion: BashExpansion): Promise<string> {
  // The argv claim, carried by every runtime case: whatever bash is handed must
  // reference the secret by name only.
  for (const value of Object.values(expansion.env)) {
    expect(expansion.command).not.toContain(value);
  }
  const { stdout } = await run("/bin/bash", ["-c", expansion.command], {
    env: { ...process.env, ...expansion.env },
  });
  return stdout;
}

describe("expandBash — bash agrees", () => {
  it("single-quoted ref yields the value as one argument", async () => {
    const out = expandBash(`printf '<%s>' 'Authorization: Bearer {{sec:gh_pat}}'`, resolve);
    expect(await bashRun(out)).toBe("<Authorization: Bearer " + GH + ">");
  });

  it("a value with spaces and metacharacters stays one argument", async () => {
    const out = expandBash(`printf '<%s>' '{{sec:spaced}}'`, resolve);
    expect(await bashRun(out)).toBe("<a b 'c' $(echo pwned)>");
  });

  it("an unquoted ref does not execute the value's command substitution", async () => {
    const out = expandBash("printf '<%s>' {{sec:spaced}}", resolve);
    expect(await bashRun(out)).toBe("<a b 'c' $(echo pwned)>");
  });

  it("heredoc with an unquoted delimiter expands the ref", async () => {
    const out = expandBash("cat <<EOF\ntoken={{sec:gh_pat}}\nEOF", resolve);
    expect((await bashRun(out)).trim()).toBe("token=" + GH);
  });

  it("heredoc with a quoted delimiter is left literal and reported missing", async () => {
    const out = expandBash("cat <<'EOF'\ntoken={{sec:gh_pat}}\nEOF", resolve);
    expect((await bashRun(out)).trim()).toBe("token={{sec:gh_pat}}");
    expect(out.missing).toEqual(["gh_pat"]);
    expect(out.env).toEqual({});
  });

  it("the value never appears in the command bash is handed", () => {
    for (const c of bashCases) {
      const out = expandBash(c.input, resolve);
      for (const value of Object.values(out.env)) expect(out.command).not.toContain(value);
    }
  });

  it("$'…' delivers the value at runtime — the splice escapes the ANSI-C quotes", async () => {
    const out = expandBash("printf '<%s>' $'{{sec:gh_pat}}'", resolve);
    expect(await bashRun(out)).toBe("<" + GH + ">");
  });

  it('$"…' + '" expands like double quotes at runtime', async () => {
    const out = expandBash('printf \'<%s>\' $"{{sec:gh_pat}}"', resolve);
    expect(await bashRun(out)).toBe("<" + GH + ">");
  });

  it("a hostile value reaches the child verbatim, never through argv or the shell", async () => {
    const out = expandBash(`printf '<%s>' '{{sec:hostile}}'`, resolve);
    expect(out.missing).toEqual([]);
    // bashRun asserts the command text carries no value; this asserts the child
    // sees the hostile value as exactly one argument, unexecuted and unexpanded.
    expect(await bashRun(out)).toBe(`<${HOSTILE}>`);
  });
});

describe("expandBash — lexical contexts the first draft got wrong", () => {
  it("ignores comment prose when pairing quotes", () => {
    const out = expandBash("# don't\necho {{sec:gh_pat}} > /tmp/o  # it's", resolve);
    expect(out.command).toContain(`"$${GH_ENV}"`); // quoted, not spliced out of a phantom span
    expect(out.missing).toEqual([]);
    // Strengthener: pins the ref as plain argv quoting. The phantom-span bug also
    // contains this substring (inside a splice), so assert the full line.
    expect(out.command).toBe(`# don't\necho "$${GH_ENV}" > /tmp/o  # it's`);
  });

  it("does not let a comment double-quote unquote the value", () => {
    const out = expandBash('# note "a\necho {{sec:gh_pat}}\n# " done', resolve);
    expect(out.command).toContain(`"$${GH_ENV}"`);
    expect(out.command).not.toMatch(/echo \$\{?__PISEC/);
  });

  it("treats $'…' as its own span and still delivers the value", () => {
    const out = expandBash("echo $'{{sec:gh_pat}}'", resolve);
    expect(out.missing).toEqual([]);
    expect(out.command).toContain(GH_ENV);
    // ANSI-C quotes do not expand parameters, so the value can only be delivered
    // by the close-and-reopen splice — the same treatment as a single-quoted ref.
    expect(out.command).toBe(`echo $''"$${GH_ENV}"''`);
  });

  it("reports refs inside an unterminated quote instead of guessing", () => {
    const out = expandBash("echo 'x\nrun {{sec:gh_pat}}", resolve);
    expect(out.missing).toEqual(["gh_pat"]);
  });

  it("keeps a#b a word, not a comment", () => {
    const out = expandBash("echo a#b{{sec:gh_pat}}", resolve);
    expect(out.command).toContain("a#b");
    expect(out.missing).toEqual([]);
    // Strengthener: a naive any-#-starts-a-comment lexer also passes the two
    // assertions above (the ref is simply never seen). Pin the expansion.
    expect(out.command).toBe(`echo a#b"$${GH_ENV}"`);
  });
});
