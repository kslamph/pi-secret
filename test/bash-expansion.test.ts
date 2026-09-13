import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import { expandBash, type BashExpansion } from "../src/substitute.ts";
import { bashCases, DB, DB_ENV, GH, GH_ENV, SPACED, SPACED_ENV } from "./bash-quote-table.ts";

/** A benign witness: if the value is ever executed as shell, this file appears. */
const HOSTILE = "$(touch /tmp/pi-secure-pwned)";

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
    const marker = "/tmp/pi-secure-pwned";
    // Ensure the marker does not pre-exist.
    const { unlinkSync } = await import("node:fs");
    try { unlinkSync(marker); } catch { /* ENOENT is expected */ }
    const out = expandBash(`printf '<%s>' '{{sec:hostile}}'`, resolve);
    expect(out.missing).toEqual([]);
    // bashRun asserts the command text carries no value; this asserts the child
    // sees the hostile value as exactly one argument, unexecuted and unexpanded.
    expect(await bashRun(out)).toBe(`<${HOSTILE}>`);
    // The marker must never have been created: the value was delivered as a
    // string argument, not executed as shell.
    let markerExists = true;
    try { unlinkSync(marker); } catch { markerExists = false; }
    expect(markerExists).toBe(false);
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
  });

  it("starts a comment after ; | and & even with no space", () => {
    const out = expandBash("echo hi;#don't\necho {{sec:gh_pat}} is here;#it's", resolve);
    expect(out.command).toContain(`"$${GH_ENV}"`); // quoted expansion, not a phantom-span splice
    expect(out.command).not.toContain(`'"$`);
    expect(out.missing).toEqual([]);
  });

  it("recognizes ( and ) as word starts for #", () => {
    const out = expandBash("(cd .)#don't\necho {{sec:gh_pat}}\n(ls)#it's", resolve);
    expect(out.missing).toEqual([]);
    expect(out.command).toContain(`echo "$${GH_ENV}"`); // normal code-context expansion
    expect(out.command).not.toContain(`'"$`); // never a phantom-span splice
  });

  it("keeps an escaped semicolon word text, not a comment start", () => {
    // The brief's original input had `\;#"b 'c ...` — but `"` after `#` opens an
    // unterminated double-quote (bash: `unexpected EOF while looking for matching
    // "`).  Remove the `"` so the `'` characters are the actual sq pair the
    // splice assertion targets.  The \; still makes `;` literal, `#` is mid-word
    // (not a comment), and `'c ... d'` is a genuine single-quoted span.
    const out = expandBash(`echo a\\;#b'c {{sec:gh_pat}} d'`, resolve);
    expect(out.missing).toEqual([]);
    expect(out.command).toContain(`'"$${GH_ENV}"'`); // genuine single-quoted ref, spliced
  });

  it("does not let heredoc prose fabricate or extend a quote span", () => {
    // Odd count: lone apostrophe in heredoc body must not trigger fail-closed
    // for a ref in code context after the heredoc.
    const odd = expandBash("cat <<EOF\ndon't\nEOF\necho {{sec:gh_pat}}", resolve);
    expect(odd.missing).toEqual([]);
    expect(odd.used).toEqual(["gh_pat"]);
    expect(odd.command).toBe(`cat <<EOF\ndon't\nEOF\necho "$${GH_ENV}"`);
    // Even count: body apostrophes must not pair with a later code-context
    // quote to form a phantom span that swallows the ref.
    const even = expandBash("cat <<EOF\ndon't\nEOF\necho {{sec:gh_pat}} && echo 'x'", resolve);
    expect(even.missing).toEqual([]);
    expect(even.command).not.toContain(`'"$`); // no phantom sq splice
    expect(even.command).toBe(`cat <<EOF\ndon't\nEOF\necho "$${GH_ENV}" && echo 'x'`);
  });

  it("heredoc body apostrophe does not cause fail-closed for code after it", () => {
    // Requirement 4: fail-closed fires only for genuine code-context quote
    // uncertainty. A lone apostrophe in a heredoc body is not a quote in code
    // context, so a ref after the heredoc must still expand.
    const out = expandBash("cat <<EOF\ndon't\nEOF\necho {{sec:gh_pat}}", resolve);
    expect(out.missing).toEqual([]);
    expect(out.command).toContain(`"$${GH_ENV}"`);
  });

  it("does not let a body that opens with a quote corrupt the scan", () => {
    // Regression for requirement 6: the heredoc jump used to fall through and process
    // the body's first character with a stale index.
    const out = expandBash("cat <<EOF\n'don't\nEOF\necho {{sec:gh_pat}}", resolve);
    expect(out.missing).toEqual([]);
    expect(out.command).toContain(`echo "$${GH_ENV}"`);
  });

  it("clears wordStart across an escape pair at a genuine word start", () => {
    // Requirement 7. `)` sets the flag, the escape must clear it; bash reads one word
    // here (`echo y=a;#bc q d`), so `#` is text and the sq span must be recorded.
    const src = "echo $(printf a)\\;#b'c {{sec:gh_pat}} d'";
    const out = expandBash(src, resolve);
    expect(out.missing).toEqual([]);
    expect(out.command).toContain(`'"$${GH_ENV}"'`); // spliced, not bare
    expect(out.command).not.toMatch(/'c? ?"\$[^""]*" ?d'/); // never bare inside sq
  });

  it("excludes every body when a prose apostrophe could hide a later operator", () => {
    // Odd body apostrophes in an EARLIER body fabricated a span that swallowed the
    // second `<<EOF`, so that body was never excluded — see requirement 5.
    const two = expandBash(
      "cat <<'MSG'\nDon't do this\nMSG\ncat <<EOF\nIt's fine\nEOF\necho {{sec:gh_pat}}",
      resolve,
    );
    expect(two.missing).toEqual([]);
    expect(two.command).toContain(`echo "$${GH_ENV}"`);
    const even = expandBash(
      "cat <<'MSG'\nDon't do this\nMSG\ncat <<EOF\nIt's fine\nEOF\necho {{sec:gh_pat}} && echo 'x'",
      resolve,
    );
    expect(even.missing).toEqual([]);
    expect(even.command).not.toContain(`'"$`);
  });

  it("still blocks a heredoc operator that a real quote swallows", () => {
    const out = expandBash("echo '<<EOF'\ndon't\nEOF\necho {{sec:gh_pat}}", resolve);
    expect(out.missing).toEqual(["gh_pat"]);
  });
});
