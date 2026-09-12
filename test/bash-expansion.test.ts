import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import { expandBash, type BashExpansion } from "../src/substitute.ts";
import { bashCases, DB_ENV, GH, GH_ENV, SPACED_ENV } from "./bash-quote-table.ts";

const resolve = (name: string): string | undefined =>
  name === "gh_pat" ? "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
  : name === "db_url" ? "postgres://admin:s3cr3t@db.internal:5432/app"
  : name === "spaced" ? "a b 'c' $(echo pwned)"
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
  for (const c of bashCases) {
    it(`${c.it}: value absent from command text`, () => {
      const out = expandBash(c.input, resolve);
      for (const value of Object.values(c.env)) expect(out.command).not.toContain(value);
    });
  }
});

const run = promisify(execFile);

/**
 * Every runtime case goes through here so the env reaches the child exactly the
 * way the wrapped bash tool will deliver it: as spawned env, never as argv.
 */
async function bashRun(expansion: BashExpansion): Promise<string> {
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
});
