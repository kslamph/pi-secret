import { describe, expect, it } from "vitest";
import { envVarName, expandBash, heredocRegions } from "../src/substitute.ts";

const resolve = (name: string): string | undefined => (name === "x" ? "SECRETVALUE" : undefined);
const X = envVarName("x");

describe("heredoc edge semantics (beyond the task-4 fixture contract; each case is bash-defined, see report)", () => {
  it("two heredocs on one command line get sequential bodies", () => {
    const text = "cat <<A <<'B'\nX {{sec:x}}\nA\nY {{sec:x}}\nB\n";
    const rs = heredocRegions(text);
    expect(rs.length).toBe(2);
    expect(rs[0]!.inert).toBe(false);
    expect(rs[1]!.inert).toBe(true);
    expect(text.slice(rs[0]!.start, rs[0]!.end)).toBe("X {{sec:x}}\n");
    expect(text.slice(rs[1]!.start, rs[1]!.end)).toBe("Y {{sec:x}}\n");
    const out = expandBash(text, resolve);
    expect(out.command).toBe(`cat <<A <<'B'\nX \${${X}}\nA\nY {{sec:x}}\nB\n`);
    // One occurrence expands; the one inside the inert heredoc is reported.
    expect(out.missing).toEqual(["x"]);
  });

  it("<< inside double quotes is not an operator", () => {
    const text = 'echo "<<EOF" {{sec:x}}';
    expect(heredocRegions(text)).toEqual([]);
    expect(expandBash(text, resolve).command).toBe(`echo "<<EOF" "${'$'}${X}"`);
  });

  it("a here-string tail is not a heredoc operator", () => {
    const text = "cat <<<word\n{{sec:x}}\n";
    expect(heredocRegions(text)).toEqual([]);
  });

  it("<<- strips tabs from the terminator", () => {
    const text = "cat <<-EOF\ntoken={{sec:x}}\n\tEOF\n";
    const rs = heredocRegions(text);
    expect(rs.length).toBe(1);
    // Body-slice assertion: if tab-stripping were deleted, the terminator would
    // never match, the unterminated fallback would swallow the `\tEOF` line, and
    // every assertion below would still pass. Only the body slice distinguishes.
    expect(text.slice(rs[0]!.start, rs[0]!.end)).toBe("token={{sec:x}}\n");
    const out = expandBash(text, resolve);
    expect(out.command).toBe(`cat <<-EOF\ntoken=\${${X}}\n\tEOF\n`);
  });

  it("unterminated heredoc treats the remainder as the body", () => {
    const text = "cat <<EOF\ntoken={{sec:x}}\n";
    const out = expandBash(text, resolve);
    expect(out.command).toBe(`cat <<EOF\ntoken=\${${X}}\n`);
  });
});
