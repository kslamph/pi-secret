import { mkdtempSync, writeFileSync, mkdirSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  chooseName,
  inspectPath,
  listCandidates,
  MAX_ENV_BYTES,
  parseDotenv,
  resolvePathInput,
  splitPathInput,
} from "../src/env-file.ts";

describe("parseDotenv", () => {
  const one = (text: string) => parseDotenv(text).assignments;

  it("reads a plain assignment", () => {
    expect(one("KEY=value")).toEqual([{ key: "KEY", value: "value", line: 1, flags: [] }]);
  });

  it("strips `export` and leading indentation", () => {
    expect(one("export KEY=value").map((a) => a.key)).toEqual(["KEY"]);
    expect(one("  KEY=value").map((a) => a.value)).toEqual(["value"]);
  });

  it("ignores blank lines and comments without counting them as skipped", () => {
    const parsed = parseDotenv("# a comment\n\nKEY=value\n   \n#another\n");
    expect(parsed.assignments).toHaveLength(1);
    expect(parsed.skipped).toBe(0);
  });

  it("strips an inline comment only when whitespace precedes the #", () => {
    expect(one("KEY=value # note")[0]!.value).toBe("value");
    // No space before `#` means it is part of the value — a password can contain one.
    expect(one("KEY=abc#def")[0]!.value).toBe("abc#def");
  });

  it("strips matching quotes and keeps the inner bytes", () => {
    expect(one('KEY="a b"')[0]!.value).toBe("a b");
    expect(one("KEY='a b'")[0]!.value).toBe("a b");
    // Only the OUTER matching quote pair is stripped; the other kind is content.
    expect(one(`KEY='a "b" c'`)[0]!.value).toBe(`a "b" c`);
    expect(one(`KEY="a 'b' c"`)[0]!.value).toBe(`a 'b' c`);
  });

  it("keeps escapes literal and flags them instead of interpreting them", () => {
    const [a] = one('KEY="a\\nb"');
    expect(a!.value).toBe("a\\nb"); // backslash + n, four characters
    expect(a!.flags).toContain("escapes");
  });

  it("flags unexpanded variable references instead of interpolating", () => {
    expect(one("KEY=${OTHER}")[0]!.flags).toContain("unexpanded");
    expect(one("KEY=$OTHER")[0]!.flags).toContain("unexpanded");
    expect(one("KEY=$OTHER")[0]!.value).toBe("$OTHER");
  });

  it("lets the last of a duplicated key win, and counts the collapse", () => {
    const parsed = parseDotenv("A=1\nB=2\nA=3\n");
    expect(parsed.assignments.map((a) => [a.key, a.value])).toEqual([
      ["A", "3"],
      ["B", "2"],
    ]);
    expect(parsed.duplicates).toBe(1);
  });

  it("skips empty values, unterminated quotes and non-assignments", () => {
    const parsed = parseDotenv('EMPTY=\nQUOTED="   "\nBAD="unterminated\nYAML: value\n');
    expect(parsed.assignments).toEqual([]);
    expect(parsed.skipped).toBe(4);
  });

  it("handles CRLF and a leading BOM", () => {
    const parsed = parseDotenv("\uFEFFA=1\r\nB=2\r\n");
    expect(parsed.assignments.map((a) => a.value)).toEqual(["1", "2"]);
  });

  it("keeps a value containing = intact", () => {
    expect(one("KEY=a=b")[0]!.value).toBe("a=b");
  });

  it("reports line numbers for the rows it found", () => {
    expect(one("\n\nKEY=value")[0]!.line).toBe(3);
  });
});

describe("chooseName", () => {
  it("lowercases", () => {
    expect(chooseName("MY_API_KEY", new Set()).name).toBe("my_api_key");
  });

  it("appends 1, 2, 3 against names already in the vault", () => {
    const taken = new Set(["my_api_key", "my_api_key1"]);
    expect(chooseName("MY_API_KEY", taken).name).toBe("my_api_key2");
  });

  it("appends against names assigned earlier in the same run (F5)", () => {
    // The rule is "try the base, then 1, 2, 3" — so the second line gets 1, not 2.
    const taken = new Set<string>();
    const first = chooseName("MY_KEY", taken).name!;
    taken.add(first);
    const second = chooseName("my_key", taken).name!;
    expect([first, second]).toEqual(["my_key", "my_key1"]);
  });

  it("refuses a name it cannot repair rather than inventing one", () => {
    // Option (a): the row is disabled with a reason, never silently renamed.
    for (const raw of ["2FA_TOKEN", "MY.KEY", "MY KEY", "-LEADING"]) {
      const choice = chooseName(raw, new Set());
      expect(choice.name, raw).toBeUndefined();
      expect(choice.reason, raw).toBeTruthy();
    }
  });

  it("names the specific reason", () => {
    expect(chooseName("2FA_TOKEN", new Set()).reason).toMatch(/digit/i);
    expect(chooseName("MY.KEY", new Set()).reason).toMatch(/character/i);
  });

  it("refuses to suffix past the 64-character name limit", () => {
    const long = "a".repeat(64);
    expect(chooseName(long, new Set()).name).toBe(long);
    expect(chooseName(long, new Set([long])).reason).toMatch(/64|length|long/i);
  });
});

describe("splitPathInput (F1: no separator, no listing)", () => {
  const opts = { home: "/home/u", cwd: "/work/proj" };

  it("returns null until the text contains a /", () => {
    for (const input of ["", "env", ".env", "~", "..", "proj"]) {
      expect(splitPathInput(input, opts), input).toBeNull();
    }
  });

  it("splits a relative prefix and resolves the directory against cwd", () => {
    expect(splitPathInput("./.e", opts)).toEqual({
      dir: "/work/proj",
      fragment: ".e",
      rawPrefix: "./",
    });
  });

  it("keeps an absolute directory absolute", () => {
    expect(splitPathInput("/etc/ho", opts)).toEqual({
      dir: "/etc",
      fragment: "ho",
      rawPrefix: "/etc/",
    });
  });

  it("treats a bare / as the filesystem root", () => {
    expect(splitPathInput("/", opts)).toEqual({ dir: "/", fragment: "", rawPrefix: "/" });
  });

  it("expands ~ and ~/ to the home directory, keeping the typed prefix", () => {
    expect(splitPathInput("~/pro", opts)).toEqual({
      dir: "/home/u",
      fragment: "pro",
      rawPrefix: "~/",
    });
    expect(splitPathInput("~/a/b", opts)).toEqual({
      dir: "/home/u/a",
      fragment: "b",
      rawPrefix: "~/a/",
    });
  });

  it("walks up with ../", () => {
    expect(splitPathInput("../.e", opts)).toEqual({
      dir: "/work",
      fragment: ".e",
      rawPrefix: "../",
    });
  });

  it("resolves a typed path for reading, expanding ~", () => {
    expect(resolvePathInput("./.env", opts)).toBe("/work/proj/.env");
    expect(resolvePathInput("~/.env", opts)).toBe("/home/u/.env");
    expect(resolvePathInput("/etc/.env", opts)).toBe("/etc/.env");
  });
});

describe("listCandidates", () => {
  const base = mkdtempSync(join(tmpdir(), "pi-secret-envfile-"));
  mkdirSync(join(base, "sub"));
  mkdirSync(join(base, "src"));
  writeFileSync(join(base, ".env"), "A=1\n");
  writeFileSync(join(base, ".env.local"), "A=1\n");
  writeFileSync(join(base, "env.txt"), "A=1\n");

  it("includes dotfiles, because .env is the point", () => {
    const names = listCandidates(base, ".env")
      .candidates.filter((c) => c.name !== "../")
      .map((c) => c.name);
    expect(names.sort()).toEqual([".env", ".env.local"]);
  });

  it("puts directories first and marks them with a trailing slash", () => {
    const { candidates } = listCandidates(base, "");
    expect(candidates.filter((c) => c.dir).map((c) => c.name)).toEqual(["../", "src/", "sub/"]);
    expect(candidates[0]!.name).toBe("../");
  });

  it("filters by prefix, not by substring", () => {
    expect(listCandidates(base, "env").candidates.map((c) => c.name)).toEqual(["env.txt"]);
    expect(listCandidates(base, "nv").candidates).toEqual([]);
  });

  it("offers ../ only while browsing, never inside a filtered list", () => {
    // A navigation row cannot match a filter, and as the first row it would become Tab's
    // default target: `./.env` + Tab would complete to `./../`.
    expect(listCandidates(base, "").candidates[0]?.name).toBe("../");
    expect(listCandidates(base, ".env").candidates.map((c) => c.name)).not.toContain("../");
    expect(listCandidates("/", "").candidates.map((c) => c.name)).not.toContain("../");
  });

  it("reports an unreadable directory instead of throwing", () => {
    const { candidates, error } = listCandidates(join(base, "nope"), "");
    expect(candidates).toEqual([]);
    expect(error).toMatch(/no such/i);
  });

  it("shows a broken symlink as a file rather than dropping it", () => {
    symlinkSync(join(base, "gone"), join(base, "dangling"));
    expect(listCandidates(base, "dangling").candidates).toContainEqual({ name: "dangling", dir: false });
  });
});

describe("inspectPath (F2: regular text files only)", () => {
  const base = mkdtempSync(join(tmpdir(), "pi-secret-inspect-"));
  mkdirSync(join(base, "adir"));
  writeFileSync(join(base, "ok.env"), "A=1\n");
  writeFileSync(join(base, "bin.env"), Buffer.from([0x41, 0x00, 0x42]));
  writeFileSync(join(base, "big.env"), Buffer.alloc(MAX_ENV_BYTES + 1, 0x41));

  it("accepts a regular text file", () => {
    expect(inspectPath(join(base, "ok.env"))).toEqual({ kind: "file" });
  });

  it("reports a directory as a directory so the picker can descend", () => {
    expect(inspectPath(join(base, "adir")).kind).toBe("dir");
  });

  it("reports a missing path", () => {
    expect(inspectPath(join(base, "nope")).kind).toBe("missing");
  });

  it("refuses non-regular files", () => {
    expect(inspectPath("/dev/null").kind).toBe("other");
    expect(inspectPath("/dev/null").error).toMatch(/not a file/i);
  });

  it("refuses a file over the size limit", () => {
    const found = inspectPath(join(base, "big.env"));
    expect(found.kind).toBe("file");
    expect(found.error).toMatch(/too large/i);
  });

  it("refuses a file with a NUL byte in the first 8 KiB", () => {
    const found = inspectPath(join(base, "bin.env"));
    expect(found.error).toMatch(/text/i);
  });
});
