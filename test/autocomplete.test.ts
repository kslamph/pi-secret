import { describe, expect, it } from "vitest";
import { createSecAutocompleteProvider } from "../src/autocomplete.ts";
import type { AutocompleteItem } from "@earendil-works/pi-tui";
import { Vault } from "../src/vault.ts";

const GH = "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8";

function vault(): Vault {
  const v = new Vault("t");
  v.add("gh_pat", GH, "prompt");
  v.add("db_url", "postgres://admin:s3cr3t@db.internal:5432/app", "paste");
  return v;
}

const signal = new AbortController().signal;
const suggest = (v: Vault, line: string, col = line.length) =>
  createSecAutocompleteProvider(() => v).getSuggestions([line], 0, col, { signal });

describe("{{sec: completion", () => {
  it("offers every name right after the prefix", async () => {
    const out = await suggest(vault(), "curl -H '{{sec:");
    expect(out?.items.map((i: AutocompleteItem) => i.value)).toEqual(["gh_pat", "db_url"]);
    expect(out?.prefix).toBe("{{sec:");
  });

  it("filters on a partial name", async () => {
    const out = await suggest(vault(), "echo {{sec:db");
    expect(out?.items.map((i: AutocompleteItem) => i.value)).toEqual(["db_url"]);
    expect(out?.prefix).toBe("{{sec:db");
  });

  it("describes each entry with length and fingerprint only, never a value", async () => {
    const out = await suggest(vault(), "{{sec:");
    const text = JSON.stringify(out);
    expect(text).not.toContain(GH);
    expect(text).not.toContain("s3cr3t");
    expect(out?.items[0]?.description).toMatch(/len \d+ · sha256:[0-9a-f]{4}/);
  });

  it("stays out of the way for ordinary braces and other text", async () => {
    const v = vault();
    for (const line of ["echo {", "echo {{not_sec:gh", "echo {{sec}}", "echo hello", "echo '{{sec:'"]) {
      // Including the CLOSED single-quoted case: at that cursor there is no half-typed
      // ref, it is inert text, and suggesting a name there would be noise. It also
      // agrees with the guard, which refuses to expand a ref inside quotes.
      expect(await suggest(v, line)).toBeNull();
    }
  });

  it("does suggest inside an OPEN quote, which is where the user is actually typing", async () => {
    // `curl -H '{{sec:` — cursor inside the quotes, ref still incomplete. This is the
    // common case and it must work; the quoted one above must not.
    const out = await suggest(vault(), "curl -H '{{sec:");
    expect(out?.items.map((i: AutocompleteItem) => i.value)).toEqual(["gh_pat", "db_url"]);
  });

  it("returns nothing rather than throwing on an empty vault", async () => {
    expect(await suggest(new Vault("empty"), "{{sec:")).toBeNull();
  });
});

describe("applying a completion", () => {
  /** Drive the real two-step flow: suggest at the cursor, then apply the chosen item. */
  async function complete(line: string, cursorCol = line.length) {
    const v = vault();
    const p = createSecAutocompleteProvider(() => v);
    const typed = /\{\{sec:([a-z0-9_-]*)$/.exec(line.slice(0, cursorCol))?.[1] ?? "";
    const suggestions = await p.getSuggestions([line], 0, cursorCol, { signal });
    if (!suggestions || suggestions.items.length === 0) throw new Error(`no suggestions for ${line}`);
    const item = suggestions.items.find((i: AutocompleteItem) => i.value.startsWith(typed)) ?? suggestions.items[0]!;
    return p.applyCompletion([line], 0, cursorCol, item, suggestions.prefix).lines[0];
  }

  it("replaces the partial token with a complete ref", async () => {
    expect(await complete("{{sec:gh")).toBe("{{sec:gh_pat}}");
    expect(await complete("curl -H '{{sec:db")).toBe("curl -H '{{sec:db_url}}");
  });

  it("keeps the closing braces the user already typed from doubling up", async () => {
    expect(await complete("{{sec:gh}} tail", 8)).toBe("{{sec:gh_pat}} tail");
  });

  it("leaves a trailing argument intact", async () => {
    expect(await complete("{{sec:db}} --flag", 8)).toBe("{{sec:db_url}} --flag");
  });

  it("never writes a value into the editor", async () => {
    const out = await complete("{{sec:");
    expect(out).not.toContain(GH);
    expect(out).not.toContain("s3cr3t");
    expect(out).toBe("{{sec:gh_pat}}");
  });
});