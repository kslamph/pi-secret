import { describe, expect, it } from "vitest";
import { createSecAutocompleteProvider } from "../src/autocomplete.ts";
import type { AutocompleteItem, AutocompleteProvider } from "@earendil-works/pi-tui";
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

  it("describes each entry with a masked preview, and never with a value", async () => {
    const out = await suggest(vault(), "{{sec:");
    const text = JSON.stringify(out);
    expect(text).not.toContain(GH);
    expect(text).not.toContain("s3cr3t");
    // A recognisable prefix is the point: it is what lets the user tell two keys apart.
    expect(out?.items[0]?.description).toBe("ghp_A1b2…Q7R8 · len 40");
    // The DSN is neither a provider format nor random-looking, so no characters of it show.
    expect(out?.items[1]?.description).toMatch(/^sha256:[0-9a-f]{4} · len/);
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
/**
 * Regression: loading pi-secret killed Tab completion everywhere.
 *
 * `ctx.ui.addAutocompleteProvider(factory)` is a WRAPPER hook: pi calls
 * `factory(currentProvider)` and installs the result, where the chain starts at pi's
 * built-in command/file provider. Returning a standalone provider instead of wrapping
 * `current` discards the built-in one, so `/`-command completion, `@`-file completion and
 * Tab file completion all answer null — which reads to the user as "the Tab key is broken".
 */
describe("stacking on the built-in provider", () => {
  function baseProvider(): AutocompleteProvider {
    return {
      triggerCharacters: ["@", "/"],
      getSuggestions: async () => ({ items: [{ value: "builtin-item", label: "builtin-item" }], prefix: "bu" }),
      applyCompletion: () => ({ lines: ["builtin-applied"], cursorLine: 0, cursorCol: 14 }),
      shouldTriggerFileCompletion: () => true,
    };
  }

  it("delegates to the provider underneath when the cursor is not inside a ref", async () => {
    const p = createSecAutocompleteProvider(() => vault(), baseProvider());
    const out = await p.getSuggestions(["echo bu"], 0, 7, { signal });
    expect(out?.items[0]?.value).toBe("builtin-item");
  });

  it("still serves its own refs, and does not ask the base provider for those", async () => {
    let asked = false;
    const base = baseProvider();
    base.getSuggestions = async () => {
      asked = true;
      return null;
    };
    const p = createSecAutocompleteProvider(() => vault(), base);
    const out = await p.getSuggestions(["{{sec:db"], 0, 9, { signal });
    expect(out?.items.map((i: AutocompleteItem) => i.value)).toEqual(["db_url"]);
    expect(asked).toBe(false);
  });

  it("applies the built-in provider's completion for the built-in provider's items", () => {
    const p = createSecAutocompleteProvider(() => vault(), baseProvider());
    const out = p.applyCompletion(["echo bu"], 0, 7, { value: "builtin-item", label: "builtin-item" }, "bu");
    expect(out.lines[0]).toBe("builtin-applied");
  });

  it("keeps the built-in trigger characters and adds its own", () => {
    const p = createSecAutocompleteProvider(() => vault(), baseProvider());
    expect(p.triggerCharacters).toEqual(expect.arrayContaining(["@", "/", "{"]));
  });

  it("forwards shouldTriggerFileCompletion so force-Tab respects the base provider's rules", () => {
    const p = createSecAutocompleteProvider(() => vault(), baseProvider());
    expect(p.shouldTriggerFileCompletion?.([], 0, 0)).toBe(true);
  });

  it("works with no base provider (direct use in tests, and defensive on odd hosts)", async () => {
    const p = createSecAutocompleteProvider(() => vault());
    expect(await p.getSuggestions(["echo bu"], 0, 7, { signal })).toBeNull();
    expect(await p.getSuggestions(["{{sec:"], 0, 7, { signal })).not.toBeNull();
  });
});
