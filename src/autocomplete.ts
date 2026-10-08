import type { AutocompleteItem, AutocompleteProvider } from "@earendil-works/pi-tui";
import type { Vault } from "./vault.ts";

/**
 * `{{sec:NAME}}` completion in the editor — the human-facing half of spec §5's discovery
 * story. The `/sec` verbs already complete through the command's own
 * `getArgumentCompletions`; this covers the ref syntax the model uses and the user
 * types by hand.
 *
 * Value-free by construction, exactly like `sec_list`: items are built from the vault's
 * PublicEntry projection, which has no value field to interpolate. That matters more here
 * than anywhere else in the extension, because this is the one surface that writes text
 * back into the editor — a place a careless `entry.value` would put the secret into the
 * user's input line, and from there into the transcript. (The same reason
 * `ctx.ui.setEditorText()` is absent from the restore seam.)
 */
const PREFIX = "{{sec:";

/** The partially-typed ref immediately before the cursor, or null. */
export function refPrefixBefore(textBeforeCursor: string): { prefix: string; typed: string } | null {
  const m = /\{\{sec:([a-z0-9_-]*)$/.exec(textBeforeCursor);
  if (!m) return null;
  return { prefix: PREFIX + m[1]!, typed: m[1]! };
}

export function createSecAutocompleteProvider(getVault: () => Vault): AutocompleteProvider {
  return {
    // `{` is the only character that can begin a ref. The provider still declines to
    // suggest for an ordinary brace, so an unrelated `{` opens nothing.
    triggerCharacters: ["{"],

    async getSuggestions(lines, cursorLine, cursorCol) {
      const line = lines[cursorLine] ?? "";
      const match = refPrefixBefore(line.slice(0, cursorCol));
      if (!match) return null;
      let entries;
      try {
        entries = getVault().entries();
      } catch {
        // No session bound yet (the dispatcher and tools can run before session_start).
        // An autocomplete popup that throws would take the editor's key handling with it.
        return null;
      }
      const items: AutocompleteItem[] = entries
        .filter((e) => e.name.startsWith(match.typed))
        .map((e) => ({
          value: e.name,
          label: e.name,
          description: `len ${e.length} · sha256:${e.fingerprint}`,
        }));
      return items.length ? { items, prefix: match.prefix } : null;
    },

    applyCompletion(lines, cursorLine, cursorCol, item, prefix) {
      const line = lines[cursorLine] ?? "";
      // Only the typed token is replaced; anything the user already typed after the
      // cursor (a closing `}}`, a trailing argument) stays where it is, so completing
      // inside `{{sec:gh}} tail` does not eat the rest of the command.
      const before = line.slice(0, Math.max(0, cursorCol - prefix.length));
      // Completing inside `{{sec:gh}}` must consume the `}}` the user already typed,
      // or the line ends up as `{{sec:gh_pat}}}}`.
      const after = line.slice(cursorCol).replace(/^\}\}/, "");
      const next = [...lines];
      const rewritten = `${before}${PREFIX}${item.value}}}${after}`;
      next[cursorLine] = rewritten;
      return { lines: next, cursorLine, cursorCol: before.length + PREFIX.length + item.value.length + 2 };
    },
  };
}