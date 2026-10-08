import type { ExtensionCommandContext } from "@earendil-works/pi-coding-agent";
import { DynamicBorder, keyHint } from "@earendil-works/pi-coding-agent";
import type { Component } from "@earendil-works/pi-tui";
import { Container, Input, Key, Spacer, Text, matchesKey } from "@earendil-works/pi-tui";
import { inspectPath, listCandidates, resolvePathInput, splitPathInput, type Candidate } from "./env-file.ts";

/**
 * The two screens of §12g. Both are chrome-only: they are built from pi's own parts
 * (`DynamicBorder`, `Text`, `Input`, `keyHint`), the same family as the masked prompt, and neither
 * of them is ever given a secret VALUE.
 *
 * That last point is structural, not a promise. `chooseAssignments` returns row **ids** — indices
 * the caller can map back to its own array. The component has no field to leak, so §12g F6 ("the
 * value is never rendered") does not depend on anyone remembering it.
 */

/** Only the part of a theme these screens need, so tests can pass a stub. */
export interface ImportTheme {
  fg(color: string, text: string): string;
}

/** Rows visible at once in either list. */
const MAX_VISIBLE = 8;

function windowAround(total: number, highlight: number): { start: number; end: number } {
  if (total <= MAX_VISIBLE) return { start: 0, end: total };
  const half = Math.floor(MAX_VISIBLE / 2);
  const start = Math.min(Math.max(0, highlight - half), total - MAX_VISIBLE);
  return { start, end: start + MAX_VISIBLE };
}

export interface PickerOptions {
  cwd: string;
  home: string;
  /**
   * Injectable for the same reason `Vault`'s `toVar` is: §12g F1 claims the picker performs **no**
   * filesystem call before the user types a separator, and a claim like that is only worth making
   * if a test can observe the call not happening.
   */
  list?: typeof listCandidates;
}

/**
 * §12g.1 — the path picker.
 *
 * Returns the absolute path of an existing regular file, or `undefined` if the user cancelled.
 * Reading the file is the caller's job; this only ever asks the filesystem for directory listings
 * and metadata.
 */
export async function pickFile(
  ctx: ExtensionCommandContext,
  title: string,
  opts: PickerOptions,
): Promise<string | undefined> {
  if (ctx.mode !== "tui" || !ctx.hasUI) return undefined;
  const lister = opts.list ?? listCandidates;

  return ctx.ui.custom<string | undefined>((tui, theme, _kb, done) => {
    const input = new Input({ prompt: "Path ❯ ", placeholder: "./ or ~/ or /" });
    // The prompt always holds focus while it is on screen, and `Input` only draws its cursor when
    // it believes it is focused.
    input.focused = true;

    const list = new Container();
    const container = new Container();
    container.addChild(new DynamicBorder());
    container.addChild(new Spacer(1));
    container.addChild(new Text(theme.fg("accent", title), 1, 0));
    container.addChild(new Spacer(1));
    container.addChild(input);
    container.addChild(new Spacer(1));
    container.addChild(list);
    container.addChild(new Spacer(1));
    container.addChild(
      new Text(
        `${theme.fg("dim", "↑/↓")}${theme.fg("muted", " choose")}  ${keyHint("tui.input.tab", "complete")}  ${keyHint("tui.select.confirm", "use this file")}  ${keyHint("tui.select.cancel", "cancel")}`,
        1,
        0,
      ),
    );
    container.addChild(new Spacer(1));
    container.addChild(new DynamicBorder());

    let candidates: Candidate[] = [];
    let highlight = 0;
    let settled = false;

    const draw = () => tui.requestRender();

    const showMessage = (message: string) => {
      list.clear();
      list.addChild(new Text(theme.fg("dim", message), 1, 0));
      candidates = [];
    };

    /**
     * Recompute the list from the current input.
     *
     * The `split === null` branch is §12g F1: an empty buffer, or a word with no separator, lists
     * nothing AND calls nothing. Everything else about "the user initiates the starting point"
     * follows from this one early return.
     *
     * `reset` is true when the listing context changed (first draw, or Tab accepted something), as
     * opposed to a keystroke or an arrow key, which only clamps. Without the distinction the user's
     * ↑/↓ choice would be destroyed on the next character typed.
     */
    const refresh = (reset = false) => {
      const typed = input.getValue();
      const split = splitPathInput(typed, { home: opts.home, cwd: opts.cwd });
      if (!split) {
        // No message: the input's own placeholder already says "start with ./ or ~/ or /", and
        // saying it twice on one screen is noise.
        list.clear();
        candidates = [];
        draw();
        return;
      }
      const listing = lister(split.dir, split.fragment);
      if (listing.error) {
        showMessage(listing.error);
        draw();
        return;
      }
      candidates = listing.candidates;
      if (!candidates.length) {
        showMessage("no matches");
        draw();
        return;
      }
      // `../` is a place to GO, not a completion to accept: starting on it made Tab on `./`
      // produce `./../`. It stays reachable with ↑.
      if (reset) {
        const first = candidates.findIndex((c) => c.name !== "../");
        highlight = first === -1 ? 0 : first;
      }
      highlight = Math.min(Math.max(highlight, 0), candidates.length - 1);
      const win = windowAround(candidates.length, highlight);
      list.clear();
      for (let i = win.start; i < win.end; i++) {
        const row = candidates[i]!;
        const text = row.name;
        list.addChild(new Text(i === highlight ? theme.fg("accent", `▸ ${text}`) : `  ${text}`, 1, 0));
      }
      draw();
    };

    const settle = (value: string | undefined) => {
      if (settled) return;
      settled = true;
      done(value);
    };

    /** Tab: accept the highlighted row. A directory descends, a file completes the name. */
    const accept = () => {
      const row = candidates[highlight];
      if (!row) return;
      const split = splitPathInput(input.getValue(), { home: opts.home, cwd: opts.cwd });
      if (!split) return;
      input.setValue(split.rawPrefix + row.name);
      refresh(true);
    };

    /** Enter: act on what was TYPED, never on what happens to be highlighted. */
    const confirm = () => {
      const typed = input.getValue().trim();
      if (!typed) return;
      const resolved = resolvePathInput(typed, { home: opts.home, cwd: opts.cwd });
      const found = inspectPath(resolved);
      if (found.kind === "dir") {
        input.setValue(typed.endsWith("/") ? typed : `${typed}/`);
        refresh(true);
        return;
      }
      if (found.kind === "missing") {
        showMessage("no such file");
        draw();
        return;
      }
      if (found.kind === "other" || found.error) {
        showMessage(found.error ?? "not a file");
        draw();
        return;
      }
      settle(resolved);
    };

    refresh(true);

    return {
      render: (width: number) => container.render(width),
      invalidate: () => container.invalidate(),
      handleInput: (data: string) => {
        if (settled) return;
        if (matchesKey(data, Key.escape) || matchesKey(data, Key.ctrl("c"))) {
          settle(undefined);
          return;
        }
        if (matchesKey(data, Key.up)) {
          if (candidates.length) highlight = Math.max(0, highlight - 1);
          refresh();
          return;
        }
        if (matchesKey(data, Key.down)) {
          if (candidates.length) highlight = Math.min(candidates.length - 1, highlight + 1);
          refresh();
          return;
        }
        if (matchesKey(data, Key.tab)) {
          accept();
          return;
        }
        if (matchesKey(data, Key.return)) {
          confirm();
          return;
        }
        input.handleInput(data);
        // A keystroke changes the candidate set, so the default target is recomputed: after typing
        // `.env`, Tab must complete to `.env`, not to whatever row happened to be highlighted while
        // the list meant something else.
        refresh(true);
      },
    };
  });
}

export interface ChoiceRow {
  /** Opaque to this component: the caller maps it back to its own data. */
  id: number;
  label: string;
  note?: string;
  /**
   * The classifier's verdict (spec §12g). Likely rows are what the list shows by default; the rest
   * are one keypress away, never silently discarded.
   */
  likely: boolean;
  disabled: boolean;
}

/**
 * §12g.2 — the assignment list.
 *
 * Returns the ids of the ticked rows, or `[]` if the user cancelled or ticked nothing. Values are
 * not present here in any form: only names, notes and a boolean that says whether the value looked
 * credential-shaped.
 */
export async function chooseAssignments(
  ctx: ExtensionCommandContext,
  title: string,
  rows: readonly ChoiceRow[],
  summary: string,
): Promise<number[]> {
  if (ctx.mode !== "tui" || !ctx.hasUI) return [];

  return ctx.ui.custom<number[]>((tui, theme, _kb, done) => {
    const selected = new Set<number>();
    const list = new Container();
    const container = new Container();
    container.addChild(new DynamicBorder());
    container.addChild(new Spacer(1));
    container.addChild(new Text(theme.fg("accent", title), 1, 0));
    container.addChild(new Spacer(1));
    if (summary) container.addChild(new Text(theme.fg("dim", summary), 1, 0));
    container.addChild(list);
    container.addChild(new Spacer(1));
    const footer = new Text("", 1, 0);
    container.addChild(footer);
    container.addChild(new Spacer(1));
    container.addChild(new DynamicBorder());

    /**
     * spec §12g: show only the likely secrets.
     *
     * The first version of this screen showed every assignment with the likely ones marked, on the
     * theory that hiding a line the user can see in the file is worse than showing noise. A real
     * `~/.bashrc` settled it the other way: 34 rows, 10 marked, 6 of those marked wrongly — the
     * list was unusable, and the user asked for the noise to go. So the predicate gates the default
     * view, and `TAB` reveals everything, which keeps both properties: a quiet list, and no line
     * that cannot be reached.
     *
     * When nothing at all is likely, everything is shown: an empty screen would be a worse failure
     * than the noise the filter exists to remove.
     */
    const likelyRows = rows.filter((r) => r.likely);
    let showAll = likelyRows.length === 0;
    const visible = () => (showAll ? rows : likelyRows);
    // Both halves matter: with nothing likely the filter is already showing everything, and a
    // toggle there would only offer an empty list.
    const canToggle = likelyRows.length > 0 && likelyRows.length < rows.length;

    let highlight = Math.max(0, visible().findIndex((r) => !r.disabled));
    let settled = false;

    const draw = () => tui.requestRender();

    const footerText = () => {
      const count = selected.size;
      const add = count ? `⏎ add ${count}` : "⏎ add";
      // Only offered when there IS something hidden, so the hint never invites a no-op.
      const toggleHint = canToggle
        ? showAll
          ? `  TAB likely only (${likelyRows.length})`
          : `  TAB show all ${rows.length}`
        : "";
      return `space select  a all  n none  ${add}${toggleHint}  esc cancel`;
    };

    const redraw = () => {
      const shown = visible();
      highlight = Math.min(Math.max(highlight, 0), Math.max(0, shown.length - 1));
      const win = windowAround(shown.length, highlight);
      list.clear();
      for (let i = win.start; i < win.end; i++) {
        const row = shown[i]!;
        const box = selected.has(row.id) ? "[x]" : "[ ]";
        const mark = row.likely ? " • likely secret" : "";
        const note = row.note ? `  ${row.note}` : "";
        const line = `${box} ${row.label}${mark}${note}`;
        const pointer = i === highlight ? "▸ " : "  ";
        list.addChild(
          new Text(row.disabled ? theme.fg("dim", `${pointer}${line}`) : theme.fg(i === highlight ? "accent" : "text", `${pointer}${line}`), 1, 0),
        );
      }
      footer.setText(theme.fg("dim", footerText()));
      draw();
    };

    const settle = (value: number[]) => {
      if (settled) return;
      settled = true;
      done(value);
    };

    const toggle = () => {
      const row = visible()[highlight];
      if (!row || row.disabled) return;
      if (selected.has(row.id)) selected.delete(row.id);
      else selected.add(row.id);
      redraw();
    };

    redraw();

    return {
      render: (width: number) => container.render(width),
      invalidate: () => container.invalidate(),
      handleInput: (data: string) => {
        if (settled) return;
        if (matchesKey(data, Key.escape) || matchesKey(data, Key.ctrl("c"))) {
          settle([]);
          return;
        }
        if (matchesKey(data, Key.up)) {
          highlight = Math.max(0, highlight - 1);
          redraw();
          return;
        }
        if (matchesKey(data, Key.down)) {
          highlight = Math.min(visible().length - 1, highlight + 1);
          redraw();
          return;
        }
        if (matchesKey(data, Key.tab)) {
          // Reveal/conceal the rows the classifier did not call secrets. Ticks survive the flip:
          // `n` is how you clear them, and the count stays visible in the footer either way.
          if (!canToggle) return;
          showAll = !showAll;
          // Land ON what changed. Simply re-listing would leave the same first screenful in place
          // (likely rows sort first), so the user would have to scroll to discover that TAB did
          // anything at all.
          const shown = visible();
          const firstHidden = showAll ? shown.findIndex((r) => !r.likely) : -1;
          highlight = Math.max(0, firstHidden >= 0 ? firstHidden : shown.findIndex((r) => !r.disabled));
          redraw();
          return;
        }
        if (matchesKey(data, Key.space) || data === " ") {
          toggle();
          return;
        }
        if (matchesKey(data, Key.return)) {
          settle([...selected]);
          return;
        }
        if (data === "a") {
          // What `a` can select is what the user can see.
          for (const row of visible()) if (!row.disabled) selected.add(row.id);
          redraw();
          return;
        }
        if (data === "n") {
          selected.clear();
          redraw();
        }
      },
    };
  });
}
