import type { ExtensionCommandContext } from "@earendil-works/pi-coding-agent";
import { Key, matchesKey, truncateToWidth } from "@earendil-works/pi-tui";
import type { PublicEntry } from "./vault.ts";

/**
 * The `/sec` menu: a list you can drive without remembering a single subcommand.
 *
 * Shape: `/sec` opens a list of this session's secrets, each showing the masked preview, so
 * you can tell two keys apart at a glance. Enter opens that entry's actions — copy, rename,
 * remove. A row (and the `a` key) adds; a row (and `t`) flips the session switch.
 *
 * Why a hand-rolled component when `ctx.ui.select` exists: the built-in selector is a plain
 * list with arrow keys, and the affordances that make this menu fast — single-letter keys, the
 * preview and age inline on the same row, a toggle that states the action it will perform —
 * are exactly what it does not offer. Text entry and confirmation are the opposite case, so
 * those use the built-in dialogs (`ctx.ui.input`, `ctx.ui.confirm`) rather than reimplementing
 * input handling a second time.
 *
 * The rows are built by pure functions so the menu's CONTENT is testable without a terminal;
 * only the key handling needs the component, and the test drives that through a fake TUI.
 */

export type SecAction =
  | { kind: "entry"; name: string }
  | { kind: "add" }
  | { kind: "toggle" }
  | { kind: "copy"; name: string }
  | { kind: "rename"; name: string }
  | { kind: "remove"; name: string }
  | { kind: "back" };

export interface Row {
  action: SecAction;
  label: string;
  /** Right-aligned dim text: the preview, length, age. */
  detail?: string;
  /**
   * Draw a separator above this row.
   *
   * Purely a rendering hint — every row stays selectable. Conflating this with
   * "not selectable" is a trap I walked into on the first pass: `Add a secret…` carries a
   * separator, and the arrow keys then skipped straight over the one row a first-time user
   * most wants.
   */
  separatorBefore?: boolean;
}

function ago(ts: number, now: number): string {
  const mins = Math.max(0, Math.round((now - ts) / 60_000));
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

/** Name column width, capped so one long name cannot push the preview off a narrow terminal. */
function nameWidth(entries: readonly PublicEntry[]): number {
  return Math.min(24, Math.max(8, ...entries.map((e) => e.name.length)));
}

function pad(name: string, width: number): string {
  return name.length >= width ? name : name + " ".repeat(width - name.length);
}

/**
 * The main list.
 *
 * The label carries the name; the detail carries everything needed to recognise it. Add and
 * the session switch are rows rather than hidden commands, because the point of this menu is
 * that nothing is hidden.
 */
export function secretRows(
  entries: readonly PublicEntry[],
  options: { enabled: boolean; now?: number },
): Row[] {
  const now = options.now ?? Date.now();
  const w = nameWidth(entries);
  const rows: Row[] = entries.map((e) => ({
    action: { kind: "entry", name: e.name },
    label: pad(e.name, w),
    // Length and source are here rather than on a second line because the whole point is
    // telling two keys apart at a glance; the preview alone can be ambiguous.
    detail: `${e.preview ?? `sha256:${e.fingerprint}`} · len ${e.length} · ${e.source} · ${ago(e.addedAt, now)}`,
  }));
  rows.push({
    action: { kind: "add" },
    label: "Add a secret…",
    detail: "a",
    separatorBefore: true,
  });
  rows.push({
    action: { kind: "toggle" },
    // The row states the ACTION it performs, not the current state, so there is no second
    // lookup and no ambiguity about what pressing enter will do.
    label: options.enabled ? "Disable for this session" : "Enable for this session",
    detail: options.enabled ? "t · clears the values" : "t",
  });
  return rows;
}

/** The per-entry action menu. */
export function entryRows(name: string): Row[] {
  return [
    { action: { kind: "copy", name }, label: "Copy value to clipboard", detail: "c" },
    { action: { kind: "rename", name }, label: "Rename…", detail: "r" },
    { action: { kind: "remove", name }, label: "Remove from this session", detail: "d", separatorBefore: true },
    { action: { kind: "back" }, label: "Back", detail: "esc" },
  ];
}

/**
 * A selectable list with single-letter shortcuts.
 *
 * `shortcuts` map a literal character to the action it performs anywhere on the list, so the
 * common moves never require reaching for the arrow keys — and the footer prints them, which
 * is the only way a user learns they exist.
 */
export function selectList(
  ctx: ExtensionCommandContext,
  title: string,
  rows: readonly Row[],
  shortcuts: Record<string, SecAction> = {},
): Promise<SecAction | null> {
  if (rows.length === 0) return Promise.resolve(null);
  return ctx.ui.custom<SecAction | null>((tui, theme, _kb, done) => {
    let cursor = 0;
    return {
      render(width: number): string[] {
        const w = Math.max(24, width);
        const lines: string[] = [];
        const add = (line = "") => lines.push(truncateToWidth(line, w));
        add(theme.fg("accent", "─".repeat(w)));
        add(` ${theme.fg("accent", theme.bold(title))}`);
        add();
        rows.forEach((row, i) => {
          if (row.separatorBefore) add();
          const pointer = i === cursor ? theme.fg("accent", "❯ ") : "  ";
          const name = truncateToWidth(row.label, Math.max(8, w - 26));
          const detail = row.detail ? theme.fg("dim", row.detail) : "";
          const gap = Math.max(1, w - name.length - detail.length - 4);
          add(` ${pointer}${name}${" ".repeat(gap)}${detail}`);
        });
        add();
        const keys = Object.keys(shortcuts);
        const hint = keys.length
          ? `↑/↓ move · enter select · ${keys.map((k) => theme.bold(k)).join("/")} ${keys.length === 1 ? "shortcut" : "shortcuts"} · esc close`
          : "↑/↓ move · enter select · esc close";
        add(` ${theme.fg("text", hint)}`);
        return lines;
      },
      invalidate() {},
      handleInput(data: string): void {
        if (matchesKey(data, Key.up)) {
          cursor = Math.max(0, cursor - 1);
        } else if (matchesKey(data, Key.down)) {
          cursor = Math.min(rows.length - 1, cursor + 1);
        } else if (matchesKey(data, Key.return)) {
          const row = rows[cursor];
          if (row) done(row.action);
        } else if (matchesKey(data, Key.escape)) {
          done(null);
        } else {
          // A shortcut fires wherever the cursor is: it is a command, not a selection.
          const ch = data.length === 1 ? data : "";
          const hit = ch ? shortcuts[ch] : undefined;
          if (hit) done(hit);
        }
        tui.requestRender();
      },
    };
  });
}

/** True when a UI capable of showing the menu exists. */
export function canShowMenu(ctx: ExtensionCommandContext): boolean {
  return ctx.mode === "tui" && ctx.hasUI;
}