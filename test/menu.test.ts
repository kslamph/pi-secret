import { describe, expect, it, vi } from "vitest";
import { entryRows, secretRows, selectList, statusLine, type Row } from "../src/menu.ts";
import { Vault, vaultForSession, setActiveScopeKey, type PublicEntry } from "../src/vault.ts";
import { isEnabled, setEnabled } from "../src/state.ts";

const GH = "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8";
const NOW = 1_760_000_000_000;

function entry(name: string, over: Partial<PublicEntry> = {}): PublicEntry {
  return {
    name,
    length: 40,
    fingerprint: "a1b2c3d4",
    preview: "ghp_A1b2…Q7R8",
    addedAt: NOW - 120_000,
    tier: "session",
    source: "paste",
    ...over,
  } as PublicEntry;
}

/**
 * A fake `ctx.ui.custom` that captures the component so keys can be fed to it. Driving the
 * REAL component is the point: row layout and key handling are the two things a pure-function
 * test cannot check, and this project has been bitten by a stub that agreed with the code
 * under test rather than with reality.
 */
function fakeUi(scripts: (string[] | null)[]) {
  // `settled` rather than a truthiness check on the value: cancelling resolves with NULL,
  // and a harness that treats null as "not finished" hangs forever on the one key every user
  // presses most. That is a bug this harness had, and it looked exactly like a component bug.
  let settled = false;
  let result: unknown;
  const rendered: string[] = [];
  const ui = {
    custom: async (factory: (tui: unknown, theme: unknown, kb: unknown, d: (v: unknown) => void) => unknown) => {
      const component = factory(
        { requestRender: () => {} },
        { fg: (_c: string, t: string) => t, bold: (t: string) => t },
        {},
        (v: unknown) => {
          settled = true;
          result = v;
        },
      ) as { render(width: number): string[]; handleInput(data: string): void };
      rendered.push(...component.render(80));
      const script = scripts.shift();
      for (const key of script ?? ["\x1b"]) component.handleInput(key);
      if (!settled) throw new Error("fake ui: the panel never called done()");
      return result;
    },
    input: vi.fn(),
    confirm: vi.fn(),
    notify: vi.fn(),
  };
  return { ui, rendered };
}

const UP = "\x1b[A";
const DOWN = "\x1b[B";
const ENTER = "\r";

describe("the /sec list", () => {
  it("shows every secret with the preview, length, source and age", () => {
    const rows = secretRows([entry("gh_pat"), entry("db_url", { source: "prompt" })], { enabled: true, now: NOW });
    const first = rows[0]!;
    expect(first.action).toEqual({ kind: "entry", name: "gh_pat" });
    expect(first.detail).toContain("ghp_A1b2…Q7R8");
    expect(first.detail).toContain("len 40");
    expect(first.detail).toContain("paste");
    expect(first.detail).toContain("2m ago");
    expect(rows[1]!.detail).toContain("prompt");
  });

  it("always offers Add, and a toggle that names BOTH the subject and the consequence", () => {
    // "Enable for this session" inside a list of per-secret items was read as being about
    // those items. It is about pi-secret itself, and the two directions have different
    // consequences, so the label states the subject and spells the consequence out.
    const on = secretRows([], { enabled: true, now: NOW });
    expect(on.map((r) => r.action.kind)).toEqual(["add", "add-file", "toggle"]);
    expect(on[2]!.label).toBe("Turn pi-secret off (clears these secrets)");
    const off = secretRows([], { enabled: false, now: NOW });
    expect(off[2]!.label).toBe("Turn pi-secret on");
  });

  it("is a single list even with nothing in it — the user always has somewhere to go", () => {
    const rows = secretRows([], { enabled: true, now: NOW });
    expect(rows).toHaveLength(3);
    expect(rows.every((r) => r.action.kind !== "entry")).toBe(true);
  });

  it("offers the file-import row next to Add, with its own shortcut", () => {
    // §12g's discovery surface: reachable without knowing the verb, same as `Add a secret…`.
    const rows = secretRows([], { enabled: true, now: NOW });
    const file = rows.find((r) => r.action.kind === "add-file")!;
    expect(file.label).toBe("Add from a file…");
    expect(file.detail).toBe("f");
    expect(rows.findIndex((r) => r.action.kind === "add")).toBeLessThan(rows.indexOf(file));
  });

  it("aligns the detail column so previews line up", () => {
    const rows = secretRows([entry("a"), entry("a_much_longer_name")], { enabled: true, now: NOW });
    const heads = rows.slice(0, 2).map((r) => r.label.length);
    expect(heads[0]).toBe(heads[1]);
  });

  it("never truncates an ACTION row to the name column width", () => {
    // "Turn pi-secret off (clears these secrets)" truncated to "Turn pi-secret off (cle…"
    // loses exactly the part that says what will happen — which is the part that matters.
    const rows = secretRows([entry("gh_pat")], { enabled: true, now: NOW });
    const toggle = rows.at(-1)!;
    const { ui, rendered } = fakeUi([["\x1b"]]);
    void selectList({ ui } as never, "t", rows);
    const line = rendered.find((l) => l.includes("Turn pi-secret"));
    expect(line).toContain(toggle.label);
  });

  it("keeps the detail column aligned when a name is longer than the column", () => {
    // Without the cap this, one long name shifts every preview to its right and the list stops
    // being scannable at all — which is the only reason the column exists.
    const long = "a_secret_name_far_too_long_for_the_column";
    const rows = secretRows([entry(long), entry("short")], { enabled: true, now: NOW });
    const { ui, rendered } = fakeUi([["\x1b"]]);
    void selectList({ ui } as never, "t", rows);
    const lines = rendered.filter((l) => l.includes("len 40") || l.includes("len 40"));
    const detailStarts = rendered
      .filter((l) => l.includes("sha256") || l.includes("ghp_"))
      .map((l) => l.search(/ghp_|sha256/));
    expect(detailStarts.length).toBeGreaterThanOrEqual(2);
    expect(new Set(detailStarts).size).toBe(1);
  });
});

describe("the status line above the list", () => {
  it("states the extension's state, not the list's contents", () => {
    // The row alone could be read as describing the entries; the status line at the top is
    // what separates "what is true now" from "what pressing this does".
    expect(statusLine(true, 3)).toMatch(/^ON .*refs expand.*3 secrets/);
    expect(statusLine(true, 1)).toContain("1 secret this session");
    expect(statusLine(false, 0)).toBe("OFF · refs do NOT expand · no values stored");
  });

  it("is rendered above the rows, not buried in them", async () => {
    const rows = secretRows([entry("gh_pat")], { enabled: false, now: NOW });
    const { ui, rendered } = fakeUi([["\x1b"]]);
    void selectList({ ui } as never, "t", rows, {}, statusLine(false, 0));
    const text = rendered.join("\n");
    expect(text).toContain("OFF");
    expect(text.indexOf("OFF")).toBeLessThan(text.indexOf("gh_pat"));
  });
});

describe("the per-entry actions", () => {
  it("offers copy, rename, remove and back — and nothing that reveals the value on screen", () => {
    const rows = entryRows("gh_pat");
    expect(rows.map((r) => r.action.kind)).toEqual(["copy", "rename", "remove", "back"]);
    expect(JSON.stringify(rows)).not.toContain(GH);
  });
});

describe("driving the list", () => {
  const rows = secretRows([entry("gh_pat"), entry("db_url")], { enabled: true, now: NOW });

  it("opens the highlighted row on enter", async () => {
    const { ui } = fakeUi([[ENTER]]);
    const action = await selectList({ ui } as never, "t", rows);
    expect(action).toEqual({ kind: "entry", name: "gh_pat" });
  });

  it("moves with the arrow keys over EVERY row, including the one under a separator", async () => {
    // The separator is a rendering hint, not a hole in the list: `Add a secret…` carries one
    // and must still be reachable, because it is the row a first-time user wants.
    const { ui } = fakeUi([[DOWN, DOWN, ENTER]]);
    expect(await selectList({ ui } as never, "t", rows)).toEqual({ kind: "add" });
    const third = fakeUi([[DOWN, DOWN, DOWN, ENTER]]);
    expect(await selectList({ ui: third.ui } as never, "t", rows)).toEqual({ kind: "add-file" });
    const fourth = fakeUi([[DOWN, DOWN, DOWN, DOWN, ENTER]]);
    expect(await selectList({ ui: fourth.ui } as never, "t", rows)).toEqual({ kind: "toggle" });
    const second = fakeUi([[DOWN, ENTER]]);
    expect(await selectList({ ui: second.ui } as never, "t", rows)).toEqual({ kind: "entry", name: "db_url" });
  });

  it("fires a shortcut from anywhere, without moving the cursor first", async () => {
    const { ui } = fakeUi([["a"]]);
    expect(await selectList({ ui } as never, "t", rows, { a: { kind: "add" }, t: { kind: "toggle" } })).toEqual({
      kind: "add",
    });
  });

  it("does not fire a shortcut for a key that is not bound", async () => {
    // `x` is not bound: nothing happens, so the panel stays open and the user keeps typing.
    const { ui } = fakeUi([["x", ENTER]]);
    expect(await selectList({ ui } as never, "t", rows, { a: { kind: "add" } })).toEqual({
      kind: "entry",
      name: "gh_pat",
    });
  });

  it("closes on escape, and up at the top does not wrap around", async () => {
    const { ui } = fakeUi([["\x1b"]]);
    expect(await selectList({ ui } as never, "t", rows)).toBeNull();
    const stuck = fakeUi([[UP, UP, ENTER]]);
    expect(await selectList({ ui: stuck.ui } as never, "t", rows)).toEqual({ kind: "entry", name: "gh_pat" });
  });

  it("prints the shortcuts in the footer, since that is the only way they are discoverable", () => {
    const { ui, rendered } = fakeUi([["\x1b"]]);
    void selectList({ ui } as never, "pi-secret", rows, { a: { kind: "add" }, t: { kind: "toggle" } });
    const footer = rendered.join("\n");
    expect(footer).toContain("a");
    expect(footer).toContain("t");
    expect(footer).toContain("enter select");
  });

  it("renders a pointer on the selected row and never past the terminal width", () => {
    const { ui, rendered } = fakeUi([["\x1b"]]);
    void selectList({ ui } as never, "pi-secret", rows);
    const body = rendered.join("\n");
    expect(body).toContain("❯");
    for (const line of rendered) expect(line.length).toBeLessThanOrEqual(80);
  });
});
/**
 * Reported from the field: after removing a secret the menu stayed on that secret's action
 * page — offering "Rename" and "Remove" for something that no longer exists. The entry sub-menu
 * now always hands control back to the list once it has changed or deleted the entry.
 */
describe("leaving an entry menu", () => {
  it("returns to the list after a removal, and after a rename", async () => {
    // The behaviour under test is the RETURN, so it is driven through the real command loop:
    // the sub-menu must not re-open the entry it just changed.
    const vault = new Vault("menu-loop");
    vault.add("gh_pat", GH, "prompt");
    const removed: string[] = [];
    const ctx = {
      mode: "tui" as const,
      hasUI: true,
      ui: {
        notify: vi.fn(),
        input: vi.fn(),
        confirm: vi.fn(async () => true),
        // First panel: pick the entry. Second: pick Remove. Third: must be the LIST, and
        // answering "no" there ends the loop instead of proving anything.
        custom: vi.fn(),
      },
    };
    const script = [
      { kind: "entry", name: "gh_pat" } as const,
      { kind: "remove", name: "gh_pat" } as const,
      null,
    ];
    ctx.ui.custom = vi.fn(async () => script.shift() ?? null) as never;
    const { runSecMenu } = await import("../src/commands.ts");
    await runSecMenu(ctx as never, vault);
    removed.push(...vault.names());
    expect(removed).toEqual([]);
    // two panels were drawn: the entry menu and the list again — not a third entry menu.
    expect(ctx.ui.custom).toHaveBeenCalledTimes(3);
  });

  it("refuses to keep showing an entry menu for something that is already gone", async () => {
    const vault = new Vault("menu-vanished");
    const ctx = {
      mode: "tui" as const,
      hasUI: true,
      ui: { notify: vi.fn(), input: vi.fn(), confirm: vi.fn(), custom: vi.fn() },
    };
    // The entry disappears between the list and the sub-menu (another tab ran `/sec off`).
    const script = [
      { kind: "entry", name: "gh_pat" } as const,
      { kind: "remove", name: "gh_pat" } as const,
      null,
    ];
    let i = 0;
    ctx.ui.custom = vi.fn(async () => script[i++] ?? null) as never;
    const { runSecMenu } = await import("../src/commands.ts");
    await runSecMenu(ctx as never, vault);
    // Three panels: the list, the entry's actions, and the list again. The guard means the
    // action page is drawn ONCE — without it the menu would offer rename/remove for a name
    // that is not in the vault, which is how a user ends up staring at a secret that is gone.
    expect(ctx.ui.custom).toHaveBeenCalledTimes(3);
  });
});

/**
 * The menu's toggle is the same destructive action as `/sec off`, reached by a different door,
 * so it must ask the same question. Guarding only the verb form would leave the shortcut that
 * clears everything unguarded.
 */
describe("turning pi-secret off from the menu", () => {
  it("asks first, and leaves everything alone when the user declines", async () => {
    setEnabled(true);
    // The REGISTRY instance: the toggle calls dropActiveVault(), which empties the value
    // registered for the active scope. A standalone `new Vault(...)` is not that object, so
    // asserting on it would pass no matter what the toggle did.
    setActiveScopeKey("menu-toggle-decline");
    const vault = vaultForSession("menu-toggle-decline");
    vault.add("gh_pat", GH, "prompt");
    const confirm = vi.fn(async () => false);
    const ctx = {
      mode: "tui" as const,
      hasUI: true,
      ui: { notify: vi.fn(), input: vi.fn(), confirm, custom: vi.fn() },
    };
    const script = [{ kind: "toggle" } as const, null];
    let i = 0;
    ctx.ui.custom = vi.fn(async () => script[i++] ?? null) as never;
    const { runSecMenu } = await import("../src/commands.ts");
    await runSecMenu(ctx as never, vault);
    expect(confirm).toHaveBeenCalledTimes(1);
    expect(isEnabled()).toBe(true);
    expect(vaultForSession("menu-toggle-decline").resolve("gh_pat")).toBe(GH);
    setEnabled(true);
    setActiveScopeKey(undefined);
  });

  it("clears and disables when the user confirms", async () => {
    setEnabled(true);
    setActiveScopeKey("menu-toggle-accept");
    const vault = vaultForSession("menu-toggle-accept");
    vault.add("gh_pat", GH, "prompt");
    const confirm = vi.fn(async () => true);
    const ctx = {
      mode: "tui" as const,
      hasUI: true,
      ui: { notify: vi.fn(), input: vi.fn(), confirm, custom: vi.fn() },
    };
    const script = [{ kind: "toggle" } as const, null];
    let i = 0;
    ctx.ui.custom = vi.fn(async () => script[i++] ?? null) as never;
    const { runSecMenu } = await import("../src/commands.ts");
    await runSecMenu(ctx as never, vault);
    expect(confirm).toHaveBeenCalledTimes(1);
    expect(isEnabled()).toBe(false);
    expect(vaultForSession("menu-toggle-accept").names()).toEqual([]);
    setEnabled(true);
    setActiveScopeKey(undefined);
  });
});
