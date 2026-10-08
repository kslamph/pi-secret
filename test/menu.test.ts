import { describe, expect, it, vi } from "vitest";
import { entryRows, secretRows, selectList, type SecAction, type Row } from "../src/menu.ts";
import { Vault, type PublicEntry } from "../src/vault.ts";

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

  it("always offers Add, and a toggle that states the action it performs", () => {
    const on = secretRows([], { enabled: true, now: NOW });
    expect(on.map((r) => r.action.kind)).toEqual(["add", "toggle"]);
    expect(on[1]!.label).toBe("Disable for this session");
    expect(on[1]!.detail).toContain("clears the values");
    const off = secretRows([], { enabled: false, now: NOW });
    expect(off[1]!.label).toBe("Enable for this session");
  });

  it("is a single list even with nothing in it — the user always has somewhere to go", () => {
    const rows = secretRows([], { enabled: true, now: NOW });
    expect(rows).toHaveLength(2);
    expect(rows.every((r) => r.action.kind !== "entry")).toBe(true);
  });

  it("aligns the detail column so previews line up", () => {
    const rows = secretRows([entry("a"), entry("a_much_longer_name")], { enabled: true, now: NOW });
    const heads = rows.slice(0, 2).map((r) => r.label.length);
    expect(heads[0]).toBe(heads[1]);
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
    expect(await selectList({ ui: third.ui } as never, "t", rows)).toEqual({ kind: "toggle" });
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
    void selectList({ ui } as never, "pi-secure", rows, { a: { kind: "add" }, t: { kind: "toggle" } });
    const footer = rendered.join("\n");
    expect(footer).toContain("a");
    expect(footer).toContain("t");
    expect(footer).toContain("enter select");
  });

  it("renders a pointer on the selected row and never past the terminal width", () => {
    const { ui, rendered } = fakeUi([["\x1b"]]);
    void selectList({ ui } as never, "pi-secure", rows);
    const body = rendered.join("\n");
    expect(body).toContain("❯");
    for (const line of rendered) expect(line.length).toBeLessThanOrEqual(80);
  });
});