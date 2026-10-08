import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { initTheme } from "@earendil-works/pi-coding-agent";
import { chooseAssignments, pickFile, type ChoiceRow } from "../src/file-import.ts";
import { listCandidates } from "../src/env-file.ts";

const CANARY = "ghp_CANARYCANARYCANARYCANARYCANARYCANARY";
// Also drops pi's APC cursor marker (\x1b_pi:c\x07), which is not an SGR sequence.
const strip = (text: string) => text.replace(/\x1b\[[0-9;]*m/g, "").replace(/\x1b_[^\x07]*\x07/g, "");

interface Screen {
  render(width: number): string[];
  handleInput(data: string): void;
}
type Factory = (tui: unknown, theme: unknown, kb: unknown, done: (value: never) => void) => Screen;

const themeStub = { fg: (_color: string, text: string) => text, bold: (text: string) => text };

function fixture(): { base: string; cwd: string } {
  const base = mkdtempSync(join(tmpdir(), "pi-secret-import-"));
  mkdirSync(join(base, "src"));
  writeFileSync(join(base, ".env"), `API_KEY=${CANARY}\nPORT=8080\n`);
  writeFileSync(join(base, ".env.local"), "A=1\n");
  writeFileSync(join(base, "plain.txt"), "hello\n");
  return { base, cwd: base };
}

/** One character at a time: a component that only copes with single keystrokes must be fed them. */
function type(screen: Screen, text: string): void {
  for (const ch of text) screen.handleInput(ch);
}

function openPicker(opts: { cwd: string; home: string; list?: typeof listCandidates }) {
  let component: Screen | undefined;
  const done = vi.fn();
  const ctx = {
    mode: "tui" as const,
    hasUI: true,
    ui: {
      custom: (factory: Factory) => {
        component = factory({ requestRender() {} }, themeStub, {}, (value) => done(value));
        return new Promise(() => {});
      },
    },
  };
  void pickFile(ctx as never, "pi-secret — add from a file", opts);
  return { screen: () => component!, done };
}

function openChooser(rows: ChoiceRow[]) {
  let component: Screen | undefined;
  const done = vi.fn();
  const ctx = {
    mode: "tui" as const,
    hasUI: true,
    ui: {
      custom: (factory: Factory) => {
        component = factory({ requestRender() {} }, themeStub, {}, (value) => done(value));
        return new Promise(() => {});
      },
    },
  };
  void chooseAssignments(ctx as never, "pi-secret — ./.env", rows, "7 assignments · 3 look like secrets");
  return { screen: () => component!, done };
}

// Rows are padded to the full width; trailing padding is noise for assertions.
const text = (screen: Screen) => strip(screen.render(80).join("\n")).replace(/[ \t]+$/gm, "");

describe("the path picker", () => {
  beforeAll(() => initTheme("dark"));

  it("reads nothing and lists nothing before a separator is typed (F1)", () => {
    const { base } = fixture();
    const list = vi.fn(listCandidates);
    const { screen } = openPicker({ cwd: base, home: base, list });
    const shown = text(screen());
    // The guidance is the input's placeholder — one statement of it, not two.
    expect(shown).toContain("./ or ~/ or /");
    expect(shown).not.toContain("plain.txt");
    expect(list).not.toHaveBeenCalled();

    type(screen(), "./");
    expect(list).toHaveBeenCalledTimes(1);
  });

  it("narrows as you type, and dotfiles are in the list", () => {
    const { base } = fixture();
    const { screen } = openPicker({ cwd: base, home: base });
    type(screen(), "./.env");
    const shown = text(screen());
    expect(shown).toMatch(/\.env$/m);
    expect(shown).toContain(".env.local");
    expect(shown).not.toContain("plain.txt");
  });

  it("Tab accepts the highlighted entry — a directory descends", () => {
    const { base } = fixture();
    const { screen } = openPicker({ cwd: base, home: base });
    type(screen(), "./");
    // `../` is listed but never the default target, so Tab cannot produce `./../`.
    screen().handleInput("\t");
    expect(text(screen())).toContain("./src/");
  });

  it("Tab completes a file name instead of descending", () => {
    const { base } = fixture();
    const { screen } = openPicker({ cwd: base, home: base });
    type(screen(), "./.env");
    screen().handleInput("\t");
    const shown = text(screen());
    expect(shown).toContain("./.env");
    expect(shown).not.toContain("./.env/");
  });

  it("arrow keys move the highlight, and up still reaches ../", () => {
    const { base } = fixture();
    const { screen } = openPicker({ cwd: base, home: base });
    type(screen(), "./");
    screen().handleInput("\x1b[B"); // down: src/ -> .env
    screen().handleInput("\t");
    expect(text(screen())).toContain("./.env");

    const again = openPicker({ cwd: base, home: base });
    type(again.screen(), "./");
    again.screen().handleInput("\x1b[A"); // up: onto the navigation row
    again.screen().handleInput("\t");
    expect(text(again.screen())).toContain("./../");
  });

  it("Enter confirms an existing regular file by its resolved path", () => {
    const { base } = fixture();
    const { screen, done } = openPicker({ cwd: base, home: base });
    type(screen(), "./.env");
    screen().handleInput("\r");
    expect(done).toHaveBeenCalledWith(join(base, ".env"));
  });

  it("Enter on a directory descends rather than confirming", () => {
    const { base } = fixture();
    const { screen, done } = openPicker({ cwd: base, home: base });
    type(screen(), "./src");
    screen().handleInput("\r");
    expect(text(screen())).toContain("./src/");
    expect(done).not.toHaveBeenCalled();
  });

  it("Enter on a missing path says so and keeps the input", () => {
    const { base } = fixture();
    const { screen, done } = openPicker({ cwd: base, home: base });
    type(screen(), "./nope");
    screen().handleInput("\r");
    expect(text(screen())).toContain("no such file");
    expect(text(screen())).toContain("./nope");
    expect(done).not.toHaveBeenCalled();
  });

  it("Enter refuses a path that exists but is not a regular file (F2)", () => {
    const { base } = fixture();
    const { screen, done } = openPicker({ cwd: base, home: base });
    type(screen(), "/dev/null");
    screen().handleInput("\r");
    expect(text(screen())).toContain("not a file");
    expect(done).not.toHaveBeenCalled();
  });

  it("Esc cancels with no path", () => {
    const { base } = fixture();
    const { screen, done } = openPicker({ cwd: base, home: base });
    type(screen(), "./.env");
    screen().handleInput("\x1b");
    expect(done).toHaveBeenCalledWith(undefined);
  });

  it("never renders a value from the file it is pointing at (F6)", () => {
    const { base } = fixture();
    const { screen } = openPicker({ cwd: base, home: base });
    type(screen(), "./.env");
    screen().handleInput("\r");
    expect(text(screen())).not.toContain(CANARY);
    expect(text(screen())).not.toContain("CANARYCANARY");
  });
});

describe("the assignment list", () => {
  beforeAll(() => initTheme("dark"));

  const rows = (): ChoiceRow[] => [
    { id: 0, label: "github_token", likely: true, disabled: false },
    { id: 1, label: "stripe_key", likely: true, disabled: false },
    { id: 2, label: "2fa_token", note: "can't auto-name: starts with a digit", likely: true, disabled: true },
    { id: 3, label: "port", likely: false, disabled: false },
    { id: 4, label: "log_level", likely: false, disabled: false },
  ];

  it("shows the likely secrets, with markers and reasons", () => {
    const { screen } = openChooser(rows());
    const shown = text(screen());
    expect(shown).toContain("github_token");
    expect(shown).toContain("stripe_key");
    expect(shown).toContain("• likely secret");
    expect(shown).toContain("can't auto-name: starts with a digit");
    expect(shown).toContain("7 assignments · 3 look like secrets");
    expect(shown).not.toContain(CANARY);
  });

  it("hides the rows the classifier did not call secrets, and says so", () => {
    // The 2026-10-08 correction: a real ~/.bashrc put PS1, HISTSIZE and friends in this list, and
    // 34 rows of shell settings made it unusable.
    const { screen } = openChooser(rows());
    const shown = text(screen());
    expect(shown).not.toContain("port");
    expect(shown).not.toContain("log_level");
    expect(shown).toContain("TAB show all 5");
  });

  it("TAB reveals every row, and TAB again puts them back", () => {
    const { screen } = openChooser(rows());
    screen().handleInput("\t");
    const all = text(screen());
    expect(all).toContain("port");
    expect(all).toContain("log_level");
    expect(all).toContain("TAB likely only (3)");
    screen().handleInput("\t");
    expect(text(screen())).not.toContain("port");
  });

  it("TAB lands on the first row it revealed, so the change is visible", () => {
    // Re-listing alone would leave the same screenful in place — the likely rows sort first — and
    // the user would have to scroll to find out whether TAB did anything.
    const { screen } = openChooser(rows());
    screen().handleInput("\t");
    const lines = text(screen()).split("\n");
    // `Text` is rendered with one column of padding, so the pointer is not at index 0.
    const pointerRow = lines.find((l) => l.trimStart().startsWith("▸"))!;
    expect(pointerRow).toContain("port");
    expect(pointerRow).not.toContain("• likely secret");
  });

  it("shows everything when nothing at all is likely — an empty screen helps nobody", () => {
    const none: ChoiceRow[] = [
      { id: 0, label: "port", likely: false, disabled: false },
      { id: 1, label: "log_level", likely: false, disabled: false },
    ];
    const { screen, done } = openChooser(none);
    const shown = text(screen());
    expect(shown).toContain("port");
    expect(shown).toContain("log_level");
    // With nothing hidden there is no toggle to offer.
    expect(shown).not.toContain("TAB");
    screen().handleInput(" ");
    screen().handleInput("\r");
    expect(done).toHaveBeenCalledWith([0]);
  });

  it("ticks with space and reports the ids on Enter", () => {
    const { screen, done } = openChooser(rows());
    screen().handleInput(" "); // github_token
    screen().handleInput("\x1b[B");
    screen().handleInput(" "); // stripe_key
    screen().handleInput("\r");
    expect(done).toHaveBeenCalledWith([0, 1]);
  });

  it("counts the selection in the footer", () => {
    const { screen } = openChooser(rows());
    expect(text(screen())).toContain("⏎ add ");
    screen().handleInput(" ");
    expect(text(screen())).toContain("⏎ add 1");
  });

  it("a selects what is visible and addable, and never a hidden row", () => {
    const { screen, done } = openChooser(rows());
    screen().handleInput("a");
    screen().handleInput("\r");
    // 2fa_token is disabled, and port/log_level are hidden: only 0 and 1 are reachable.
    expect(done).toHaveBeenCalledWith([0, 1]);
  });

  it("a after TAB reaches the hidden rows too, because now they are visible", () => {
    const { screen, done } = openChooser(rows());
    screen().handleInput("\t");
    screen().handleInput("a");
    screen().handleInput("\r");
    expect(done).toHaveBeenCalledWith([0, 1, 3, 4]);
  });

  it("keeps a tick across the TAB flip, and still reports it", () => {
    const { screen, done } = openChooser(rows());
    screen().handleInput("\t"); // show all, landing on the first revealed row (port)
    screen().handleInput(" "); // tick port
    screen().handleInput("\t"); // back to likely-only, port now hidden
    const shown = text(screen());
    expect(shown).not.toContain("port");
    expect(shown).toContain("⏎ add 1");
    screen().handleInput("\r");
    expect(done).toHaveBeenCalledWith([3]);
  });

  it("refuses to tick a disabled row", () => {
    const { screen, done } = openChooser(rows());
    screen().handleInput("\x1b[B");
    screen().handleInput("\x1b[B"); // onto the disabled row
    screen().handleInput(" ");
    screen().handleInput("\r");
    expect(done).toHaveBeenCalledWith([]);
  });

  it("n clears the selection", () => {
    const { screen, done } = openChooser(rows());
    screen().handleInput("a");
    screen().handleInput("n");
    screen().handleInput("\r");
    expect(done).toHaveBeenCalledWith([]);
  });

  it("Enter with nothing ticked adds nothing", () => {
    const { screen, done } = openChooser(rows());
    screen().handleInput("\r");
    expect(done).toHaveBeenCalledWith([]);
  });

  it("Esc cancels the flow", () => {
    const { screen, done } = openChooser(rows());
    screen().handleInput(" ");
    screen().handleInput("\x1b");
    expect(done).toHaveBeenCalledWith([]);
  });
});
