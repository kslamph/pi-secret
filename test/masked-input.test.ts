import { beforeAll, describe, expect, it } from "vitest";
import { initTheme } from "@earendil-works/pi-coding-agent";
import { applyInput, emptyMaskState, promptMaskedSecret, type MaskState } from "../src/masked-input.ts";

const GH = "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8";

function feed(...chunks: string[]): MaskState {
  return chunks.reduce((state, data) => applyInput(state, data), emptyMaskState());
}

describe("applyInput", () => {
  it("accumulates typed characters", () => {
    expect(feed("a", "b", "c").buf).toBe("abc");
  });

  it("accepts a pasted token in one chunk", () => {
    expect(feed(GH)).toMatchObject({ buf: GH, status: "editing" });
  });

  it("submits on a trailing newline from a paste and keeps the value clean", () => {
    expect(feed(`${GH}\r`)).toMatchObject({ buf: GH, status: "submit" });
  });

  it("submits on a lone carriage return", () => {
    expect(feed("abc\r")).toMatchObject({ buf: "abc", status: "submit" });
    expect(feed("abc\n")).toMatchObject({ buf: "abc", status: "submit" });
  });

  it("strips bracketed paste framing", () => {
    expect(feed("\x1b[200~" + GH + "\x1b[201~").buf).toBe(GH);
  });

  it("drops carriage returns inside a pasted block", () => {
    expect(applyInput(emptyMaskState(), "abc\r\ndef").buf).toBe("abcdef");
  });

  it("handles backspace including UTF-8 agnostic deletion", () => {
    expect(feed("abc", "\x7f").buf).toBe("ab");
    expect(feed("ab", "\x7f", "\x7f", "\x7f").buf).toBe("");
  });

  it("ignores raw arrow keys, home/end and mouse reports (they are not typed)", () => {
    expect(feed("ab", "\x1b[C", "\x1b[A", "\x1b[H", "\x1b[<0;1;1M").buf).toBe("ab");
  });

  it("ignores navigation keys arriving in kitty CSI form — they must not be typed", () => {
    // In a kitty-protocol terminal arrows/home/end/delete arrive as e.g. "\x1b[1;1:1A" or
    // "\x1b[57419u". These used to fall through the printable filter and type digits.
    for (const key of ["\x1b[1;1:1A", "\x1b[1;1:1B", "\x1b[1;1:1C", "\x1b[1;1:1D", "\x1b[57419u", "\x1b[57421u", "\x1b[57422u", "\x1b[57423u", "\x1b[57424u", "\x1b[3~", "\x1b[5~", "\x1b[6~"]) {
      expect(feed("ab", key), JSON.stringify(key)).toMatchObject({ buf: "ab", status: "editing" });
    }
  });

  it("cancels on escape and ctrl+c without keeping the buffer", () => {
    expect(feed("abc", "\x1b").status).toBe("cancel");
    expect(applyInput(feed("abc"), "\x03").status).toBe("cancel");
  });

  it("ignores other control characters", () => {
    expect(feed("a\x07b\x00c").buf).toBe("abc");
  });
});

describe("escape handling (regression: a half-typed secret must not be discarded)", () => {
  it("ignores F1–F4 (SS3) instead of cancelling", () => {
    const state = feed("abc", "\x1bOP");
    expect(state.buf).toBe("abc");
    expect(state.status).toBe("editing");
  });

  it("ignores charset and mode selectors", () => {
    expect(feed("abc", "\x1b(B").buf).toBe("abc");
    expect(feed("abc", "\x1b=").buf).toBe("abc");
  });

  it("still cancels on a lone ESC", () => {
    expect(feed("abc", "\x1b").status).toBe("cancel");
  });
});

describe("keys as they actually arrive in a kitty-protocol terminal", () => {
  const KITTY = {
    escape: "\x1b[27u",
    ctrlC: "\x1b[99;5u",
    enter: "\x1b[13u",
    backspace: "\x1b[127u",
  };

  it("cancels on kitty-protocol escape", () => {
    expect(applyInput(emptyMaskState(), KITTY.escape).status).toBe("cancel");
  });

  it("cancels on kitty-protocol ctrl+c", () => {
    const state = applyInput(emptyMaskState(), "ghp_secret");
    expect(state.buf).toBe("ghp_secret");
    const out = applyInput(state, KITTY.ctrlC);
    expect(out.status).toBe("cancel");
    expect(out.buf).toBe("");
  });

  it("submits on kitty-protocol enter", () => {
    const state = applyInput(emptyMaskState(), "ghp_secret");
    expect(applyInput(state, KITTY.enter)).toMatchObject({ buf: "ghp_secret", status: "submit" });
  });

  it("still handles raw bytes, because the protocol is negotiated per terminal", () => {
    expect(applyInput(emptyMaskState(), "\x1b").status).toBe("cancel");
    expect(applyInput(emptyMaskState(), "\x03").status).toBe("cancel");
    expect(applyInput(emptyMaskState(), "ghp_x\r").status).toBe("submit");
  });

  it("never lets a cancel key leave residue in the buffer", () => {
    for (const key of [KITTY.escape, KITTY.ctrlC, "\x1b", "\x03"]) {
      expect(applyInput({ buf: "partial_secret", cursor: 14, status: "editing" }, key)).toMatchObject({
        buf: "",
        status: "cancel",
      });
    }
  });
});

/** Drive the real component the way pi's TUI would: render, feed, render, read back. */
describe("the rendered dialog through ctx.ui.custom", () => {
  // The dialog composes pi's own `keyHint`, which reads the interactive theme singleton.
  // pi initializes it at startup; a headless test has to do it explicitly.
  beforeAll(() => initTheme("dark"));
  function harness() {
    let captured: { render: (width: number) => string[]; handleInput: (s: string) => void } | undefined;
    const ui = {
      custom: (factory: never) => {
        captured = (factory as never as (
          tui: unknown,
          theme: unknown,
          kb: unknown,
          done: (v: unknown) => void,
        ) => { render: (n: number) => string[]; handleInput: (s: string) => void })(
          { requestRender() {} },
          { fg: (_c: string, t: string) => t, bold: (t: string) => t },
          {},
          () => {},
        );
        return new Promise<never>(() => {});
      },
    };
    return async function capture() {
      void promptMaskedSecret({ mode: "tui", hasUI: true, ui } as never, "Value for sec:gh_pat");
      await Promise.resolve();
      return captured!;
    };
  }
  const renderPlain = (lines: string[]) => lines.join("\n");
  // The cursor is inverse-video on the first bullet, so it lands inside the run of bullets.
  const stripAnsi = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "");

  it("never renders the secret, only bullets and the length", async () => {
    const capture = harness();
    const component = await capture();
    component.handleInput(GH);
    const lines = stripAnsi(renderPlain(component.render(80)));
    expect(lines).not.toContain(GH);
    expect(lines).toContain("•".repeat(GH.length));
    expect(lines).toContain("40");
  });

  it("shows the title and the cancel hint, built with pi's own key binding names", async () => {
    const capture = harness();
    const component = await capture();
    const lines = renderPlain(component.render(80));
    expect(lines).toContain("Value for sec:gh_pat");
    expect(lines).toMatch(/esc/i);
    expect(lines).toMatch(/ctrl\+c|escape\/ctrl\+c/i);
  });

  it("does not exceed the requested width", async () => {
    const capture = harness();
    const component = await capture();
    component.handleInput("z".repeat(300));
    for (const line of component.render(40)) {
      expect(stripAnsi(line).length).toBeLessThanOrEqual(40);
    }
  });
});
