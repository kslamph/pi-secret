import { describe, expect, it } from "vitest";
import { applyInput, emptyMaskState, renderMasked, type MaskState } from "../src/masked-input.ts";

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
    const state = feed(`${GH}\r`);
    expect(state).toMatchObject({ buf: GH, status: "submit" });
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

  it("ignores arrows, home/end and mouse reports", () => {
    expect(feed("ab", "\x1b[C", "\x1b[A", "\x1b[H", "\x1b[<0;1;1M").buf).toBe("ab");
  });

  it("cancels on escape and ctrl+c without keeping the buffer", () => {
    expect(feed("abc", "\x1b").status).toBe("cancel");
    expect(applyInput(feed("abc"), "\x03").status).toBe("cancel");
  });

  it("ignores other control characters", () => {
    expect(feed("a\x07b\x00c").buf).toBe("abc");
  });
});

describe("renderMasked", () => {
  it("shows bullets only — never the value", () => {
    const state = feed(GH);
    const lines = renderMasked(state, "Value for sec:gh_pat", 60);
    const joined = lines.join("\n");
    expect(joined).not.toContain(GH);
    expect(joined).not.toContain(GH.slice(0, 8));
    expect(joined).toContain("•".repeat(GH.length));
    expect(joined).toContain("40");
  });

  it("shows the title", () => {
    expect(renderMasked(emptyMaskState(), "Value for sec:x", 60).join("\n")).toContain("Value for sec:x");
  });

  it("never exceeds the requested width", () => {
    const lines = renderMasked(feed("z".repeat(300)), "t", 40);
    for (const line of lines) expect(line.replace(/\x1b\[[0-9;]*m/g, "").length).toBeLessThanOrEqual(40);
  });
});

describe("escape handling (regression: a half-typed secret must not be discarded)", () => {
  it("ignores F1–F4 (SS3) instead of cancelling", () => {
    // \x1bOP is ESC-prefixed but is not CSI. Treating any leftover ESC as "cancel"
    // wiped the buffer, so pressing F1 mid-entry threw away what the user typed.
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

/**
 * Reported from the field: "esc to cancel" did not cancel, and Ctrl+C typed characters into
 * the secret instead. Both were the same root cause, and neither was visible in the unit tests
 * because they only ever fed RAW bytes.
 *
 * pi negotiates the kitty keyboard protocol when the terminal supports it, and then keypresses
 * arrive as CSI-u sequences: ESC as `[27u`, Ctrl+C as `[99;5u`, Enter as `[13u`.
 * The old raw-byte checks missed all of them, and the character loop then appended the digits
 * to the buffer — so "esc" inserted "27" and Ctrl+C inserted "99;5u".
 */
describe("keys as they actually arrive in a kitty-protocol terminal", () => {
  const KITTY = {
    escape: "[27u",
    ctrlC: "[99;5u",
    enter: "[13u",
    backspace: "[127u",
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
    const out = applyInput(state, KITTY.enter);
    expect(out.status).toBe("submit");
    expect(out.buf).toBe("ghp_secret");
  });

  it("still handles raw bytes, because the protocol is negotiated per terminal", () => {
    expect(applyInput(emptyMaskState(), "\x1b").status).toBe("cancel");
    expect(applyInput(emptyMaskState(), "\x03").status).toBe("cancel");
    expect(applyInput(emptyMaskState(), "ghp_x\r").status).toBe("submit");
  });

  it("never lets a cancel key leave residue in the buffer", () => {
    for (const key of [KITTY.escape, KITTY.ctrlC, "\x1b", "\x03"]) {
      const out = applyInput({ buf: "partial_secret", cursor: 14, status: "editing" }, key);
      expect(out.buf, JSON.stringify(key)).toBe("");
      expect(out.status).toBe("cancel");
    }
  });

  it("states both cancel keys in the footer, so the promise matches the terminal", () => {
    const footer = renderMasked(emptyMaskState(), "t", 80)[2]!;
    expect(footer).toMatch(/esc or ctrl\+c to cancel/);
  });
});
