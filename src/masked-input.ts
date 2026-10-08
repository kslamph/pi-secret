import type { ExtensionCommandContext } from "@earendil-works/pi-coding-agent";
import { Key, matchesKey } from "@earendil-works/pi-tui";

export interface MaskState {
  buf: string;
  cursor: number;
  status: "editing" | "submit" | "cancel";
}

export function emptyMaskState(): MaskState {
  return { buf: "", cursor: 0, status: "editing" };
}

// Terminal escape sequences: CSI (arrows, home/end, SGR mouse reports, bracketed
// paste), SS3 (F1–F4), and charset/mode selectors. All are keypresses the user did
// not mean as text, and none of them is the cancel key.
const ESCAPE_SEQUENCES = /\x1b\[[0-9;?"<>]*[ -/]*[@-~]|\x1bO[A-Za-z0-9]|\x1b[()][0-9A-Za-z]|\x1b[=>78MDEHc]/g;
const LONE_ESC = /\x1b/g;

const PASTE_ON = "\x1b[200~";
const PASTE_OFF = "\x1b[201~";

function stripFraming(data: string): string {
  return data.replaceAll(PASTE_ON, "").replaceAll(PASTE_OFF, "");
}

function stripNoise(data: string): string {
  return stripFraming(data).replace(ESCAPE_SEQUENCES, "");
}

export function applyInput(state: MaskState, data: string): MaskState {
  if (state.status !== "editing") return state;
  let buf = state.buf;

  if (data === "\x03") return { buf: "", cursor: 0, status: "cancel" };

  // Strip escape sequences FIRST so a lone ESC — the cancel key — stays
  // distinguishable from a sequence we merely do not model. F-keys and charset
  // selectors arrive ESC-prefixed but are not CSI; treating any leftover ESC as
  // "cancel" silently discards a half-typed secret, which is the worst failure
  // Keys are decoded with pi-tui's own matcher FIRST, exactly as pi's components do.
  //
  // This used to be raw byte surgery, and that was wrong in a way a user hit immediately: pi
  // negotiates the kitty keyboard protocol when the terminal supports it, and then a keypress
  // arrives as a CSI-u sequence rather than a bare byte — ESC as `\x1b[27u`, Ctrl+C as
  // `\x1b[99;5u`, Enter as `\x1b[13u`. The old checks missed every one of them and the byte
  // loop then APPENDED the digits to the buffer, so "esc to cancel" did not cancel and Ctrl+C
  // typed characters into the secret. `matchesKey` handles both encodings, and is the library's
  // canonical path rather than a reimplementation of it.
  if (matchesKey(data, Key.escape) || matchesKey(data, Key.ctrl("c")) || matchesKey(data, Key.ctrl("d"))) {
    return { buf: "", cursor: 0, status: "cancel" };
  }
  if (matchesKey(data, Key.return)) {
    return { buf, cursor: buf.length, status: "submit" };
  }
  if (matchesKey(data, Key.backspace)) {
    buf = buf.slice(0, -1);
    return { buf, cursor: buf.length, status: "editing" };
  }

  // available here: the user concludes nothing was stored and may paste the token
  // somewhere unprotected instead.
  const cleaned = stripNoise(data);
  if (cleaned === "\x1b") return { buf: "", cursor: 0, status: "cancel" };
  const text = cleaned.replace(LONE_ESC, "");

  const newline = /[\r\n]/.exec(text);
  const head = newline ? text.slice(0, newline.index) : text;

  for (const ch of head) {
    if (ch === "\x7f" || ch === "\b") buf = buf.slice(0, -1);
    else if (ch === "\x03") return { buf: "", cursor: 0, status: "cancel" };
    else if (ch.codePointAt(0)! >= 32) buf += ch;
  }

  if (newline) {
    const tail = text.slice(newline.index).replace(/[\r\n]/g, "");
    buf += tail;
    return { buf, cursor: buf.length, status: "submit" };
  }
  return { buf, cursor: buf.length, status: "editing" };
}

/** Deliberately ignores the value: renders `•` × length plus a live length. */
export function renderMasked(state: MaskState, title: string, width: number): string[] {
  const dots = "•".repeat(state.buf.length);
  const clipped = dots.length > Math.max(0, width - 12) ? dots.slice(-Math.max(0, width - 12)) : dots;
  return [
    title.slice(0, width),
    clipped || " ".repeat(1),
    // The hint must be true for the terminal the user is actually on. Kitty-protocol
    // terminals send ESC as `\x1b[27u`, which is exactly the case the old hint got wrong.
    `len ${state.buf.length} · enter to store · esc or ctrl+c to cancel`.slice(0, width),
  ];
}

export async function promptMaskedSecret(
  ctx: ExtensionCommandContext,
  title: string,
): Promise<string | undefined> {
  if (ctx.mode !== "tui" || !ctx.hasUI) return undefined;
  // `overlay: true` puts this in the same visual family as the built-in dialogs (pi's
  // `ctx.ui.input` for the name, `select`, `confirm`). Without it the component is dropped
  // INTO the editor container, so the two halves of one flow — name, then value — looked like
  // two unrelated pieces of software.
  const result = await ctx.ui.custom<{ value?: string }>((_tui, theme, _kb, done) => {
    let state = emptyMaskState();
    let dirty = true;
    const finish = () => {
      if (state.status === "submit") done({ value: state.buf });
      else done({});
      state = { buf: "", cursor: 0, status: state.status }; // drop the buffer ASAP
    };
    return {
      render(width: number) {
        const lines = renderMasked(state, title, width);
        return lines.map((l, i) => (i === 1 ? theme.fg("toolTitle", l) : theme.fg("muted", l)));
      },
      invalidate() {
        dirty = true;
      },
      handleInput(data: string) {
        const previous = state.status;
        state = applyInput(state, data);
        dirty = true;
        if (state.status !== previous) finish();
      },
      dispose() {
        state = { buf: "", cursor: 0, status: "cancel" };
      },
    };
  }, { overlay: true });
  const value = result?.value;
  return value && value.trim() ? value : undefined;
}
