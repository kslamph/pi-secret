import type { ExtensionCommandContext } from "@earendil-works/pi-coding-agent";

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
    `len ${state.buf.length} · enter to store · esc to cancel`.slice(0, width),
  ];
}

export async function promptMaskedSecret(
  ctx: ExtensionCommandContext,
  title: string,
): Promise<string | undefined> {
  if (ctx.mode !== "tui" || !ctx.hasUI) return undefined;
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
  });
  const value = result?.value;
  return value && value.trim() ? value : undefined;
}
