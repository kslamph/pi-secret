import type { ExtensionCommandContext } from "@earendil-works/pi-coding-agent";
import type { Component } from "@earendil-works/pi-tui";
import { Container, Input, Key, Spacer, Text, matchesKey } from "@earendil-works/pi-tui";
import { DynamicBorder, keyHint } from "@earendil-works/pi-coding-agent";

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
const ESCAPE_SEQUENCES = /\x1b\[[0-9;?:"<>]*[ -/]*[@-~]|\x1bO[A-Za-z0-9]|\x1b[()][0-9A-Za-z]|\x1b[=>78MDEHc]/g;
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

  // Navigation keys are accepted but ignored. The mask keeps the cursor pinned at the end and
  // only the buffer matters, so honoring arrows here would need a second cursor model in the
  // model that owns the value — a larger change than the complaint is worth. The critical
  // part is that these sequences do NOT fall through to the printable filter, where the
  // sequence's digits (`1;1:1A`) would be typed into the secret itself.
  const NAV = [Key.left, Key.right, Key.up, Key.down, Key.home, Key.end, Key.delete, Key.pageUp, Key.pageDown, Key.tab];
  if (NAV.some((k) => matchesKey(data, k))) {
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

/**
 * The mask is applied by feeding the SHARED `Input` component a row of bullets and keeping the
 * real value in our own buffer.
 *
 * The chrome — border, accent title, the input line with its cursor, the key hints — is pi's own
 * `DynamicBorder` / `Text` / `Input` / `keyHint`, assembled in the same order as
 * `ExtensionInputComponent`, which is what `ctx.ui.input` renders for the NAME step of this very
 * flow. Hand-drawing a lookalike was the mistake: it drifted in position (a centred transparent
 * overlay floating over the scrollback) and in style, so one flow read as two applications.
 *
 * The value never reaches a rendered node: the only thing the input line ever holds is bullets.
 * Deliberately absent: any character of the real value, in any intermediate state.
 */
/** The two things the component needs from a theme: colour for accent and plain text. */
export interface MaskTheme {
  fg(color: string, text: string): string;
}

function maskedDialog(theme: MaskTheme, title: string, length: number, bullets: string): Container {
  const input = new Input({ placeholder: "paste is fine — it is never echoed" });
  input.setValue(bullets);
  const container = new Container();
  container.addChild(new DynamicBorder());
  container.addChild(new Spacer(1));
  container.addChild(new Text(theme.fg("accent", title), 1, 0));
  container.addChild(new Spacer(1));
  container.addChild(input);
  container.addChild(new Spacer(1));
  container.addChild(
    new Text(
      `${keyHint("tui.select.confirm", "store")}  ${keyHint("tui.select.cancel", "cancel")}  len ${length}`,
      1,
      0,
    ),
  );
  container.addChild(new Spacer(1));
  container.addChild(new DynamicBorder());
  return container;
}

export async function promptMaskedSecret(
  ctx: ExtensionCommandContext,
  title: string,
): Promise<string | undefined> {
  if (ctx.mode !== "tui" || !ctx.hasUI) return undefined;
  // NOT `overlay: true`. pi's built-in `input`/`select`/`confirm` render into the editor
  // container, at the bottom of the screen; `custom({overlay: true})` centres a transparent
  // panel over the scrollback instead, which is what made this prompt collide with the
  // context block. Same placement, same parts, only the masking is ours.
  const result = await ctx.ui.custom<{ value?: string }>((_tui, theme, _kb, done) => {
    let state = emptyMaskState();
    // The visible view is rebuilt after every keystroke: the only thing the input line ever
    // holds is bullets, so there is no frame in which the value exists in rendered form.
    let view: Component = maskedDialog(theme, title, 0, "");
    let settled = false;
    return {
      render(width: number) {
        return view.render(width);
      },
      invalidate() {},
      handleInput(data: string) {
        if (settled) return;
        const previous = state.status;
        state = applyInput(state, data);
        if (state.status === previous) {
          view = maskedDialog(theme, title, state.buf.length, "•".repeat(state.buf.length));
          return;
        }
        settled = true;
        // Drop the buffer before resolving: it must not outlive the prompt by even one tick.
        const value = state.status === "submit" ? state.buf : "";
        state = { buf: "", cursor: 0, status: "cancel" };
        view = maskedDialog(theme, title, 0, "");
        done(value ? { value } : {});
      },
      dispose() {
        state = { buf: "", cursor: 0, status: "cancel" };
      },
    };
  });
  const value = result?.value;
  return value && value.trim() ? value : undefined;
}
