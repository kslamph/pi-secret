import { scanBash } from "./substitute/bash.ts";
import { findRefs } from "./refs.ts";

/**
 * Detects "this bash command will write a secret REFERENCE to a file" — the one case
 * spec §9 classes as notify-only rather than blocked.
 *
 * Why notify and not block: `printf '%s' {{sec:x}} > ~/.netrc` is a real thing to want,
 * and the file it lands in is outside our protection anyway. Blocking would break a
 * legitimate command to prevent nothing. The warning goes ONLY to the user, never into
 * model context: a model told "your command wrote a masked ref to a file" reliably tries
 * to fix it by rewriting the file, which is the corruption this design avoids.
 *
 * The existing lexer is reused rather than re-implemented. A `>` inside single quotes,
 * inside a comment, or inside a heredoc body is a character, not an operator, and this
 * project has already spent five rounds learning that a second ad-hoc shell scanner is
 * how you get a silent wrong-credential path. So: blank out every region `scanBash`
 * says is not code — preserving offsets — and scan only what remains.
 */

/** The command with every non-code region replaced by spaces, same length, same offsets. */
function codeOnly(command: string): string {
  const lex = scanBash(command);
  const out = command.split("");
  for (const span of lex.spans) {
    if (span.kind === "sq" || span.kind === "dq" || span.kind === "ansq" || span.kind === "loc" || span.kind === "comment" || span.kind === "heredoc") {
      for (let i = span.start; i < span.end && i < out.length; i++) out[i] = " ";
    }
  }
  return out.join("");
}

const DEVICE = /^\/dev\/(?:null|zero|stdout|stderr|tty|fd\/)/;
const isDevice = (path: string): boolean => DEVICE.test(path);

const WORD_END = /[\s|;&()<>]/;

/** The next whitespace-delimited word starting at or after `from`, or undefined. */
function nextWord(text: string, from: number): string | undefined {
  let i = from;
  while (i < text.length && /\s/.test(text[i]!)) i++;
  if (i >= text.length || WORD_END.test(text[i]!)) return undefined;
  let end = i;
  while (end < text.length && !WORD_END.test(text[end]!)) end++;
  return text.slice(i, end);
}

/**
 * Known false positive: inside `[[ … ]]`, `>` is a comparison operator rather than a
 * redirect, so `[[ $a > $b ]]` is reported as writing to a file named after `$b`.
 * Deliberately not handled. A spurious warning is user-visible noise, never a security
 * hole, and teaching the scanner about `[[ ]]` is exactly the fragile-detector work this
 * design has twice declined — a detector that misfires reads as pi-secure being broken.
 *
 * Files this command would write through an output redirect or `tee`.
 *
 * Reports nothing for the forms that write no durable file: descriptor duplication
 * (`2>&1`, `>&2`) and the null device. `>|` (noclobber override) IS a write and is
 * reported.
 */
export function bashWriteTargets(command: string): string[] {
  const code = codeOnly(command);
  const targets: string[] = [];
  const push = (target: string | undefined): void => {
    if (target && !isDevice(target)) targets.push(target);
  };

  for (let i = 0; i < code.length; i++) {
    const ch = code[i]!;

    if (ch === ">") {
      // No need to look at a preceding `&`: the scan is character-by-character, so the
      // `>` of `&>` and of `&>>` is reached like any other.
      let j = i;
      while (code[j] === ">" || code[j] === "|") j++; // `>>`, `>|`, plain `>`
      if (code[j] === "&") continue; // `>&N` duplicates a descriptor: no file involved
      push(nextWord(code, j));
      i = j - 1;
      continue;
    }

    if (ch === "t" && /^tee(?=$|[\s|;&()])/.test(code.slice(i))) {
      // Only as a COMMAND word: `| tee out`, `; tee out`, `(tee out)`. A filename that
      // merely contains "tee" is not a command.
      const before = code.slice(0, i).replace(/\s+$/, "");
      const atCommandStart = before === "" || /[|;&(]$/.test(before);
      if (!atCommandStart) continue;
      const rest = code.slice(i + 3);
      const m = /^\s+(?:-[^\s]+\s+)*(\S+)/.exec(rest);
      push(m?.[1]);
    }
  }
  return [...new Set(targets)];
}

export interface RedirectWarning {
  targets: string[];
  message: string;
}

/**
 * The user-facing warning, or undefined when there is nothing to warn about.
 *
 * Fires only when the command contains a ref: without one, writing to a file is none of
 * this extension's business, and a warning that fires on ordinary redirection is a
 * warning the user learns to ignore — which is how a real one stops being read.
 */
export function bashRedirectWarning(command: string): RedirectWarning | undefined {
  if (findRefs(command).length === 0) return undefined;
  const targets = bashWriteTargets(command);
  if (!targets.length) return undefined;
  return {
    targets,
    message:
      `pi-secure: this command writes a secret REFERENCE (not the value) to ${targets.join(", ")}. ` +
      `That file will contain the literal {{sec:…}} text, which will not work there. ` +
      `Materialising secrets into files is out of scope — if you need the value in that file, ` +
      `run the command yourself.`,
  };
}