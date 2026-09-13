import { envVarName, findRefs, type SecretResolver } from "../refs.ts";

export interface BashExpansion {
  command: string;
  env: Record<string, string>;
  used: string[];
  missing: string[];
}

type State = "code" | "sq" | "dq" | "ansq" | "loc";

interface Interval {
  start: number;
  end: number;
}

interface QuoteScan {
  sq: Interval[];
  dq: Interval[];
  /** ANSI-C spans: $'…'. Bash does not expand parameters inside, so a ref there
   *  can only be delivered by the close-and-reopen splice, like a sq ref. */
  ansq: Interval[];
  /** Locale spans: $"…". Expands like double quotes. */
  loc: Interval[];
  /** Non-null when the scan ends inside a quote; `index` is the opening quote
   *  character. Anything at or after it sits in quoting we cannot see. */
  unterminated: { state: State; index: number } | null;
}

/**
 * Characters that end one bash word and start the next. A `#` after one of
 * these (or at index 0, or after newline/space/tab) begins a comment; `#` in
 * any other position is mid-word text (`echo a#b` stays one word).
 *
 * Measured against /bin/bash: `;|&()` are confirmed comment-start boundaries.
 * `<`, `>`, and `<<<` alike leave `#word` as a comment — `: >#f`, `echo hi >#log`,
 * `: <#f`, `echo hi <#f`, `echo x <<<#f` all exit 2 with no file created, so the
 * redirect is left without a target. Normalised to include `>` for symmetry
 * with `<`: a `#` after either redirect operator is a comment, period.
 *
 * `=` and `$()` are confirmed non-boundaries (`x=#hello` is a value,
 * `echo $(echo 1)#c` prints `1#c`).
 */
const WORD_BOUNDARY = /[( )<>;|&\t\n]/;

export interface HeredocRegion {
  /** Body text between the operator line and the terminator. */
  start: number;
  end: number;
  /** A quoted delimiter ('EOF' / "EOF" / \\EOF) suppresses parameter expansion. */
  inert: boolean;
}

/**
 * Quote spans and lexical context, bash-aware beyond plain quotes:
 *  - Heredoc bodies (both quoted and unquoted delimiters) are skipped entirely:
 *    every quote character inside is literal text, not a delimiter, and no quote
 *    state is carried across the body into the code that follows;
 *  - `#` starts a comment when it starts a word — tracked via a lexer flag
 *    rather than a preceding-character lookup, because `\;` makes the `;`
 *    literal and `( )` are word starts even though they are not in the old
 *    whitespace-only set — and comment text pairs no quotes;
 *  - `$'…'` and `$"…"` are their own spans, closed by the next unescaped
 *    delimiter, so a `"` inside $"…" opens nothing and a `'` inside $'…' closes
 *    only that span;
 *  - An unterminated quote at EOF is reported so `expandBash` can fail-closed.
 */
function quoteIntervals(text: string, heredocBodies: HeredocRegion[] = []): QuoteScan {
  const sq: Interval[] = [];
  const dq: Interval[] = [];
  const ansq: Interval[] = [];
  const loc: Interval[] = [];
  let state: State = "code";
  let open = -1; // index of the opening quote character
  /** True when the next code-state character starts a new bash word. */
  let wordStart = true;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (state === "code") {
      // Heredoc bodies are literal text: every quote character there is data,
      // not a delimiter.  Skip to the end of whichever body we are in.  The
      // terminator line is NOT part of the body region, so it is processed
      // normally (its characters set wordStart as any other code text would).
      //
      // Use find() + outer-loop continue, NOT an inner-loop break: a plain
      // `break` exits only the inner for, then control falls through and
      // evaluates the stale `ch` (the body's first character) at the post-jump
      // index — a body opening with `'` would anchor a phantom sq span. The
      // `continue` here targets this scan loop, skipping that stale-ch
      // evaluation entirely. (Verified: changing `break` to `continue` is a
      // no-op because both target the inner loop — this restructure is
      // required.)
      const body = heredocBodies.find((b) => i >= b.start && i < b.end);
      if (body) {
        i = body.end - 1; // loop will increment past the last body char
        wordStart = true; // body ends with \n before the terminator line
        continue; // req6: never re-process the stale `ch` at the new index
      }
      if (ch === "'") {
        state = "sq";
        open = i;
        wordStart = false; // opening quote is word text
      } else if (ch === '"') {
        state = "dq";
        open = i;
        wordStart = false;
      } else if (ch === "$" && i + 1 < text.length) {
        const next = text[i + 1];
        if (next === "'") {
          state = "ansq";
          open = i + 1;
          i++;
          wordStart = false;
        } else if (next === '"') {
          state = "loc";
          open = i + 1;
          i++;
          wordStart = false;
        } else if (next === "\\") {
          i++; // \$ is an escaped dollar — clears wordStart (word text, req 7)
          wordStart = false;
        } else {
          wordStart = false; // $ followed by a regular character
        }
      } else if (ch === "\\" && i + 1 < text.length) {
        i++; // escape pair: \<char> is word text, so it clears wordStart
             // (req 7 — leaving it inherited lets a later `#` be misread as a
             //  comment start after a preceding boundary like `)`)
        wordStart = false;
      } else if (ch === "#" && wordStart) {
        // Comment to end of line; the newline itself stays in code state.
        const nl = text.indexOf("\n", i);
        if (nl === -1) break;
        i = nl;
        wordStart = true; // newline is a word boundary
      } else if (ch != null && WORD_BOUNDARY.test(ch)) {
        wordStart = true;
      } else {
        wordStart = false;
      }
    } else if (state === "sq") {
      if (ch === "'") {
        sq.push({ start: open + 1, end: i });
        state = "code";
        wordStart = false; // closing quote is word text
      }
    } else if (state === "ansq") {
      if (ch === "\\") i++; // escapes are processed inside $'…'
      else if (ch === "'") {
        ansq.push({ start: open + 1, end: i });
        state = "code";
        wordStart = false;
      }
    } else if (state === "dq") {
      if (ch === "\\") i++;
      else if (ch === '"') {
        dq.push({ start: open + 1, end: i });
        state = "code";
        wordStart = false;
      }
    } else {
      if (ch === "\\") i++;
      else if (ch === '"') {
        loc.push({ start: open + 1, end: i });
        state = "code";
        wordStart = false;
      }
    }
  }
  return { sq, dq, ansq, loc, unterminated: state === "code" ? null : { state, index: open } };
}

/** Matches `<<EOF`, `<<-EOF`, `<<'EOF'`, `<<"EOF"`, `<<\\EOF` at a word position. */
const HEREDOC_RE = /<<(-?)[ \t]*(\\?)(['"]?)([A-Za-z_][A-Za-z0-9_]*)\3/g;

export function heredocRegions(text: string): HeredocRegion[] {
  // Built incrementally: each operator's swallowed-check is computed against
  // quoteIntervals(text, regions), where `regions` holds every body found so
  // far. Operators are examined left-to-right, so every body preceding the
  // current operator is already known — the quote scan skips them, preventing
  // an earlier body's apostrophes from fabricating a span that hides a later
  // `<<` (requirement 5).
  const regions: HeredocRegion[] = [];
  // Just past the previously consumed terminator line; -1 = none consumed yet.
  // Bodies follow their operators in the same left-to-right order, so a second
  // operator on the same command line has its body after the first one's body.
  let cursor = -1;

  HEREDOC_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = HEREDOC_RE.exec(text))) {
    const opStart = m.index;
    // `<<<word` is a here-string; this `<<` is its tail, not an operator.
    if (opStart > 0 && text[opStart - 1] === "<") continue;
    // So is `<<` inside an already-consumed heredoc body: bodies are data.
    if (regions.some((r) => opStart >= r.start && opStart < r.end)) continue;
    // Recompute swallowed per operator: quoteIntervals(text, regions) skips the
    // bodies found so far, so body apostrophes can't pair with later code-state
    // quotes into a phantom span that hides this operator.
    const { sq, dq, ansq, loc } = quoteIntervals(text, regions);
    const isSwallowed =
      sq.some((r) => opStart >= r.start && opStart < r.end) ||
      dq.some((r) => opStart >= r.start && opStart < r.end) ||
      ansq.some((r) => opStart >= r.start && opStart < r.end) ||
      loc.some((r) => opStart >= r.start && opStart < r.end);
    if (isSwallowed) continue;

    const delimiter = m[4] as string;
    const dash = Boolean(m[1]);
    // 'EOF', "EOF" and \\EOF all suppress expansion in the body.
    const inert = Boolean(m[3]) || Boolean(m[2]);
    const opLineEnd = text.indexOf("\n", opStart + m[0].length);
    if (opLineEnd === -1) continue;

    let scan = Math.max(opLineEnd + 1, cursor);
    const bodyStart = scan;
    let bodyEnd = -1;
    let found = false;
    while (scan <= text.length) {
      const nl = text.indexOf("\n", scan);
      const line = text.slice(scan, nl === -1 ? text.length : nl);
      // `<<-` strips leading tabs from the terminator line before comparing.
      if ((dash ? line.replace(/^\t+/, "") : line) === delimiter) {
        bodyEnd = scan;
        found = true;
        cursor = nl === -1 ? text.length + 1 : nl + 1;
        break;
      }
      if (nl === -1) break;
      scan = nl + 1;
    }
    if (!found) {
      // Unterminated heredoc: bash uses the rest of the input as the body (with
      // a warning), so treat the remainder as the body.
      bodyEnd = text.length;
      cursor = text.length + 1;
    }
    regions.push({ start: bodyStart, end: bodyEnd, inert });
  }
  return regions;
}

export function expandBash(command: string, resolve: SecretResolver): BashExpansion {
  const env: Record<string, string> = {};
  const used: string[] = [];
  const missing: string[] = [];

  const bind = (name: string): string | undefined => {
    const value = resolve(name);
    if (value === undefined) {
      if (!missing.includes(name)) missing.push(name);
      return undefined;
    }
    const varName = envVarName(name);
    env[varName] = value;
    if (!used.includes(name)) used.push(name);
    return varName;
  };

  const regions = heredocRegions(command);
  const inInertRegion = (index: number): boolean =>
    regions.some((r) => r.inert && index >= r.start && index < r.end);

  const { sq, dq, ansq, loc, unterminated } = quoteIntervals(command, regions);
  const edits: Array<{ start: number; end: number; text: string }> = [];

  for (const ref of findRefs(command)) {
    // A quoted-delimiter heredoc body performs no expansion, so the ref cannot
    // be substituted there. Record it as unusable rather than silently dropping
    // it: the caller blocks on `missing` instead of running a command that would
    // send the literal placeholder.
    if (inInertRegion(ref.start)) {
      if (!missing.includes(ref.name)) missing.push(ref.name);
      continue;
    }
    // Fail closed: a quote left open means the lexer cannot know where it ends,
    // so any later ref may sit inside quoting we cannot see (the review repro
    // delivered a literal variable name through exactly such a phantom span).
    // bash rejects the command as a syntax error anyway; reporting it here makes
    // the failure ours, and ours is the message the model reads.
    if (unterminated && ref.start >= unterminated.index) {
      if (!missing.includes(ref.name)) missing.push(ref.name);
      continue;
    }
    const varName = bind(ref.name);
    if (varName === undefined) continue; // unknown name: leave the literal ref for the caller to report

    const inHeredoc = regions.some((r) => !r.inert && ref.start >= r.start && ref.end <= r.end);
    const inDq = dq.some((r) => ref.start >= r.start && ref.end <= r.end);
    const inLoc = loc.some((r) => ref.start >= r.start && ref.end <= r.end);
    const inSq = sq.some((r) => ref.start >= r.start && ref.end <= r.end);
    const inAnsq = ansq.some((r) => ref.start >= r.start && ref.end <= r.end);

    if (inSq || inAnsq) {
      // The ONLY edit is at the ref itself: close the quote, splice in the
      // double-quoted variable, reopen. Touching characters around the ref (an
      // earlier draft deleted `ref.start - 1`, the space before it) drops the
      // span's closing quote and yields an unterminated quote — a bash syntax
      // error, not a silent literal.
      //   'A {{sec:x}} B'  ->  'A '"$VAR"' B'
      //   '{{sec:x}} B'    ->  ''"$VAR"' B'       (leading empty quote is correct)
      //   'A {{sec:x}}'    ->  'A '"$VAR"''        (trailing empty quote likewise)
      // $'…' needs the same splice: ANSI-C strings do not expand parameters, so
      // an inline $VAR would deliver the literal variable name.
      edits.push({ start: ref.start, end: ref.end, text: `'"${'$'}${varName}"'` });
      continue;
    }
    // Quote-protected references use the bare `$VAR` form ($"…" expands like
    // double quotes); braces are added only where the name would otherwise be
    // misread — in a heredoc body (no quotes protect it) and wherever a word
    // character follows the ref (`{{sec:x}}suffix` would otherwise read the
    // variable as `VARsuffix`).
    edits.push({
      start: ref.start,
      end: ref.end,
      text: inHeredoc
        ? "${" + varName + "}"
        : inDq || inLoc
          ? /^[A-Za-z0-9_]$/.test(command[ref.end] ?? "")
            ? "${" + varName + "}"
            : `${'$'}${varName}`
          : `"${'$'}${varName}"`,
    });
  }

  let out = command;
  for (const edit of [...edits].sort((a, b) => b.start - a.start)) {
    out = out.slice(0, edit.start) + edit.text + out.slice(edit.end);
  }
  return { command: out, env, used, missing };
}
