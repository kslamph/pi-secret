import { envVarName, findRefs, RESERVED_NAME, type SecretResolver } from "../refs.ts";

export interface BashExpansion {
  command: string;
  env: Record<string, string>;
  used: string[];
  missing: string[];
}

export type SpanKind = "sq" | "dq" | "ansq" | "loc" | "comment" | "heredoc" | "arith";

export interface BashLex {
  /** Lexical spans in source order. A position's context is a single lookup
   *  against these (plus `unterminated` for the tail). */
  spans: { kind: SpanKind; start: number; end: number }[];
  /** Non-null when the scan ends inside a quote/heredoc we cannot close;
   *  `index` is the opening character. Anything at or after it sits in a
   *  context the scanner cannot see. */
  unterminated: { kind: SpanKind; index: number } | null;
}

interface Interval {
  start: number;
  end: number;
}

export interface HeredocRegion {
  /** Body text between the operator line and the terminator. */
  start: number;
  end: number;
  /** A quoted delimiter ('EOF' / "EOF" / \\EOF) suppresses parameter expansion. */
  inert: boolean;
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

/**
 * Phase 2 (req 2): a heredoc delimiter is any unquoted WORD, not just an
 * identifier. Measured against bash: `cat <<1`, `cat <<E-O-F` and `cat <<EOF.txt`
 * all print their bodies. A narrow `[A-Za-z_][A-Za-z0-9_]*` class rejected all three,
 * so those bodies were scanned as code and the ref inside them was expanded —
 * the silent-non-delivery class again, just via a different delimiter.
 *
 * The stop set must contain every character bash treats as an operator/separator,
 * so it can never swallow `<`, `|`, `&`, `;`, `(`, `)` or whitespace.
 */
const DELIM_STOP = /[\s|&<>();]/;

/** Matches `<<EOF`, `<<-EOF`, `<<'EOF'`, `<<"EOF"`, `<<\\EOF` at a word position. */

/**
 * Single-pass bash lexical scanner (Task 15 phase 1 extract).
 *
 * One pass over the text, an explicit quote stack, and a `comment` scan mode
 * that records comment spans yet still sees `<<` operators on a comment line —
 * which preserves the *current* (comment-unaware) heredoc behavior exactly.
 * Phase 2 makes operators inside comments inert (req 4) and flips those
 * goldens deliberately; phase 1 changes nothing.
 *
 * The walk maintains:
 *  - a quote stack (sq/dq/ansq/loc) — the only real nesting bash quotes have;
 *  - a list of heredoc body regions, skipped wholesale (every quote character
 *    inside is literal data, and no quote state carries across them);
 *  - `wordStart`, a lexer flag (not a preceding-char lookup) so `#` after `\;`
 *    or `)` stays text and a real word-start `#` opens a comment;
 *  - `cursor`, the next usable body start, so two `<<` on one line get
 *    sequential bodies.
 *
 * Heredoc operators are detected in both code and comment state (never inside a
 * quote or a body), which reproduces the old "swallowed" check for free: a `<<`
 * inside `'…'` is simply never seen as an operator, and a `<<` inside an earlier
 * body is skipped by the body-jump. The `<<<` here-string tail and the
 * `text[p-1] === "<"` guard mirror the old regex's `<<<` handling.
 */
export function scan(text: string): { lex: BashLex; heredocs: HeredocRegion[] } {
  const spans: BashLex["spans"] = [];
  const heredocs: HeredocRegion[] = [];
  const n = text.length;

  // Quote stack. sq/dq/ansq/loc only — `$()` etc. are not tracked as nesting,
  // matching the flat state machine of the code this replaces.
  type QuoteFrame = { kind: "sq" | "dq" | "ansq" | "loc"; open: number };
  const qstack: QuoteFrame[] = [];
  /**
   * Phase 2 (req 3 + the "two different `)`" item): the three ways a `(` opens
   * mean different things, and a flat character set cannot tell them apart.
   *  - `arith`     — `$(( … ))`; a `<<` inside is a SHIFT, not a heredoc operator.
   *  - `subshell`  — `( … )`; the closing `)` ends a word, so `#` after it comments.
   *  - `cmdsubst`  — `$( … )`; the closing `)` does NOT end a word, because the word
   *                  began before the `$(` — measured: `y=$(printf a)#c` does not
   *                  comment, while `(cd .)#c` does.
   */
  const parens: Array<"subshell" | "cmdsubst" | "arith"> = [];
  const inArith = (): boolean => parens.includes("arith");
  /** Next usable heredoc body start (after the most recent terminator line). */
  let cursor = -1;

  let wordStart = true;
  /** True while scanning the tail of a comment line. */
  let inComment = false;
  let i = 0;

  // Attempts a heredoc operator at `i` (text[i] === text[i+1] === "<"). On a
  // real operator it records the body region + span and returns the index just
  // past the operator token; otherwise returns null (the `<<` is ordinary text).
  const tryHeredocOp = (at: number): number | null => {
    const op = parseHeredocOp(text, at);
    // `<<<` here-string tail (or `<<<<…`): the matched `<<` is preceded by a
    // `<`, so it is not a heredoc operator. Skip the `<<` as a text pair.
    if (op && (at === 0 || text[at - 1] !== "<")) {
      const opEnd = at + op.len;
      const opLineEnd = text.indexOf("\n", opEnd);
      if (opLineEnd !== -1) {
        let scan = Math.max(opLineEnd + 1, cursor);
        const bodyStart = scan;
        let bodyEnd = -1;
        let found = false;
        while (scan <= n) {
          const nl = text.indexOf("\n", scan);
          const line = text.slice(scan, nl === -1 ? n : nl);
          // `<<-` strips leading tabs from the terminator line first.
          if ((op.dash ? line.replace(/^\t+/, "") : line) === op.delimiter) {
            bodyEnd = scan;
            found = true;
            cursor = nl === -1 ? n + 1 : nl + 1;
            break;
          }
          if (nl === -1) break;
          scan = nl + 1;
        }
        if (!found) {
          // Unterminated heredoc: bash uses the rest of the input as the body.
          bodyEnd = n;
          cursor = n + 1;
        }
        heredocs.push({ start: bodyStart, end: bodyEnd, inert: op.inert });
        spans.push({ kind: "heredoc", start: bodyStart, end: bodyEnd });
      }
      return opEnd;
    }
    return null;
  };

  while (i < n) {
    // Skip any heredoc body we are currently inside: its quotes are data.
    let jumped = false;
    for (const b of heredocs) {
      if (i >= b.start && i < b.end) {
        i = b.end; // loop will increment past the terminator line's first char
        wordStart = true; // a body ends with \n before the terminator line
        jumped = true;
        break;
      }
    }
    if (jumped) continue;

    const top = qstack[qstack.length - 1];
    const ch = text[i];

    if (inComment) {
      if (ch === "\n") {
        inComment = false;
        wordStart = true;
        i++;
        continue;
      }
      // Phase 2 (req 4): comment text is INERT. bash comments out the rest of the
      // line, so a `<<` on it registers no operator and opens no body. Phase 1
      // honoured it here; that is exactly the behaviour being removed. Measured:
      // `# cat <<EOF` runs line 2 as a command and prints `done`.
      i++;
      continue;
    }

    if (top) {
      // Inside a quote: only the matching closer (or an escape) matters.
      if (top.kind === "ansq") {
        if (ch === "\\") {
          i += 2;
          continue;
        }
        if (ch === "'") {
          spans.push({ kind: "ansq", start: top.open + 1, end: i });
          qstack.pop();
          wordStart = false;
        }
        i++;
        continue;
      }
      if (top.kind === "loc") {
        if (ch === "\\") {
          i += 2;
          continue;
        }
        if (ch === '"') {
          spans.push({ kind: "loc", start: top.open + 1, end: i });
          qstack.pop();
          wordStart = false;
        }
        i++;
        continue;
      }
      if (top.kind === "sq") {
        if (ch === "'") {
          spans.push({ kind: "sq", start: top.open + 1, end: i });
          qstack.pop();
          wordStart = false;
        }
        i++;
        continue;
      }
      // dq
      if (ch === "\\") {
        i += 2;
        continue;
      }
      if (ch === '"') {
        spans.push({ kind: "dq", start: top.open + 1, end: i });
        qstack.pop();
        wordStart = false;
      }
      i++;
      continue;
    }

    // ---- code state ----
    if (ch === "'") {
      qstack.push({ kind: "sq", open: i });
      i++;
      wordStart = false;
      continue;
    }
    if (ch === '"') {
      qstack.push({ kind: "dq", open: i });
      i++;
      wordStart = false;
      continue;
    }
    if (ch === "$" && i + 1 < n) {
      const nx = text[i + 1];
      if (nx === "'") {
        qstack.push({ kind: "ansq", open: i + 1 });
        i += 2;
        wordStart = false;
        continue;
      }
      if (nx === '"') {
        qstack.push({ kind: "loc", open: i + 1 });
        i += 2;
        wordStart = false;
        continue;
      }
      if (nx === "\\") {
        i += 2; // \$ is escaped dollar — word text
        wordStart = false;
        continue;
      }
      if (nx === "(") {
        if (text[i + 2] === "(") {
          // `$(( … ))` arithmetic. Its `<<` is a shift operator, so nothing inside
          // may be read as a heredoc. Two frames because bash writes two open parens.
          parens.push("arith", "arith");
          i += 3;
        } else {
          parens.push("cmdsubst");
          i += 2;
        }
        wordStart = false;
        continue;
      }
      // $ followed by a regular character: word text.
      i++;
      wordStart = false;
      continue;
    }
    if (ch === "\\" && i + 1 < n) {
      // A LINE CONTINUATION is not an escape pair. bash deletes both characters and
      // carries on in the SAME parser state, so `wordStart` must be left untouched;
      // a normal `\<char>` is word text and clears it. Without this split,
      // `echo x \` + newline + `#don't` misses the comment and splices a ref into
      // text bash discards — measured, it prints `x`, same as `echo x #don't`.
      if (text[i + 1] === "\n") {
        i += 2;
        continue;
      }
      i += 2; // escape pair: \<char> is word text, clears wordStart
      wordStart = false;
      continue;
    }
    if (ch === "#" && wordStart && !inArith()) {
      // Comment to end of line. The newline itself stays in code state, and the
      // rest of the line is still scanned (comment mode) so a `<<` on it is seen
      // — preserving the current comment-unaware heredoc behavior.
      const nl = text.indexOf("\n", i);
      const end = nl === -1 ? n : nl;
      spans.push({ kind: "comment", start: i, end });
      if (nl === -1) {
        i = n; // whole tail is comment; nothing more to scan
        break;
      }
      inComment = true;
      i++; // move past '#'; remaining line chars scanned in comment mode
      continue;
    }
    if (ch === "<" && i + 1 < n && text[i + 1] === "<" && !inArith()) {
      const next = tryHeredocOp(i);
      if (next !== null) {
        i = next;
        wordStart = false;
        continue;
      }
      i += 2;
      wordStart = false;
      continue;
    }
    if (ch === "(") {
      parens.push("subshell");
      wordStart = true;
      i++;
      continue;
    }
    if (ch === ")") {
      // The two `)` are NOT interchangeable. Closing a subshell ends a word, so a
      // following `#` comments (measured: `(cd .)#c` comments). Closing a command
      // substitution or arithmetic does not — the word began before the `$(`, so
      // `#` is still mid-word (measured: `y=$(printf a)#c` does NOT comment).
      if (parens.pop() === "subshell") wordStart = true;
      i++;
      continue;
    }
    if (ch != null && WORD_BOUNDARY.test(ch)) {
      wordStart = true;
      i++;
      continue;
    }
    wordStart = false;
    i++;
  }

  // Arithmetic annotation: `$(…)` is ordinary code in phase 1 (req 3 makes it a
  // real context in phase 2), but the span is emitted now so the interface is
  // complete and phase 2's diff is localized. Interior characters are NOT
  // skipped, preserving current behavior exactly.
  for (const a of findArithSpans(text)) {
    spans.push({ kind: "arith", start: a.start, end: a.end });
  }

  const unterminated =
    qstack.length > 0
      ? { kind: qstack[qstack.length - 1]!.kind as SpanKind, index: qstack[qstack.length - 1]!.open }
      : null;

  return { lex: { spans, unterminated }, heredocs };
}

/**
 * Parses a heredoc operator starting at `<<` (text[p] === text[p+1] === "<").
 * Mirrors `<<(-?)[ \t]*(\\?)(['"]?)([A-Za-z_][A-Za-z0-9_]*)\3` — optional `-`,
 * optional whitespace, an optional escaping `\`, an optional opening quote, the
 * delimiter word, and a closing quote matching the opening one — except that the
 * delimiter class is widened to any unquoted word (phase 2, req 2).
 * Returns the delimiter, whether it is inert (quoted/escaped), and the token length
 * consumed (including a closing quote when present).
 */
function parseHeredocOp(
  text: string,
  p: number,
): { delimiter: string; dash: boolean; inert: boolean; len: number } | null {
  let j = p + 2;
  let dash = false;
  if (text[j] === "-") {
    dash = true;
    j++;
  }
  while (j < text.length && (text[j] === " " || text[j] === "\t")) j++;
  let esc = false;
  if (text[j] === "\\") {
    esc = true;
    j++;
  }
  let quote: string | null = null;
  const qc = text[j];
  if (qc === "'" || qc === '"') {
    quote = qc;
    j++;
  }
  const dStart = j;
  // Phase 2 (req 2): ANY unquoted word is a delimiter. The old
  // `[A-Za-z_][A-Za-z0-9_]*` class rejected `1`, `E-O-F` and `EOF.txt`, all of
  // which bash honours — their bodies were then scanned as code and any ref inside
  // was expanded instead of being reported unusable.
  //
  // The stop set MUST also include the delimiter's own quote when one is open.
  // Without that, `<<'EOF'` scans straight through the closing `'` (which is not
  // an operator character), yielding the delimiter `EOF'` and then failing the
  // closing-quote check — i.e. quoted heredocs would stop being recognised at all.
  const isStop = (ch: string): boolean => DELIM_STOP.test(ch) || (quote !== null && ch === quote);
  if (!(j < text.length && !isStop(text[j] ?? ""))) return null;
  while (j < text.length && !isStop(text[j] ?? "")) j++;
  const delimiter = text.slice(dStart, j);
  const close = text[j];
  if (quote) {
    if (close !== quote) return null;
    j++; // consume the closing quote
  }
  return { delimiter, dash, inert: esc || quote !== null, len: j - p };
}

/** Finds `$(…)` arithmetic-ish regions (balanced parens) for span annotation. */
function findArithSpans(text: string): { start: number; end: number }[] {
  const out: { start: number; end: number }[] = [];
  let i = 0;
  while (i < text.length) {
    if (text[i] === "$" && text[i + 1] === "(" && text[i + 2] === "(") {
      let depth = 0;
      let j = i + 1;
      for (; j < text.length; j++) {
        if (text[j] === "(") depth++;
        else if (text[j] === ")") {
          depth--;
          if (depth === 0) break;
        }
      }
      out.push({ start: i, end: j + 1 });
      i = j + 1;
    } else {
      i++;
    }
  }
  return out;
}

/** Public single-pass scanner (Task 15 interface). */
export function scanBash(text: string): BashLex {
  return scan(text).lex;
}

/** Thin compatible wrapper: same shape as before, backed by the single pass. */
export function heredocRegions(text: string): HeredocRegion[] {
  return scan(text).heredocs;
}

export function expandBash(command: string, resolve: SecretResolver): BashExpansion {
  const env: Record<string, string> = {};
  const used: string[] = [];
  const missing: string[] = [];

  const bind = (name: string): string | undefined => {
    const value = resolve(name);
    if (value === undefined) {
      // The reserved marker is exempt, and it is the ONLY exemption: no value is ever
      // behind `{{sec:redacted}}` — it is the text pi-secret itself writes where it
      // masked one — so reporting it as a name that could not be delivered refuses
      // commands that merely quote the syntax. Measured 2026-10-10: two of my own tool
      // calls were refused outright, both of them edits to this project's own tests.
      //
      // Every other unresolvable name is still reported, deliberately: after /resume the
      // vault is a new session's, so a ref carried by the transcript is stale, and
      // running `curl -H 'Bearer {{sec:gh_pat}}'` with a literal placeholder is the
      // false-confidence failure this design treats as its worst case.
      if (name !== RESERVED_NAME && !missing.includes(name)) missing.push(name);
      return undefined;
    }
    const varName = envVarName(name);
    env[varName] = value;
    if (!used.includes(name)) used.push(name);
    return varName;
  };

  const { lex, heredocs } = scan(command);
  const spans = lex.spans;
  const unterminated = lex.unterminated;
  const regions = heredocs;
  const inInertRegion = (index: number): boolean =>
    regions.some((r) => r.inert && index >= r.start && index < r.end);

  const sq: Interval[] = spans.filter((s) => s.kind === "sq").map((s) => ({ start: s.start, end: s.end }));
  const dq: Interval[] = spans.filter((s) => s.kind === "dq").map((s) => ({ start: s.start, end: s.end }));
  const ansq: Interval[] = spans
    .filter((s) => s.kind === "ansq")
    .map((s) => ({ start: s.start, end: s.end }));
  const loc: Interval[] = spans.filter((s) => s.kind === "loc").map((s) => ({ start: s.start, end: s.end }));
  const comments: Interval[] = spans
    .filter((s) => s.kind === "comment")
    .map((s) => ({ start: s.start, end: s.end }));
  const edits: Array<{ start: number; end: number; text: string }> = [];

  for (const ref of findRefs(command)) {
    // §12h: a ref whose name stores nothing is SYNTAX BEING QUOTED — a commit
    // message, a comment, documentation inside a heredoc. Nothing can be denied
    // delivery because there is no value behind the name, so the fail-closed
    // branches below do not apply to it: it passes through as the literal it
    // already is.
    //
    // The scrubber's RESERVED_NAME is NOT excluded here, and that exclusion is what
    // this line used to have. `{{sec:redacted}}` is never backed by a value — it is the
    // text pi-secret itself writes where it masked one — so treating it as a value
    // denied delivery refused any command that merely contained it, including edits to
    // this project's own docs and tests. A masked value headed for a file is still
    // reported, by the user-only redirect warning. The guard (bashRefIssues) filters the
    // same case and the two must agree, or an allow here is undone by the caller's
    // `missing` block.
    const prose = resolve(ref.name) === undefined;
    // A ref inside a comment is text bash DISCARDS — the command runs without it
    // ever being delivered. Expanding it would report the ref as `used` while
    // nothing reaches the child, which is exactly the silent-non-delivery failure:
    // the model believes it passed the token and has no reason to look again. Report
    // it missing so the caller blocks.
    if (comments.some((c) => ref.start >= c.start && ref.end <= c.end)) {
      if (!prose && !missing.includes(ref.name)) missing.push(ref.name);
      continue;
    }
    // A quoted-delimiter heredoc body performs no expansion, so the ref cannot
    // be substituted there. Record it as unusable rather than silently dropping
    // it: the caller blocks on `missing` instead of running a command that would
    // send the literal placeholder.
    if (inInertRegion(ref.start)) {
      if (!prose && !missing.includes(ref.name)) missing.push(ref.name);
      continue;
    }
    // Fail closed: a quote left open means the lexer cannot know where it ends,
    // so any later ref may sit inside quoting we cannot see. bash rejects the
    // command as a syntax error anyway; reporting it here makes the failure
    // ours, and ours is the message the model reads.
    if (unterminated && ref.start >= unterminated.index) {
      if (!prose && !missing.includes(ref.name)) missing.push(ref.name);
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
