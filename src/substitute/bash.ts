import { envVarName, findRefs, type SecretResolver } from "../refs.ts";

export interface BashExpansion {
  command: string;
  env: Record<string, string>;
  used: string[];
  missing: string[];
}

type State = "code" | "sq" | "dq";

interface Interval {
  start: number;
  end: number;
}

/** Single- and double-quoted spans. Escapes matter only inside double quotes. */
function quoteIntervals(text: string): { sq: Interval[]; dq: Interval[] } {
  const sq: Interval[] = [];
  const dq: Interval[] = [];
  let state: State = "code";
  let open = -1;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (state === "code") {
      if (ch === "'") {
        state = "sq";
        open = i + 1;
      } else if (ch === '"') {
        state = "dq";
        open = i + 1;
      } else if (ch === "\\" && i + 1 < text.length) {
        i++;
      }
    } else if (state === "sq") {
      if (ch === "'") {
        sq.push({ start: open, end: i });
        state = "code";
      }
    } else {
      if (ch === "\\") i++;
      else if (ch === '"') {
        dq.push({ start: open, end: i });
        state = "code";
      }
    }
  }
  return { sq, dq };
}

export interface HeredocRegion {
  /** Body text between the operator line and the terminator. */
  start: number;
  end: number;
  /** A quoted delimiter ('EOF' / "EOF" / \\EOF) suppresses parameter expansion. */
  inert: boolean;
}

/** Matches `<<EOF`, `<<-EOF`, `<<'EOF'`, `<<"EOF"`, `<<\\EOF` at a word position. */
const HEREDOC_RE = /<<(-?)[ \t]*(\\?)(['"]?)([A-Za-z_][A-Za-z0-9_]*)\3/g;

export function heredocRegions(text: string): HeredocRegion[] {
  const { sq, dq } = quoteIntervals(text);
  const swallowed = (index: number): boolean =>
    sq.some((r) => index >= r.start && index < r.end) ||
    dq.some((r) => index >= r.start && index < r.end);

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
    // An operator a quote swallows (`echo '<<EOF'`, `echo "<<EOF"`) is plain text.
    if (swallowed(opStart)) continue;
    // So is `<<` inside an already-consumed heredoc body: bodies are data.
    if (regions.some((r) => opStart >= r.start && opStart < r.end)) continue;

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

  const { sq, dq } = quoteIntervals(command);
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
    const varName = bind(ref.name);
    if (varName === undefined) continue; // unknown name: leave the literal ref for the caller to report

    const inHeredoc = regions.some((r) => !r.inert && ref.start >= r.start && ref.end <= r.end);
    const inDq = dq.some((r) => ref.start >= r.start && ref.end <= r.end);
    const inSq = sq.some((r) => ref.start >= r.start && ref.end <= r.end);

    if (inSq) {
      // The ONLY edit is at the ref itself: close the single quote, splice in
      // the double-quoted variable, reopen. Touching characters around the ref
      // (an earlier draft deleted `ref.start - 1`, the space before it) drops
      // the span's closing quote and yields an unterminated quote — a bash
      // syntax error, not a silent literal.
      //   'A {{sec:x}} B'  ->  'A '"$VAR"' B'
      //   '{{sec:x}} B'    ->  ''"$VAR"' B'       (leading empty quote is correct)
      //   'A {{sec:x}}'    ->  'A '"$VAR"''        (trailing empty quote likewise)
      edits.push({ start: ref.start, end: ref.end, text: `'"${'$'}${varName}"'` });
      continue;
    }
    // Quote-protected references use the bare `$VAR` form; braces are added only
    // where the name would otherwise be misread — in a heredoc body (no quotes
    // protect it) and wherever a word character follows the ref (`{{sec:x}}suffix`
    // would otherwise read the variable as `VARsuffix`).
    edits.push({
      start: ref.start,
      end: ref.end,
      text: inHeredoc
        ? "${" + varName + "}"
        : inDq
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
