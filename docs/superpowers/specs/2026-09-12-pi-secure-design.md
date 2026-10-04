# pi-secure — design

**Status:** approved design, pending implementation plan
**Date:** 2026-09-12
**Threat model:** the logging LLM endpoint

## 1. Purpose

Keep credentials out of everything an LLM endpoint can see — request bodies, session
files, transcripts, exports — while letting the model *use* those credentials in shell
commands and tool calls without friction.

The user should never have to paste a token into a conversation, and if they do, it
should not end up in the conversation.

### What we are defending against

A model endpoint that **records** what you send it: a reseller, a random
OpenAI-compatible proxy, a gateway with retention, a human reviewing logs. The token
must simply never be in the bytes that leave the machine, nor in the transcript that
would reveal it on a later turn.

### What we are explicitly *not* defending against

An endpoint that **actively attacks you** by steering the model to exfiltrate. That is
not solvable at this layer, and pretending otherwise is worse than saying so:

- `bash` gives the model (and therefore its puppeteer) full read access as your user:
  `~/.aws/credentials`, `~/.ssh`, `~/.pi/agent/auth.json` (pi's own provider keys),
  any `.env` in the repo.
- A ref is a capability handle. Anyone who can direct the model can spend it, and can
  reconstruct any secret by slicing it in a shell (`printf '%s' "$VAR" | cut -c1-8`),
  because redaction matches whole known values.
- pi ships **no sandbox** by design (see `docs/security.md`).

For an actively hostile endpoint the answer is a sandbox boundary with egress
substitution — pi's own `sbx` pattern, where the container receives a *host-bound*
sentinel and the proxy swaps the real credential on egress. pi-secure is a
complement to that, not a substitute. See §12.

## 2. Design constraints from the user

1. **The model must compose freely.** It learns exactly one syntax and no environment
   conventions. Mechanisms invisible to the model are preferred over mechanisms it must
   remember.
2. **Only `a` + `b` consumption paths:** shell commands and tool arguments. Secrets are
   never materialized into files.
3. **Ambient credentials are not policed.** Anything already reachable via `env` or a
   file is the model's to use, ungated — the model is capable of judging it, and
   gating what you cannot protect is only friction. Shape-scrubbing (§8) still masks
   such values *on the way back*, since masking blocks nothing.
4. **TUI-entered secrets live for one session only.** Never persisted, never reused
   across `/new`, `/fork`, `/resume`.
5. **Capture is a move, not a delete** — non-destructive, interrupting nothing.

## 3. Verified pi mechanics this design rests on

All confirmed against the installed build, not assumed. Implementation must not
proceed if a check fails.

| Fact | Location | Why it matters |
|---|---|---|
| `tool_call` receives a `structuredClone` of the model's args | `pi-ai/dist/utils/validation.js:281` → `agent-loop.js:284,304` | Mutating `event.input` cannot reach the persisted `toolCall` block. Injection is invisible on disk. |
| `tool_result` hook runs before the result message is built/persisted | `agent-session.js:244-266` | Scrubbing at write time propagates to every downstream consumer. |
| `tool_execution_start` emits `toolCall.arguments`, not the mutated clone | `agent-loop.js:298-303, 334-339` | Live TUI renders the ref, never the value. |
| `tool_execution_update` emits original args **and the raw partial result** | `agent-loop.js:459-473` | Streamed *args* are safe; streamed *output* is **not** — partials bypass `tool_result` and render live, so the wrapped bash tool must scrub them (see §4 row 6b, §10). |
| TUI renders call args from the message content block | `interactive-mode.js:2630, 3019` | Same for restored sessions and `/export`. |
| `input` transforms happen before skill/template expansion **and** before persistence | `agent-session.js:843-852` | Capture-at-input means the value never touches the session file. |
| The `context` hook is wired only via the agent's `transformContext` | `sdk.js:227-231` | It is **not** on the compaction path. |
| Compaction/branch summarization bypasses `context` | `branch-summarization.js:224-226` | Write-time scrubbing is load-bearing, not defense-in-depth. |
| `ctx.ui.input()` has no masked mode | `extensions/types.d.ts:74` | Masked entry requires a `ctx.ui.custom()` component. |

**Hazard:** `tool_result` handlers receive `input: args` — the **mutated** clone, which
*does* contain real values. Nothing may interpolate `event.input` into an error string
or log line.

## 4. Architecture

Three modules; `substitute`/`scrub` are pure and carry all the security-relevant logic.

```
input ───────► [5] capture ──┐
tool_call ───► [3] inject ───┼──► [1] vault  Map<name, {value, addedAt, fp, len}>
tool_result ─► [4] scrub ◄───┘         ▲
context ─────► [4] scrub ──────────────┘
before_provider_request ► [4] scrub (last mile)

[2] ui: /sec add|list|remove|rename|test|restore|off|on  +  masked prompt  +  receipt
```

- **[1] vault** — `Map` on `globalThis.__PI_SECURE__`, keyed by session file. Memory
  only; no serializer ever sees it. API: `add`, `remove`, `has`, `resolve`, `names`,
  `values` (called only by the scrubber).
- **[2] ui** — masked prompt via `ctx.ui.custom()` (renders `•`, accepts bracketed
  paste, shows length + fingerprint on confirm); `/sec` command family; transcript
  receipt entries.
- **[3] inject** — wrapped `bash` tool (`createBashToolDefinition(cwd, { spawnHook })`)
  plus a generic `tool_call` deep-walk for non-shell tools.
- **[4] scrub** — value-exact and shape-based masking of text at three points:
  `tool_result` (disk + display + context), `context` (last mile for non-tool content),
  `before_provider_request` (bytes leaving the machine). Also rewrites the bash
  truncation temp file.
- **[5] capture** — `input` handler: detect, vault-add, transform text to a ref,
  emit a receipt.

Pure helpers in `substitute.ts` / `scrub.ts`: `findRefs`, `expandBash` (quote-aware),
`maskValues`, `maskShapes`, `fingerprint`. No I/O, table-driven, unit tested.

## 5. Model-facing contract

One rule, delivered as `promptGuidelines` on the `sec_list` tool (guidelines are
included only while the tool is active, and must name the tool they refer to):

- Reference credentials as `{{sec:NAME}}` in bash commands and tool arguments. The
  value is substituted at execution time and is never visible to you.
- Use `sec_list` to see available names. Never ask the user to paste a secret, token,
  password, or API key.
- If a `sec:` reference is rejected, call `sec_list` and retry with a valid name.

`{{sec:NAME}}` chosen over `$sec:NAME` (collides with shell expansion) and over env
indirection exposed to the model (violates constraint 1).

**Round-trip property:** masking replaces a value with **the ref**, not `***`. When a
command echoes a token or an error page dumps one, the model reads back
`Authorization: Bearer {{sec:gh_token}}` and can paste that straight into its next
command. Masking that the model cannot reuse would force it to ask you again.

**Unknown ref** → `{ block: true, reason: "sec:gh_token not found. Available: sec:gh_pat, sec:db_url. (Values are never shown.)" }`.
Names are not secrets, so the error is maximally useful and self-correcting in one
round trip.

**Discovery:** read-only `sec_list` tool returning name, length, fingerprint, `addedAt`,
and whether it came from this session. Never values. Human-side `/sec` and `{{sec:`
autocomplete via `addAutocompleteProvider`.

## 6. Ingest

### 6.1 Masked prompt — `/sec add [name]`

`ctx.ui.custom()` component: characters render as `•`, never echoed via `notify`, never
written to a custom entry. On confirm, show `len` + `sha256:xxxx` so a truncated key or
stray newline is visibly wrong. `/sec test NAME` reprints that fingerprint — the only
way to answer "did I capture the right thing?" without echoing.

Lifetime: this session only (§7). Consent: **silent resolve** — the user typed it, so
intent is fresh and implicit.

### 6.2 Capture — paste into the conversation

The primary, most natural path. Type normally, hit Enter, and the credential becomes a
handle:

```
you:  use this for the staging deploy: ghp_A1b2C3d4E5f6G7h8I9j0

      → value moves into the vault as sec:gh_staging_token

you:  use this for the staging deploy: {{sec:gh_staging_token}}   ← what is persisted & sent

      ⛨ captured sec:gh_staging_token · len 40 · sha256:9c3f
```

Non-destructive, non-blocking: **no confirm dialog on the high-confidence path.** The
message still goes to the model, now holding a usable ref, so the workflow continues
without a keystroke. Implemented in the `input` handler returning
`{ action: "transform", text }`.

Detection, in confidence order:

- **Anchored prefixes** (capture silently): `ghp_`, `github_pat_`, `gho_`, `sk-ant-`,
  `sk-`, `AIza`, `AKIA`/`ASIA`, `xox[baprs]-`, `glpat-`, `npm_`, `pypi-Po-`, `hf_`,
  `dckr_pat_`, `eyJ` JWTs, PEM blocks.
- **Key/value shape**: a credential-ish key name (`token`, `secret`, `password`,
  `passwd`, `api[_-]?key`, `authorization`) followed by a high-entropy run.
- **Bare high-entropy** (len ≥ 20, mixed character classes, Shannon > 4.0): **confirm
  first.** This is where we will be wrong, and an unwanted silent rewrite of the user's
  own words is the one destructive outcome.
- **Never capture:** 40-char lowercase hex (**git SHAs** — capturing these would make
  the extension actively harmful to normal work), 64-char hex, UUIDs, semver, file
  paths, URLs, `node_modules` fragments, and anything already matching `{{sec:…}}`
  (re-sending an old transcript line must not re-capture).
- Multi-secret messages: capture each, distinct names.
- Auto-naming derives from provider prefix plus nearby context words
  ("github" + "staging" → `gh_staging_token`); collisions append `-2`. A wrong guess is
  cheap to fix (`/sec rename`) and never blocks.
- Idempotence: if the value already exists in the vault, reuse that name.

**Receipt is a transcript entry, not a notification.** `pi.appendEntry` +
`registerEntryRenderer` puts a dim line where it happened — visible in scrollback, on
resume, in `/export`, and auditable later. `notify()` alone vanishes in seconds, and a
capture the user cannot audit is one they'll stop trusting. The entry stores only
name/length/fingerprint.

**Restore is the escape hatch that makes silent capture safe.** `/sec restore NAME`
copies the value to the **clipboard** — never into chat, never into a tool result, and
deliberately never into the editor buffer. That last exclusion is a correction made
during implementation review: `ctx.ui.setEditorText()` places text in the input that the
user submits, so prefilling it would write the secret straight back into the session
transcript and undo the entire feature. Clipboard-only keeps the escape hatch usable
while leaving no path for a prefilled submit to re-leak the value. There is **no `sec_reveal` tool**, and the tool registry must never gain
one: restore is a user command path, not something the model can invoke.

### 6.3 Out of scope: ambient sources

`env` passthrough, `!op read` / keychain command sources, and file sources are dropped
(constraints 3 + §1). pi-secure holds *only* what you give it this session. A secret
that also lives in `process.env` remains reachable as `$NAME`; adopting it is a
user-side act (stop exporting it, then `/sec add`).

## 7. Lifetime

"Session" = one session file.

- **Survive:** `/reload`, and any in-session turn. Because pi re-evaluates the extension
  module on reload and destroys ordinary module state, the vault hangs off `globalThis`
  keyed by session-file path, and a new instance reclaims its own key.
- **Drop on:** `/new`, `/fork`, `/resume`, process exit. Cleared in `session_shutdown`
  for those reasons.
- **Never written to:** session JSONL, custom entries, tool `details`, logs, temp files.

If a ref is used after the vault lost it, the masked prompt fires at that moment — the
cost of a lifetime boundary is one re-entry, not a broken turn.

## 8. Scrubbing

Two independent matchers. §8.1 applies to every text block at all three points in §4;
§8.2 applies to the same points with one scope limit, stated in that section.

### 8.1 Value-exact (vault contents)

For each vault value: replace all occurrences with `{{sec:NAME}}`. Also mask
`base64(value)` and `hex(value)` since tools echo those. Matching is a
length-descending literal sweep — vault size is single digits, no automaton needed.

Minimum-length guard (≥ 8) to avoid a short value chewing up unrelated text.

**Prefix-variant rule:** if a longer secret's leading 12+ chars match a shorter
candidate, mask the *longer* first, and never emit a masked ref from a prefix of a
different secret. This closes the "prefix oracle" — otherwise the transcript would
contain a searchable hash of a real key, letting anyone with the file confirm guesses.
The only stored derived form is 4 hex chars of `sha256(value)`, and only for the
user-visible fingerprint, never as a matcher key.

### 8.2 Shape-based (the logger win)

Mask credential-shaped strings regardless of provenance. This is what covers the
`env` and `~/.aws/credentials` reads that value-exact can't see, and it is what makes
the design actually serve §1 for a logging endpoint.

Same anchored-prefix list as §6.2, plus PEM blocks and `key=<high-entropy>`, applied to
*inbound* text only (tool results, resumed history, provider payload). No grants, no
blocks — masking on return costs the model nothing it couldn't still do with the value.

**Scope limit, and why: `read` and `grep` results are excluded by default.** Heuristic
masking of *file contents* breaks the edit round-trip. If `read ~/.aws/credentials`
returns `aws_secret_access_key = {{se...dacted}}`, then (a) no later `edit` `oldText` can
ever match that line, and (b) a full-file `write` would persist the mask **over your real
directive, silently destroying it** — with §9 blocking refs in write paths, the model
would instead get wedged. Heuristic matching is a guess, and a guess must not be allowed
to alter bytes the user may need to write back. Value-exact masking (§8.1) still applies
in `read`/`grep`, because that value came to us from the user this session and they can
re-enter it.

The knob `scrubFileReads` (default `false`) flips this on for users who rate logger
protection over round-trip fidelity; when it is `true`, §9's write/edit block is what
prevents the corruption above, at the cost of the model being unable to `edit` a
credential-bearing file at all.

Accepts two trade-offs, deliberately:
- **False positives** on random hashes and doc snippets — mitigated by the same denylist
  as §6.2 (git SHAs especially; pi prints them constantly) and by the `read`/`grep`
  exclusion above. The `sk-` prefix is the loosest pattern and the most likely to fire on
  prose; it is matched only with a following 20+ char alphanumeric run.
- **Ineffective against transformation** — `base64` of a file, `cut` slices, and hashes
  of secrets pass through. Shape matching is hygiene, not a boundary.

Masked shapes with no vault match become `{{sec:redacted}}` so the transcript reads
honestly rather than showing a phantom handle. The model can't *use* that ref — by
design, since it never entered the vault.

### 8.3 Ordering

`tool_result` scrubbing is the **primary** guarantee, not a backstop: because it runs
before the result message is persisted (§3), the on-disk transcript, `/export`, resumed
sessions, and compaction summaries all inherit clean content. `context` and
`before_provider_request` catch content that entered by another route — pre-existing
sessions from before pi-secure was installed, injected extension messages, and
anything produced on a path that skips tool hooks.

## 9. Enforcement rules

| Path | Ref present | Action |
|---|---|---|
| `bash` command | yes | expand via env indirection (§10) |
| `write` / `edit` content | yes | **hard block** — would store the literal `{{sec:…}}` text and silently corrupt the file |
| `read`, `grep`, `find`, `ls` | yes | **hard block** — refs have no meaning as paths/patterns here |
| other custom tools | yes | expand in-place into `event.input` |
| `bash` redirect (`> .env`, `tee`) | yes | **notify-only** — command runs; user sees a `ctx.ui.notify` warning |
| any tool | value appears in output | masked by §8 |

Bash redirects are warn-only because blocking them breaks legitimate commands
(`printf '%s' {{sec:x}} > ~/.netrc` is a real thing to want), and the file it lands in is
outside our protection anyway. The warning goes **only to the user, never into model
context**: a model told "your command wrote a masked ref to a file" reliably tries to fix
it by rewriting the file, which is the corruption we are avoiding.

The `write`/`edit` block reason is written so the model stops instead of routing around
it:

> `sec refs are not written to files (the literal text would be stored). Materializing
> secrets into files is out of scope. If this value came from a scrubbed tool result,
> tell the user where it needs to go and let them place it.`

## 10. Injection mechanics

Two paths, deliberately different.

**bash** — the built-in tool is replaced by re-registering
`createBashToolDefinition(cwd, { spawnHook })` under `bash` (the documented pattern;
`examples/extensions/bash-spawn-hook.ts`). The wrapper must **carry over** that
definition's `promptSnippet`, `promptGuidelines`, `renderCall`, and `renderResult` so the
only observable change to the model is that refs work. The spawnHook receives `{command, cwd, env}`
and returns a rewritten command plus env. This keeps the value out of the command text
*entirely*, which also keeps it out of shell history, `/proc/*/cmdline` for the shell
itself, and any error that echoes the command.

**everything else** — `tool_call` deep-walks `event.input` (objects, arrays, nested) and
replaces ref substrings with the resolved value. There is no process boundary to hide
behind, so we accept the value in memory and rely on §3: the persisted block is
untouched.

### Quote-awareness (the fiddly part)

The bash rewriter must understand shell quoting. `{{sec:x}}` inside **single quotes**
does not expand, so a naive swap to `$__PISEC_X` yields the literal string at runtime —
a silent, confusing failure. Correct transform:

```
'Authorization: Bearer {{sec:gh}}'  →  'Authorization: '"$__PISEC_GH"''
"…{{sec:gh}}…"                       →  "…${__PISEC_GH}…"
{{sec:gh}} (unquoted)                →  "$__PISEC_GH"
heredoc body                         →  ${__PISEC_GH} (only in unquoted-delimiter heredocs)
```

Env var names: `__PISEC_` + the uppercased entry name sanitized to `[A-Z0-9_]`
(**untruncated** — `isValidName` already caps names at 64) + `_` + 16 hex of
`sha256(name)`, so at most 89 characters and always a valid POSIX identifier. Secret
names are public in the transcript and Task 6 derives them from model-steerable text,
so the tag must resist a *targeted* second preimage: 32 bits was not enough (a
40-char window plus an 8-hex tag made `"x"`×45+`"4a5"` and `"x"`×45+`"1y32"` collide,
a ~2^16 walk). Both places a name enters the vault — `add()` and `rename()` — refuse a
collision. A ref whose name is not in the vault is never silently dropped — see §11.

If a ref sits in a position where expansion cannot happen (single-quoted heredoc with a
quoted delimiter, inside `$(printf '%q')`, etc.), **block with a reason** rather than
executing a command that would send the literal placeholder.

## 11. Error handling

- Unknown ref → block, list valid names, never values.
- Empty/whitespace captured value → rejected at ingest. A captured `""` is a footgun.
- Ref on a name the vault lost after `/reload` → masked prompt at point of use.
- Value > 1 MiB → rejected with a hint that this looks like a file, not a token.
- Scrub pass must never throw into the agent loop; on internal error, log the *class*
  of failure (not the content) and fail **closed** for that text block: replace with
  `{{sec:redacted}}`.
- `sec_list` and all receipt/fingerprint paths must be value-free by construction, not
  by filtering.

## 12. Known gaps (accepted)

1. No defense against an actively adversarial endpoint (§1).
2. Child processes still see values in argv when the model puts a resolved header in an
   argument position (`curl -H "Bearer …"`): visible to your own uid via `ps`.
3. Transformed secrets (`cut`, `base64`, `rev`) escape §8.
4. `!` user-bash paste is **not** captured: the command line is echoed from
   `event.command`, and we can't cleanly rewrite what you already typed. Known hole.
5. Ambient env and on-disk credentials remain readable by design (constraint 3), except
   where §8.2 happens to mask them.
6. A heap core dump can contain vault values; same as any in-process secret store.
7. `/name` session names and entry labels are not scrubbed — you typed those.
8. **A secret value becomes *code* when interpolated into a string a second shell
   parses.** Env delivery is safe within one shell: bash never re-expands the result of
   parameter expansion, so `printf '<%s>' $VAR` only word-splits a value containing
   `$(...)` (measured). It is **not** safe through a nested shell - `sh -c "echo $VAR"`,
   `bash -c`, `eval`, `ssh host "..."`, `docker exec ... sh -c` take the expanded value
   as *source*, and a value containing `$(...)` executes (measured: both the `sh -c` and
   `eval` variants created a marker file). The model cannot see values, so it cannot
   craft one; exposure needs a user-supplied secret containing shell metacharacters, or
   a model talked into piping a ref through `sh -c`/`eval`. Mitigated by guideline, not
   by detector: reliably parsing shell is what this project's lexer has repeatedly failed
   at, and a fragile nested-shell detector would produce false blocks that read as
   pi-secure being broken.
9. **(Closed by Task 15's phase-2 single-pass scanner.)** ~~~ Bash lexical coverage is bounded by a two-scanner design, and three shapes are knowingly left open until Task 15.~~~ Historical record: delimiters must currently match `[A-Za-z_][A-Za-z0-9_]*`, but
   bash accepts any unquoted word: `cat <<1`, `cat <<E-O-F`, `cat <<EOF.txt` all run, and their
   bodies are then not excluded from quote tracking — with an even apostrophe count that is the
   silent-non-delivery class again. `# cat <<EOF` is a comment in bash and registers an operator
   here. And `$((m<<k))` is safe today only by accident: the narrow delimiter charset is the
   single thing preventing it from matching as a heredoc operator, which is why widening the
   charset must land in the same change as an arithmetic/comment context guard rather than on
   its own. Severity: correctness and availability, not confidentiality — a mis-lexed command
   either fails, or receives the literal variable name while the secret stays in the child
   environment. The reason not to leave it permanently: a model whose `{{sec:x}}` echoes back as
   `$VAR` will try to fix it, and the obvious fix is asking the user to paste the token into a
   command — the one path this design exists to close.
10. **Two shape-masking limits are chosen, not accidental.** (a) A *raw* secret folded across
    lines by `fold`/`fmt` is not caught: whitespace-tolerant matching applies only to the derived
    encodings (base64, base64url, hex), because tolerating it for raw values made an 8-character
    vault entry mask `abc def ghi` out of ordinary prose — `MIN_SCRUBABLE_LENGTH` is 8, so that is
    reachable, and eating output the model needs is its own failure. (b) A key=value credential
    containing `<` or `>` masks up to that character, because a value class that swallows angle
    brackets starts consuming markup. Encoded forms of vaulted values, including line-wrapped
    base64 (`kubectl get secret -o yaml`, `git diff` of a credential file) and either hex case,
    are covered — round 2 measured three leaks in exactly that area before fixing them.
11. **(Closed by Task 16.)** A truncated encoding is now masked: each derived encoding contributes a head-window and a tail-window form, and a window hit masks the whole visible run of the encoding's alphabet. Residual: the mask stops at the first whitespace, so a *wrapped* truncated run is masked only up to the wrap — pinned as a deliberate residual in `test/scrub.test.ts`.

Historical note: `maskForms` used to require the whole derived form to appear, so an *encoded* vaulted secret whose base64 is cut by
    output truncation is left visible: measured, cutting an 88-character encoding at 84 characters
    exposes 94% of it with zero hits. pi truncates to the **last** 5000 lines / 50KB and can return a
    partial last line, so the surviving fragment is typically the tail. This applies only to secrets
    reaching output in *encoded* form (the value itself never appears, since refs keep it in the
    child environment), and only where the encoding was already going to be visible — but it is a
    confidentiality gap, so it is scheduled ahead of the tasks that consume scrubbing rather than
    documented away.
12. **Capture does not understand quotes escaped *inside* a quoted value.** Measured:
    `password="ab\"cd\"` yields no candidate, so nothing is captured. This fails safe — no capture
    means no announcement of protection, and the text behaves as it would without pi-secure — and
    fixing it needs quote-escaping awareness inside the matcher for one shape. Accepted. Capture's
    other known non-matches are deliberate: `password=<placeholder>` (angle brackets excluded,
    because `<your-token-here>` is a template rather than a secret).
13. **With `scrubFileReads: false` (the default), `read`/`grep` on a credential file sends
   raw secrets to a logging endpoint.** This is the largest accepted hole in the design, and
   it is a deliberate trade for file round-trip fidelity (§8.2). Flip the knob if you care
   more about the logger than about editing such files.

## 13. Testing

**The canary sweep is the gate on "safe to use"**, and it is deliberately
path-agnostic: it doesn't care *which* hook leaked, only whether anything did.

1. **Unit, pure:** `expandBash` over a table of quoting/heredoc/multi-ref/adjacent-ref
   cases; §8.1/8.2 matchers including base64/hex variants and the prefix-oracle rule;
   entropy detector against a hostile corpus — 40-hex git SHAs, 64-hex, UUIDs, semver,
   URLs, `node_modules` paths (must **not** match), and one real-format sample per
   anchored prefix (must match).
2. **Integration via the SDK** (`createAgentSession`), not a human in a TUI: drive turns
   where bash echoes `GITHUB_TOKEN`, where a tool result dumps a credential file, and
   where the model writes a `.env` (expect block). Assert the persisted session file,
   the rendered component strings, and the captured provider payload contain `{{sec:…}}`
   and not the canary.
3. **CI invariant:** after every scenario, grep the session dir and temp dir for the
   literal canary. Any hit fails the build.
4. **`/export` and `/resume` round-trip:** capture a secret, export the session to HTML,
   assert the file has no canary — this is the check that catches a leak through a
   rendering path we didn't model.

## 14. Phasing

Suggested build order, each step independently shippable and testable:

1. **P1 — the guarantee:** vault, `/sec add` masked prompt, `expandBash` + spawnHook
   wrapper, `tool_call` expansion, §8.1 value scrubbing on `tool_result`, canary sweep.
   At this point the design does the thing it exists to do.
2. **P2 — the convenience:** capture-on-paste, receipts, `/sec restore`, `sec_list`,
   autocomplete, §9 blocks, `/sec off`.
3. **P3 — the breadth:** §8.2 shape scrubbing + `scrubFileReads`, `context` and
   `before_provider_request` passes, temp-file rewrite, `powershell`.

## 15. Deliberately deferred

`!` user-bash capture · file/keychain/command sources · host-bound refs ·
`/sec export` to a file with an explicit warning · Windows `powershell` wrapper ·
multi-session vault scoping · automatic clipboard clearing after restore.
