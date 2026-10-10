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
| `addAutocompleteProvider` is a **wrapper**, not a registration | `extensions/types.d.ts:62` (`AutocompleteProviderFactory = (current: AutocompleteProvider) => AutocompleteProvider`); pi composes `provider = factory(provider)` from its built-in command/file provider | A factory that ignores `current` does not *add* completion, it **replaces** the chain: `/`-commands, `@`-files and Tab completion all answer `null`. Measured from the field as "the Tab key is broken while this extension is loaded". |
| The stock file-completion provider refuses **absolute** paths | `pi-tui` `autocomplete.js`: `if (!options.force && textBeforeCursor.startsWith("/"))` → command branch. Measured: `"/home/kslam/.pi"` → `null`, `"./node_modules/@earendil"` → 1 item | A path picker cannot reuse `CombinedAutocompleteProvider` for `/…` or `~/…` input — a leading `/` means *slash command*, so dotfiles named absolutely complete to nothing. |
| The kitty keyboard protocol changes the bytes a component receives | `pi-tui` `terminal.js` (protocol negotiation + `StdinBuffer`), `keys.js` (`matchesKey`) | `esc`, `ctrl+c`, `enter` and the arrows arrive as CSI-u (`\x1b[27u`, `\x1b[99;5u`, `\x1b[13u`) or as CSI with `:` parameters (`\x1b[1;1:1A`). Raw byte surgery misses the key **and** types its digits into the buffer. Use `matchesKey`. |
| `custom()` without `overlay` renders in the editor container, like the built-in dialogs | `interactive-mode` `showExtensionInput` (editor-container path) vs `showExtensionCustom`; `overlay: true` centres a transparent panel over the scrollback | A prompt that passes `overlay: true` collides with the context block above it instead of sitting where the built-in `input`/`select` dialogs sit. |

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

**Amended 2026-10-08 — one exception, and why it is not the same thing.** The intent above was
to refuse **ambient** sources: values that become spendable without the user doing anything in
this session. A user-initiated *"read the file I just named, show me its variables, let me tick
the ones to add"* is not ambient — the user names the file, chooses the keys, and nothing is read
until they type a path. §12g specifies it, including the structural rule that keeps it
non-ambient. What stays out: env passthrough, `op read`/keychain/command sources, and any
automatic adoption, watching, or remembering of a file across sessions.

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

`!` user-bash capture · keychain/command sources (`.env` import is now in, §12g) · env
passthrough itself · automatic file adoption, watching or cross-session memory ·
host-bound refs · `/sec export` to a file with an explicit warning · Windows `powershell`
wrapper · multi-session vault scoping · automatic clipboard clearing after restore.

## 12a. Additions from the 2026-10-08 review (three reviewer lanes, all findings adjudicated)

Recorded here rather than in code comments because each is a decision, not an accident.

1. **The shape pass must never mask the interior of an existing `{{sec:…}}`.** Closed.
   It used to be protected only by a `(?!\{\{sec:)` lookahead inside the KV alternative of
   `SHAPE_RE`, so `PREFIX_RE`/`JWT_RE`/`PEM_RE` could still match a ref's own name. A
   secret named `sk-aaaa…` (reachable from `/sec add`) round-tripped to
   `{{sec:{{sec:redacted}}}}`: stable, idempotent, and the name the model needs was gone.
   `maskShapes` now skips any match overlapping an existing ref span — a span check rather
   than one lookahead per branch, because the prefix family has a dozen branches and a
   guard inside one of them silently stops applying to the other eleven.
2. **`details.fullOutputPath` is not model-facing text and must not be masked.** Closed.
   Masking the pointer made `scrubOutputSnapshot` fail its rewrite, and its fail-closed
   branch then deleted the pointer — correct for the model, but it left the *unsanitised*
   snapshot on disk with nothing pointing at it. `ScrubOptions.preserveKeys` exists for this.
3. **`/sec off` semantics are now exact, and the asymmetry is deliberate.** Injection and
   capture follow the switch; `tool_result` scrubbing does not. A bash command containing
   a ref is REFUSED while disabled rather than run with a literal placeholder, because
   `curl -H "Bearer {{sec:gh}}"` would send a bogus header and report success — the
   false-confidence class §1 treats as the worst outcome here.
4. **Accepted, not fixed: `scrubDeep` walks every string leaf of a tool result, including
   an `ImageContent` base64 payload.** The streaming path (`scrubPartial` in
   `tools/bash.ts`) explicitly skips non-text blocks, so the two disagree. A 24-char
   window coincidence inside image bytes is not credible, so the only cost is CPU on
   image-heavy results and a small inconsistency. Recorded rather than fixed because the
   fix is a per-block type check in the generic walker, which would need the walker to
   know about pi's content-block schema.
5. **Bash ownership is decided by real path identity** (`sourceInfo.baseDir` compared
   against this module's own package directory from `import.meta.url`), not a `/pi-secure/`
   substring. A relocated install matches because both sides move together; a different
   extension whose path contains the substring does not, which is the direction that
   matters, since a false positive suppresses the only warning that a rival extension
   took `bash` from us.
6. **Every extension hook must fail CLOSED.** `scrubToolResult` always did; `context`,
   `message_end` and `before_provider_request` did not, and that mattered more than it
   looks: pi's ExtensionRunner wraps every handler in try/catch, calls `emitError`, and
   returns the value it held BEFORE the failing handler ran. An exception there is not a
   crash — it is scrubbing silently skipped on the persisted assistant message and on the
   bytes handed to the provider. `scrubDeep` also no longer recurses (measured: the
   recursive walk died at ~5000 levels with `RangeError`, reachable from a deeply nested
   model-authored tool-call argument), and the three hooks go through `scrubDeepFailClosed`,
   whose fallback over-redacts every string leaf.
7. **A gate that examined nothing has not passed.** `scripts/canary-sweep.mjs` defaulted
   `SWEEP_ROOTS` to `${cwd}/.pi/sessions`, a directory nothing in this repo writes to —
   the integration suite puts every session under `mkdtempSync(tmpdir(), "pi-secure-sessions-")`
   and pi's truncation snapshots are `tmpdir()/pi-bash*`. With `walk()` swallowing a missing
   directory, it printed "canary sweep clean across 1 roots" and exited 0 whether or not
   scrubbing worked. It now defaults to the locations that are actually written, handles
   file roots as well as directories, and **exits 2 when it examined zero files**. That last
   clause is the generalisable rule: a safety gate must be unable to report success by
   inspecting nothing.

### Refuted during adjudication

- *"`DELIM_STOP` omits `#`, so `<<EOF#comment` may misparse."* Measured against
  `/bin/bash`: bash reads the delimiter as the whole word `EOF#comment` and a
  `EOF#comment` terminator line matches it. Our stop set agrees with bash, so there is
  nothing to fix.

## 12b. The two §13 blind spots, closed 2026-10-08 (and what closing them revealed)

§13.4 named `/resume` and §3 named the compaction path as bypasses; neither had a
scenario. Adding them found a Critical and a defect in the gate itself.

8. **(Closed) A compaction summary was persisted with secrets in the clear.**
   `sessionManager.appendCompaction()` writes a `type: "compaction"` entry straight to
   the session JSONL. The summary is model-authored, and it is the ONLY model-authored text
   that never passes through `message_end` — so nothing in this extension saw it before it
   reached disk. Measured: a summary that repeated a vaulted value wrote it verbatim, and it
   survived every later turn, `/export` and `/resume`. This is precisely the case §3's
   "write-time scrubbing is load-bearing, not defense-in-depth" argument claimed to cover,
   and it did not cover it: the `context` hook is bypassed on this path by design
   (`branch-summarization.js:224-226`).
   `scrubCompactionSummaryFile` amends that one JSONL line, and only when `hits > 0`.
   Original bytes are held in memory, the rewrite goes to a temp file and is renamed over
   the target (`appendFileSync(path)` reopens by path, so the inode swap is safe), and the
   result is re-read and verified against the entry count, restoring the original on any
   failure. A half-written session file is worse than a leaky one.
   **Residual, accepted:** `agent.state.messages` keeps the unscrubbed summary for the rest
   of the process, because pi rebuilds it before `session_compact` is emitted. It is never
   persisted and never sent — `context` and `before_provider_request` both scrub outbound —
   and the next context rebuild reads the already-cleaned file. Removing it would mean
   mutating pi's agent state from an extension, which is a larger risk than the residual.
9. **(Gate defect, closed) `before_provider_request` never fired under the canary suite.**
   pi-ai's real provider implementations call `options.onPayload`
   (`api/openai-completions.js:204` and its siblings); the faux provider the suite drives
   never does. Measured with a probe extension: `agent_start`, `context`, `message_end`,
   `tool_call` and `tool_result` all fire, and `before_provider_request` fires ZERO times.
   So "the bytes leaving the machine are scrubbed" — this design's central claim — was
   asserted by nothing, and every scenario was checking files only. The harness now injects
   the callback a real provider would, and the new scenario asserts on what the hook
   RETURNED, non-vacuously: ≥3 payloads captured, no canary on the wire, and the ref
   present so a blackout cannot pass. If pi-ai's faux shape changes, the harness throws
   rather than silently reverting to testing nothing.
   Same shape as the vacuous sweep (§12a item 7): a check that cannot fail. Two of them,
   found the same way — by asking what the check actually executes.
10. **(Fixed) The integration suite read the developer's real settings.** `makeSecureSession`
    created a temp `agentDir` for the resource loader but never passed it to
    `SettingsManager`, which then defaulted to the real `~/.pi/agent`. The suite was
    subject to whatever compaction thresholds, model defaults and provider settings the
    developer happened to have.
11. **`/resume` is now a scenario** (`parseSessionEntries` + `buildSessionContext` — pi's own
    resume path): the rebuilt context carries the ref, never the canary, and the ref is dead
    afterwards rather than silently literal.

## 12c. Design compromises re-examined 2026-08, and what changed

A deliberate pass over the compromises taken while the picture was still forming. Six were
changed; the reasoning is recorded because the *original* arguments were not wrong so much as
miscalculated, and the miscalculation is the part worth keeping.

1. **`--sec-file-reads` was opt-in. Now default-on.** The original argument was sound — masking a
   credential file breaks the read → edit round-trip — and the sizing was wrong, because shape
   masking already applied to every OTHER source of file content. Only `read`/`grep`/`find`/`ls`
   were excluded, and `cat ~/.aws/credentials` through bash was masked all along. The flag was
   closing one side door while leaving the front one open, and §13.3 called that front door the
   largest hole in the design. The flag is now the escape hatch, and a test pins that turning it
   off re-opens `read` but NOT bash — if the knob were wider than its description, the flip would
   have bought nothing.
2. **`/sec off` was a half-switch. It now clears the vault.** Injection and capture stopped, but
   the values stayed in memory, so every existing ref remained spendable while the UI said refs
   would not expand. Output scrubbing deliberately stays on: masking is a filter, not a capability.
   `/sec on` does not restore the values — silently resurrecting them would make the switch
   meaningless.
3. **`peerDependencies: "*"` → `~0.85.1`.** "*" was written before the design had ever run. It
   now rests on pi internals cited by file and line (§3), two of whose claims were already wrong.
   An unconstrained range advertises compatibility with exactly the versions where those internals
   have moved.
4. **§3 is executable.** `test/mechanics.test.ts` asserts each row. When a row fails, the response
   is to re-measure and then either fix pi-secure or amend §3 — never to relax the assertion.
5. **`looksCredentialish` moved out of `scrub.ts`.** It was written there when capture and
   scrubbing shared a module by convenience; the scrubber then stopped consuming it, leaving
   capture.ts as the only caller. The shared piece is the digest denylist, and the anchoring is
   load-bearing in both directions: a credential with a long hex tail CONTAINS a 40-hex run, so
   exempting a substring leaves a real secret fully visible.
6. **"Last mile" was the wrong mental model.** `before_provider_request` is provider-level — pi-ai
   invokes it from inside each provider's api — so it is an extra layer that depends on the
   provider. The durable guarantee is `context` + `message_end` + `tool_result`. pi-secure now
   measures whether the provider-level hook ran and says so once if it never did, because that
   failure mode is otherwise completely silent.

### Recorded, not changed

- **Delivery through the child's environment.** `/proc/<pid>/environ` is owner-readable for the
  life of the command, so any same-user process can read a ref's value. This is not a new hole —
  `bash` already gives the model the user's full read access — but it belongs in the record. A
  file-descriptor handoff (memfd + seal) would avoid it entirely and needs spawn support from pi;
  building it here would mean reimplementing process spawning, which is a far larger risk than
  the exposure it removes.
- **`[[ $a > $b ]]` is a known false positive** in the redirect detector. Teaching the scanner
  about `[[ ]]` is the fragile-detector work this design has twice declined, and a spurious
  warning is user-visible noise, never a security hole.

## 12d. The fingerprint became a masked preview (2026-08)

§6.1 and §11 specified a `sha256:<16 hex>` fingerprint wherever a secret is identified but not
revealed. That was sound — one-way, reveals nothing — and useless for its actual job: nobody can tell
from a digest whether the key they just pasted is the key they meant to paste, so "confirm a capture
without echoing it" was a formality. The convention every API-key console already uses is a prefix and
the last few characters with the middle masked, and adopting it is what makes the confirmation flow
usable by the person rather than only by the code.

**The gate is not "is this a key or a password."** That question has no good answer, and asking it is
how the first draft ended up gating on length and getting it wrong in both directions: a 20-character
generated password and a 20-character human password are the same length. Measured entropy settles it
too — the "strong generated password" band (4.25–4.70 bits/char) OVERLAPS the human band (3.38–4.12),
so per-character entropy cannot separate them either. The rule therefore asks the boring question:
*does showing a few characters meaningfully weaken this value?*

| Tier | Condition | Reveal | Why |
|---|---|---|---|
| 1 | matches a known provider format | prefix + 4 + `…` + 4 | provider-issued, long, random by construction: ~48 bits out of ~190. The prefix is also what identifies the KIND of key, which is the most useful thing on the line |
| 2 | ≥ 20 chars and ≥ 4.5 bits/char | 2 + `…` + 2, capped at a tenth per side | covers strong GENERATED passwords. Refusing those would be the length rule failing the other way: two characters cost ~12 bits out of ~120 |
| 3 | everything else | `sha256:…` | passphrases are where head-and-tail actually hurts — `correct-ho…ry` tells a logging endpoint the secret is English-ish. Also DSNs and short values |

The asymmetry is deliberate: revealing too much costs a couple of characters and is bounded by the
share rule; revealing too little costs a slightly less convenient confirmation and nothing else. When
the classifier is unsure it hides, which is why 4.5 sits ABOVE the human band rather than inside it.

Two findings while implementing it, both worth keeping:

- **A "find the leading hyphenated segment" prefix rule is a real bug, not a style question.** It reads
  `xK3-mQ7-` in a random 20-character secret as a prefix, prints all nine characters, and spends them
  before the share rule has counted one. A real console can afford to show a prefix because it KNOWS
  the format; so the prefix is shown only when the value matches a recognised format.
- **"What does a credential look like" is needed on both sides** — the scrubber to mask it, the preview
  to decide what may be shown. `PROVIDER_PREFIX_SOURCES` now lives in `entropy.ts` so there is one
  table rather than two that can drift. This is the second time that table has moved for the same
  reason.

**This is a deliberate weakening of §11's "receipt/fingerprint paths must be value-free by
construction".** A few characters of a long secret now reach the transcript, which is exactly what makes
them recognisable to the person who pasted them. The floor and the share rule are what keep it bounded,
and `PublicEntry.preview` is computed once at insert time so no consumer re-derives it from the value.

## 12e. A field report: the bash-ownership warning was wrong (2026-08)

A user hit `pi-secure: another extension owns bash, so {{sec:…}} refs will NOT expand` on an
install where nothing else registers `bash` and refs were expanding correctly. Worth recording,
because the defect was not a typo — it was the wrong *question*.

The check has to answer "is the registered `bash` definition ours?", and it was answering by
comparing a directory derived from `import.meta.url` against `sourceInfo.baseDir`. Two measured
facts break that:

1. **Node resolves modules to their real path; pi reports the path it loaded from.** `pi install
   <path>` creates a link under the agent dir, so `import.meta.url` is the checkout and pi's
   `sourceInfo.path` is the link. The two strings never match on any symlinked install.
2. **`sourceInfo` frequently has no `baseDir` at all.** Loading this package by file path through
   `DefaultResourceLoader` and dumping the extension's sourceInfo yields `{path, source, scope,
   origin}` and nothing else — the `baseDir` branch was dead most of the time, which forced a
   `/pi-secure/` substring fallback, and the substring is exactly what fails when the link is
   named anything else.

So the warning fired exactly when it should not, and stayed silent in the case it exists for.

The fix compares the **realpath of the extension entry file** against our own entry. That is
exact for every install layout — renamed directory, package cache, symlink, relocated checkout —
and cannot be spoofed by a path that merely resembles ours. The regression test builds a real
symlink to this package's `index.ts` under a name that does not contain "pi-secure" and asserts
the check accepts it; it fails against the previous code.

Two transferable lessons:

- **A stub that agrees with the code under test is how a wrong check stays green.** The wiring
  harness's `getAllTools` returned the invented path `"pi-secure"` — a shape pi never produces —
  because that string satisfied the substring check under test. It now returns the real entry path.
- **A diagnostic must not be able to break the session.** The warning path called
  `ctx.ui.notify` unguarded, so a UI context without `notify` threw out of `session_start`. It is
  best-effort now, like the capture receipt.

The wording changed to match reality too: first registration of a tool name wins, so load order is
the lever. "Load pi-secure after it" was both imprecise and — in the failing case — advice for a
problem that did not exist.

## 12f. The secret prompt is an ordinary pi dialog (2026-10-08, from use)

Three field reports with one theme: a surface that **mimics** pi drifts from pi, while a surface
**built from** pi's parts cannot.

**The prompt was hand-drawn.** The name step (`ctx.ui.input`) and the secret step were the same
flow but not the same look — different position, different chrome. It is now assembled from the
exact parts `ExtensionInputComponent` uses, in the same order: `DynamicBorder`, `Spacer`, an
accent title, the `Input` line, a `keyHint` footer, `DynamicBorder`. Deliberately **without**
`overlay: true` (see §3): the built-in dialogs render into the editor container, and the overlay
form centres a panel over the scrollback, which is what collided with the context block.

**Keys were decoded as bytes.** "esc to cancel" did not cancel and Ctrl+C *typed* characters,
because the kitty protocol delivers `\x1b[27u` / `\x1b[99;5u` / `\x1b[13u` and the old raw-byte
checks matched none of them, leaving the digits to be appended as text. `matchesKey` is the
library's canonical decode and handles both encodings; the byte surgery is gone.

**Navigation keys were typed into the secret.** Arrows, Home, End, Delete and Page keys arrive as
CSI (`\x1b[1;1:1A`) whose `:` parameter is outside the escape-sequence character class, so the
sequence survived stripping and its characters were appended. They are now matched and **ignored**
before the printable filter, and the class accepts `:` as a backstop. The cursor stays pinned to
the end: honouring arrows properly needs a second cursor model for a buffer the user never sees,
and "arrows do nothing" beats "arrows silently corrupt the secret".

**Transferable rule.** Chrome is *reused*, never imitated. The only thing this extension owns in
that dialog is the masking, and the value never reaches a rendered node — the input line holds
bullets and nothing else.

## 12g. Ingest from a file: `/sec add-from-file` (2026-10-08)

### Why, given §6.3

Real keys live in `.env` files. Forcing those through a copy-paste round trip is where people paste
the key into the chat instead — the behaviour this project exists to prevent. §6.3's exclusion was
aimed at **ambient** sources (values that become spendable with no user act); a flow where the user
names a file, sees its variable names, and ticks what to adopt is not ambient. The structural rule
below (nothing is read until the user types a path) is what keeps it that way, and is an invariant,
not a convention.

### Scope

**dotenv only.** No JSON/YAML/INI. No interpolation. One file per invocation, no recursion, no
watching, no memory of the file in later sessions.

### Entry points

| form | behaviour |
|---|---|
| `/sec add-from-file` | opens the path picker (§12g.2), then the list |
| `/sec add-from-file <path>` | skips the picker, goes straight to the list (same validation) — the headless path, mirroring `/sec` vs `/sec list` |
| the `/sec` menu's *Add from a file…* row | same as the bare verb |

There is **no tool**. The model cannot cause a file to be read and cannot name one; the same
reasoning as "no `sec_reveal`" (§6.2).

### 12g.1 Path picker

**F1.** No filesystem call happens before the typed (expanded) text contains a `/`. Opening the
picker, an empty buffer, and a bare word all list nothing. The candidate function is not reached,
which is what makes this checkable rather than aspirational.

**F2.** A path is read only as a **regular file**: directories, FIFOs, sockets and device nodes are
refused (a FIFO would block the UI forever), as are files over 1 MiB and non-text input (a NUL byte
in the first 8 KiB).

Resolution: `~` and `~/…` expand to `$HOME`; `~user` is not supported; relative paths resolve
against `ctx.cwd`; the input is never rewritten to an absolute path.

| key | behaviour |
|---|---|
| character | edits the path; candidates re-narrow per keystroke (local `readdir`) |
| Tab | accepts the highlighted row — a directory descends (appends `/`), a file completes the name. No candidates → nothing. |
| ↑ / ↓ | move the highlight |
| Enter | confirms only an existing regular file; a directory descends; anything else shows an inline error and leaves the input untouched |
| Esc / Ctrl+C | cancel the whole flow; nothing is added |

Enter acts on what was **typed**, Tab on what is **highlighted** — chosen over mirroring the main
editor (where Enter applies the highlighted completion) so the footer can state the rules in one
line and a mis-aimed Enter cannot silently pick a neighbouring file.

Candidates: names beginning with the fragment, **dotfiles included**, `.`/`..` excluded, directories
first then files, each alphabetical, directories marked with a trailing `/`. `../` is offered first
**only while the fragment is empty**: a navigation row cannot match a filter, and as the first row it
would become Tab's default target, turning `./.env` + Tab into `./../`. Prefix matching only — no
fuzzy, no case-insensitivity.

### 12g.2 The assignment list

Rows show the **final vault name** and nothing else about the value.

| line | result |
|---|---|
| `KEY=value`, `export KEY=value`, indented | added (`export`/indent stripped) |
| `# comment`, blank | skipped |
| `KEY=value # note` | value is `value` (inline comment needs preceding whitespace) |
| `KEY=abc#def` | value is `abc#def` |
| `KEY=`, `KEY="   "` | skipped as empty |
| `KEY="a b"`, `KEY='a b'` | value is `a b`, quotes stripped |
| the same key twice | last wins; the list notes `1 duplicate collapsed` |
| `KEY: value` | skipped — not an assignment |
| `KEY="unterminated` | skipped, counted in the footer |
| CRLF, leading BOM | `\r` stripped, BOM stripped |

**F3. The vault receives the bytes between the quotes, never a value the parser invented.** No
expansion engine: `"a\nb"` is stored literally and the row is marked `escapes stored as written`;
`${OTHER}`/`$OTHER` is stored literally and marked `unexpanded ref`. Flagged, not repaired — a
vault value that quietly differs from what the application reads out of the same file is worse than
a visible marker, and a partial dotenv implementation is a bug farm.

**F4. Naming only ever lowercases and numbers.** Lowercase, then try the base name, `1`, `2`, `3`…
against both the vault and the names already assigned **earlier in this same run**. A name that is
still invalid after lowercasing (`2FA_TOKEN`, `MY.KEY`) is **not offered**: the row is disabled
with the reason (`can't auto-name: starts with a digit`). Repairing it would invent a name the user
did not write (`k_2fa_token`) and produce a `{{sec:…}}` they later cannot explain. Editing the file
is the fix.

**F5. The name shown on the row is the name that gets created.** Suffixes are resolved while the
list is built, not while adding; otherwise ticking `my_api_key1` could create `my_api_key2`.

**F6. The value is never rendered.** No value, preview or fragment in candidates, rows, errors,
footer, or receipt — the same projection discipline as `/sec list`, which shows a masked preview
only *after* the value is in the vault. A file with no assignments produces a notification and no
list.

**F7. Unticked means absent.** Only ticked rows are added; cancel adds nothing; a per-key failure
skips only that key and reports why (the others still land). The parsed map is local to the flow and
dropped on every exit path, including cancel and throw — §7's "never written to" applies unchanged.

**F8. The classifier gates the default view, never the data.** The list opens showing only the
assignments §12g.3 calls likely secrets, and `TAB` reveals every row. Hiding noise was a correction,
not the original design: the first version showed all 34 rows of a shell profile with 10 marked, 6 of
them wrongly, and the user asked for the noise to go. The escape hatch is what keeps that safe —
no line of the file is unreachable, so a missed secret costs one keypress instead of a silent loss.
When *nothing* is likely, everything is shown rather than an empty screen, and the toggle is not
offered because it would only produce one.

The path itself is **not** treated as a secret: it appears in the transcript exactly as `cat .env`
would. Scrubbing the user's own typed command would be theatre, and the threat model already
assumes `bash` can read anything as that user.

### 12g.3 Which assignments are offered

Measured, not guessed. Importing a real `~/.bashrc`:

```
34 assignments · 10 look like secrets · 16 duplicate collapsed · 91 line skipped
```

Six of those ten were shell structure: `PS1`, `LD_LIBRARY_PATH`, `__conda_setup`,
`NODE_EXTRA_CA_CERTS`, `BETTERWRIGHT_CHROMIUM_ARGS`, `debian_chroot`. Entropy cannot separate those
from a token — `PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '` is high-entropy and
multi-class — so `looksCredentialish` now also refuses anything shaped like shell syntax, a path or
a list:

| rejected because | example |
|---|---|
| whitespace, quoting or shell metacharacters | `PS1='…\u@\h…'`, `__conda_setup="$(…)"` |
| a path stem (`~`, `/`, `./`, `../`) | `~/.local/share/mkcert/rootCA.pem` |
| a CLI flag, or an `--a,--b` list | `--no-sandbox,--disable-dev-shm-usage` |
| a `:`/`,`-separated list with no `://` | `/usr/local/cuda/lib64:/usr/lib/x86_64-linux-gnu` |
| a plain scheme URL | `https://proxy.golang.org,direct` |
| a digest | the git-SHA exemption, unchanged |

`isLikelySecret(name, value)` then decides — **in this order, because the order is the design**:

1. **provider format** (`matchesProviderFormat`) → a secret, whatever it is named. This is what
   rescues `GH_PAT=ghp_…`: a token exported under a name that says nothing.
2. **identifier/setting name** → not a secret. `CLOUDFLARE_ACCOUNT_ID` is 32 random-looking hex
   characters, and no entropy rule distinguishes that from a hex token, so without a name veto the
   row appears or not according to how much repetition the particular ID happens to contain. `url`
   and `key` are deliberately **absent** from this list (a DSN carries a password, and a signed URL
   is itself a credential); `pwd` is **present**, because in a shell file `PWD` is a directory while
   `pwd` in the scrubber's word list means a password — one word, two meanings, and the file-import
   reading is the literal one.
3. **sensitive name** (`*_API_KEY`, `*_TOKEN`, `*_SECRET` …) → a secret. The only signal that
   catches a real key whose value is short or oddly shaped, and on the measured file it was
   load-bearing for every genuine one.
4. **value shape** → the strict entropy rule above, which catches a secret under a neutral name
   (`LEGACY_KEY`).

The word list in (3) is `SENSITIVE_NAME_SOURCE`, shared with the scrubber's key/value pass — the
same judgement in both places, one definition.

**The vector is `test/fixtures/realistic-bashrc.env`.** It carries every shape above with fabricated
values, and `test/entropy.test.ts` asserts a verdict per variable name plus a case that fails if a
line is added without a declared verdict. It is a file rather than an inline copy so it can also be
imported by hand while developing.

### Modules

| file | change |
|---|---|
| `src/env-file.ts` | **new** — pure or fs-only, no UI: `parseDotenv`, `chooseName`, `splitPathInput`, `listCandidates`, `inspectPath` |
| `src/file-import.ts` | **new** — the flow's two screens (picker, assignment list). The list component returns row **ids**, so it is never handed a value: F6 does not depend on anyone remembering it |
| `src/commands.ts` | the `add-from-file` verb, the flow, the receipt, and the `VERBS` entry |
| `src/menu.ts` | the `add-file` action and its "Add from a file…" row (`f`) |
| `src/vault.ts` | `SecretSource` gains `"file"` |

### What this does not change

§8's scrubbers are untouched, because values in this flow never travel the model path at all —
`readFileSync` to vault, with no tool result, message or provider payload in between. `--sec-file-reads`
(§8.2) governs *tool output* and is unaffected. §9's enforcement rules are unaffected.

### Testing

Pure unit tests for the parser table, naming/suffixing (including F5's ordering), path splitting
and `~` expansion, candidate listing, and the F2 validator (non-regular, oversized, binary, CRLF,
BOM) — `test/env-file.test.ts`. The classifier is pinned by the golden vector
`test/fixtures/realistic-bashrc.env` (§12g.3): a verdict per name, a count that fixes the
false-positive rate, and a case that fails when a fixture line has no declared verdict. Component
tests drive the real screens through a fake `ctx.ui.custom` (`test/file-import.test.ts`): typing
narrows, Tab accepts and descends, Enter on a directory descends, Enter on a file confirms, Esc
cancels, and an empty buffer performs **zero** `readdir` calls (F1); the assignment list defaults to
the likely rows, `TAB` reveals and re-hides the rest, `a` selects only what is visible, and a tick
survives the flip (F8). Wiring tests cover both entry forms, the menu row, the `file` source label,
and that the receipt names keys only. The canary sweep (§13.3) gains this flow, asserting the
stronger property that an import appends **nothing** to the transcript — not merely that no value
appears in it.

Mutation-checked by disabling one guard at a time and confirming the tests go red: F1 (the separator
rule — two tests, including the component's), F6 (a value placed in a rendered row), and F8 (the
classifier's verdict ignored, i.e. everything shown by default); plus the classifier itself, by
removing the shell-syntax rejection and watching the golden vector fail.

## 12h. Quoting the ref syntax must not require evading our own guard (2026-10-08, from use)

### The incident

Two refusals in one session, both while *documenting* pi-secret, not using it:

1. The `write` tool refused a README whose content quoted the syntax — `{{sec:github_token}}`,
   `{{sec:NAME}}` — with "sec refs are not written to files".
2. `bash` refused a quoted heredoc carrying a commit message that happened to contain a ref-shaped
   placeholder — "sits in a shell context that will not expand it".

The only escapes were `/sec off` (which clears the vault — a sledgehammer that destroys the session's
secrets to write a paragraph of documentation) or assembling the literal at runtime (`"{" + "{"`),
which the guard never sees. The second escape is the tell: **this guard is a tripwire, not a
boundary.** A model that means to cross it crosses it textually; only the accident is stopped. A
tripwire loses nothing by gaining a deliberate door — and until it has one, every intentional use is
a false positive.

### What the guard actually protects

Not confidentiality. A ref carries a *name*, names are shown to the model by design (`sec_list`), and
no value can enter the file through one. The hazard is **correctness**: the model persisting a masked
tool result into a file a later consumer expects to hold a real credential — `~/.netrc` with
`password {{sec:gh_pat}}` breaks auth silently. That mistake has a signature: the echoed ref
**resolves in the vault**, because the scrubber only mints refs for stored values. A ref to a name
that is not stored cannot be a persisted value; it is syntax being quoted.

### The rule

`write`/`edit`, in order:

1. A ref in the `path` field is always refused. An address is never the place to quote syntax, and
   the file that would be created is wrong whatever the name resolves to.
2. **Target carve-out.** Paths with a `docs`/`doc`/`test`/`tests`/`fixtures`/`examples` directory
   segment, or a `.md`/`.markdown`/`.example`/`.sample`/`.template` basename, allow every ref and
   notify the user once. Quoting the syntax is the norm there, names are not secrets, and the one
   thing that must never happen — substitution — is refused by construction: the allow path returns
   before expansion runs.
3. Otherwise: refs that **do not resolve** are allowed, silently — quoting a name that holds nothing
   cannot be a persisted value. Refs that **resolve** are refused, with the message split so it
   teaches the recovery: the ref resolves, so the file would contain the placeholder rather than the
   value; tell the user where it needs to go and let them place it.
4. **The reserved marker is never prose.** The first canary run against this design failed, and the
   failure was the design's own blind spot: a scripted write carrying a literal `ghp_…` value arrived
   at the gate as `token={{sec:redacted}}` — the *scrubber's* marker, minted upstream when the value
   was shape-masked, non-resolving by construction. "Non-resolving means prose" cannot distinguish
   quoted syntax from our own masked output coming back. The structural discriminator is the name:
   `redacted` is the one name the scrubber owns (`RESERVED_NAME`, the single source scrub.ts's
   `GENERIC` marker is now derived from). A ref with that name in a non-doc target is refused
   whatever the vault says; doc targets may quote it, because the spec and README legitimately do.

`bash`, with the guard and the expander kept in agreement (the defense-in-depth note in
`injectBashCommand` exists because they can drift): a ref in a non-expanding context — quoted-heredoc
body, `#` comment, or after an unterminated quote — is a problem **only if it resolves**. A
non-resolving ref there is prose and passes through as the literal it already is — except the
reserved marker, which is excluded for the same reason as in the write gate. `expandBash` must drop
the matching `missing` entries, or the guard's allow is undone one line later by the caller's
fail-closed block.

### The notify — decided: always

Doc-path allows notify the user every time, one line: the count, the path, and that names only were
written — no values substituted. Chosen over notifying only when a ref resolves, because the silent
case is the one a user cannot reconstruct later, and because one line per tool call is already the
natural throttle. It goes to `ctx.ui.notify` only and never to the model, the same rule as the
redirect warning. Non-doc, non-resolving allows stay silent: nothing surprising happened.

### What this does not change

- `read`/`grep`/`find`/`ls`: a ref in a path or pattern is still refused outright.
- A literal **value** (not a ref) in any tool argument still refuses first — a doc is not licensed
  to carry the secret itself, only its syntax.
- `/sec off` still clears the vault; it remains what it was, not the escape hatch for this.

### Modules

`glue.ts` gains `isDocPath` and the write/edit verdict (allow-and-notify | silent allow | block);
`InjectOutcome` gains `notify?`. `guard.ts`'s `bashRefIssues` filters non-resolving inert refs.
`bash.ts`'s three fail-closed branches skip `missing` when the name does not resolve. `index.ts`
surfaces `out.notify` through `ctx.ui.notify`, gated on `ctx.hasUI`.

### Testing

Red-first unit table for the verdict — {doc, non-doc} × {resolving, non-resolving} plus ref-in-path —
with the input content asserted **byte-identical** on every allow (the allow path must never
substitute, and the fastest way to rot that is an early-return that drifts). `isDocPath` pins each
path class. For bash: the commit-message incident is a golden vector (quoted heredoc, non-resolving
name → passes `injectBashCommand` unchanged), while a resolving name in the same heredoc still
reports "will not expand it"; the comment and unterminated branches likewise. Wiring asserts the
notify reaches `ctx.ui.notify` and the call is *not* blocked. Mutation-checked by disabling
`isDocPath`, inverting the resolve gate, and restoring the unconditional `missing` push — each turns
tests red.

### Residuals, accepted

- A doc quoting a *resolving* ref is allowed: correct, because documentation needs real names and
  substitution is refused by construction.
- A model determined to write names into a doc can — names were never the secret, and the notify
  makes it visible to the one person who cares.
- **Prose quoting the reserved marker through bash into a non-doc file stays refused.** The original
  incident did exactly that (pi's own tool descriptions use `{{sec:redacted}}` as their placeholder,
  and the commit message copied it). The cost is one word: quote any other placeholder name. Doc and
  test targets are exempt, so documentation of the marker itself is unaffected.
- A user who deliberately stores a secret *named* `redacted` makes their stored ref collide with the
  scrubber's marker. The write gate refuses it either way (resolving or reserved), so the failure is
  conservative; `/sec rename` is the escape.
- The carve-out list is convention, not truth: `.example`-suffixed files and `examples/` directories
  are templates by culture. Anything outside it is one deliberate rename away from the old behavior,
  which is the intended friction for genuinely ambiguous targets.
