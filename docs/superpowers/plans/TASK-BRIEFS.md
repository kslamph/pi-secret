# Task briefs — wiring phase

Each section below is the complete prompt for one worker. Read
`docs/superpowers/plans/IMPLEMENTATION-BRIEF.md` FIRST — it carries the verified pi API facts,
the corrections to the plan, the non-negotiable invariants, and the working rules (no git, own only
your files, tests first, full suite + tsc green).

The plan is `docs/superpowers/plans/2026-09-12-pi-secure.md`. Section line numbers are given per task.

The suite is currently **278 tests green** on `feat/pi-secure`. After your work the whole suite must
still be green, plus yours.

---

## Task 7 — shell safety guard

**Plan section:** lines 2636-2762.

Classify each `{{sec:NAME}}` ref in a bash command as expandable / inert (sits where bash will not
expand it) / unknown (not in the vault), and produce an actionable problem string the caller blocks
on. `heredocRegions()` and the quote/span scanner already exist in `src/substitute/bash.ts` and are
your inputs — reuse them, do not write a new lexer. A ref inside a NON-inert (unquoted-delimiter)
heredoc body IS expandable.

**Files:** `src/substitute/guard.ts`, `test/guard.test.ts`, and only the append/re-export lines at
the end of `src/substitute.ts`.

---

## Task 11 — non-destructive restore

**Plan section:** lines 3955-4076.

Copy a captured secret to the clipboard and notify length+fingerprint. The `RestoreIo` interface must
have NO editor/setEditor channel — the leak must be unrepresentable, not merely avoided. Unknown
name and clipboard failure are both reported, never swallowed, and neither may echo the value.

**Files:** `src/restore.ts`, `test/restore.test.ts`.

---

## Task 13 — masked secret prompt

**Plan section:** lines 4457-4670.

Pure `MaskState` reducer + renderer (bullets, never the value) plus `promptMaskedSecret()` built on
`ctx.ui.custom()`. It must NOT use `ctx.ui.input()` anywhere — that dialog echoes to the terminal.
Handle bracketed-paste framing, backspace, Enter-as-submit, Esc/Ctrl-C as cancel, and ignore
CSI/mouse noise. `ctx.mode !== "tui"` or `!ctx.hasUI` must return `undefined` rather than throw.

**Files:** `src/masked-input.ts`, `test/masked-input.test.ts`.

---

## Task 14 — the `sec_list` tool

**Plan section:** lines 4671-4791.

A `ToolDefinition` named `sec_list` whose `promptSnippet` and `promptGuidelines` carry the
model-facing contract from spec §5: use `{{sec:NAME}}`; never ask the user to paste a secret; if a
ref is rejected run `sec_list` and retry; and do not expand a ref inside a string a second shell
parses (`sh -c`/`eval`/`ssh`) because there the value becomes source. `execute()` returns
name+length+fingerprint only, never a value, and tells the model to use `/sec add` when the vault is
empty. `details` carries names only.

**Files:** `src/tools/sec-list.ts`, `test/sec-list.test.ts`.

---

## Task 8 — the glue layer

**Plan section:** lines 2764-3121. Runs AFTER Task 7 (it imports the guard).

Pure functions connecting vault + substitute + scrub + capture:

- `injectBashCommand` — expand into env only, or block with a reason. Never the value in the command.
- `injectToolCall` — deep-walk `event.input` and expand refs in place for non-bash tools; HARD BLOCK
  refs in `write`/`edit` content and in `read`/`grep`/`find`/`ls` path/pattern arguments; do NOT
  touch bash input (the spawnHook owns it).
- `scrubToolResult` — scrub content and details; honour the `scrubFileReads` knob so shape masking is
  skipped for file reads while value-exact masking still applies; FAIL CLOSED to `{{sec:redacted}}`
  if the scrubber throws.
- `scrubMessageText`.
- `captureFromText` — `findCandidates` → `suggestNames` → `applyCapture` → `vault.add`, vaulting
  ONLY what `applyCapture` actually returned in `captured`.
- `scrubOutputSnapshot(details, vault)` — pi's bash truncation writes raw output to
  `details.fullOutputPath`. Rewrite that file scrubbed in place; on ANY failure unlink it and DELETE
  the `fullOutputPath` field, because a stale pointer to content we could not clean is worse than no
  pointer. Test both branches against a real temp file.

**Files:** `src/glue.ts`, `test/glue.test.ts`.

---

## Task 9 — the wrapped bash tool

**Plan section:** lines 3122-3342. Runs AFTER Task 8.

`createSecureBashToolDefinition(cwd, {vault, onExpand?})` re-registers pi's own
`createBashToolDefinition` — so name, `promptSnippet`, `promptGuidelines`, `renderCall`,
`renderResult` are preserved and the only observable change is that refs work — with a `spawnHook`
that expands refs into env vars. The hook MUST throw rather than spawn when a ref was left
unsubstituted, and must keep "unknown name" distinguishable from "could not determine your quoting".
Never touch `process.env`; env is per-spawn so parallel children cannot see each other's secrets.

ALSO wrap `execute()` to scrub the STREAMED partials handed to `onUpdate` — `tool_result` only fires
at the end, so without this a command that echoes a secret prints it live mid-turn. Add the runtime
test asserting the payload passed to `onUpdate` contains `{{sec:...}}` and not the value.

Finally export `bashIsOwnedByPiSecure(pi)`, which detects the silent failure where another extension
registered `bash` first and refs would reach the child as literal text with no error from pi
(`pi.getAllTools()` entries carry `sourceInfo.source`).

**Files:** `src/tools/bash.ts`, `test/bash-tool.test.ts`.

---

## Task 10 — the real wiring

**Plan section:** lines 3343-3954. Runs AFTER Tasks 8, 9, 11, 13, 14.

This is the task that makes the extension actually work; today `src/index.ts` is a no-op stub.

- `src/state.ts` — one enabled flag shared by commands and hooks.
- `src/receipt.ts` — the capture receipt component (`Box`/`Text` come from `@earendil-works/pi-tui`;
  `Theme` is exported from the pi root).
- `src/commands.ts` — ONE `/sec` command with `add|list|remove|rename|test|restore|off|on`. `add`
  uses the masked prompt and NEVER `ctx.ui.input()`. `rename` must handle `Vault.rename`'s throw
  path as well as its `false` return.
- `src/index.ts` — the full hook set: `session_start` (bind scope, register wrapped bash + sec_list,
  warn loudly if bash was not ours), `session_shutdown` (drop the vault on new/fork/resume/quit, keep
  it on reload), `input` (capture-on-paste, append a receipt entry, return `{action:"transform"}`),
  `tool_call` (inject + block), `tool_result` (scrub + scrub the `fullOutputPath` snapshot + notify
  WITHOUT ever interpolating `event.input`), `context` and `before_provider_request` (last-mile
  scrub), plus `registerEntryRenderer` and the `sec-file-reads` flag.
  `scrubDeepMessages`/`scrubDeepPayload` go in `index.ts` or `glue.ts`, your choice.
- `test/wiring.test.ts` — drive the whole surface through a fake `ExtensionAPI` and assert every
  invariant in the brief: capture-on-input transforms and leaves no value, write/edit blocks,
  `tool_result` masks values AND shapes, the provider payload is masked, the vault survives `reload`
  and dies on `new`, and `/sec off` / `/sec on` flip capture.

**Files:** `src/index.ts`, `src/commands.ts`, `src/state.ts`, `src/receipt.ts`, `test/wiring.test.ts`.

---

## Task 12 — the canary integration sweep

**Plan section:** lines 4077-4456. Runs AFTER Task 10.

The gate on "safe to use".

- `test/helpers/session.ts` — a scripted faux-provider session running the REAL extension.
  `DefaultResourceLoaderOptions` REQUIRES `agentDir` (point it at a temp dir). Pass an explicit temp
  `sessionDir` to `SessionManager.create`, register the faux provider, drive the turn with
  `session.prompt()`.
- `test/integration/canary.test.ts` — the plan's scenarios: bash echoing a vaulted secret never
  persists it; an env-var echo comes back masked; a credential file dumped by bash is shape-masked;
  the model can reuse a ref it read back; a write carrying a secret is refused (no file created); a
  large truncated dump leaves no unscrubbed snapshot on disk; nothing canary-shaped survives in ANY
  artifact.
- `scripts/canary-sweep.mjs` and the `test:canary` entry in `package.json`.

The canary value must be greppable across the whole session dir AND the pi-bash temp snapshots.

If the SDK plumbing fights you, fix the HELPER, never the assertions — the assertions are the spec's
guarantee. If a scenario cannot pass because of a real defect in `src/`, do NOT weaken it: leave it
failing and report exactly which hook leaks and what the fix would be.

**Files:** `test/helpers/session.ts`, `test/integration/canary.test.ts`, `scripts/canary-sweep.mjs`,
and ONLY the `test:canary` entry in `package.json` `scripts`.