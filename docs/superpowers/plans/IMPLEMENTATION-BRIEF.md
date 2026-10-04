# Implementation brief — wiring phase (Tasks 7→10, 11, 12, 13, 14)

**Read this before the task section in `docs/superpowers/plans/2026-09-12-pi-secure.md`.**
The plan was written against an earlier tree. The corrections below are verified against the
installed `@earendil-works/pi-coding-agent@0.85.1` / `@earendil-works/pi-ai@0.85.1`
type declarations in `node_modules/` and against the CURRENT `src/`. Where they disagree with the
plan, **they win**.

## Verified API facts (do not re-derive, do not guess)

| Fact | Where |
|---|---|
| `createBashToolDefinition(cwd: string, options: BashToolOptions)` | `dist/core/tools/bash.d.ts` |
| `BashSpawnContext = { command: string; cwd: string; env: NodeJS.ProcessEnv }`; `BashSpawnHook = (ctx) => ctx` (sync, must return) | same |
| `BashToolDetails = { truncation?; fullOutputPath? }` | same |
| `pi.registerTool(tool)`, `pi.registerCommand(name, {description?, getArgumentCompletions?, handler})`, `pi.registerEntryRenderer(customType, (entry, options, theme) => Component \| undefined)`, `pi.appendEntry(customType, data?)`, `pi.registerFlag(name, {description, type:"boolean", default})`, `pi.getFlag(name)` | `dist/core/extensions/types.d.ts` |
| `pi.getAllTools(): ToolInfo[]` where `ToolInfo = Pick<ToolDefinition,...> & { sourceInfo: SourceInfo }`, `SourceInfo = { path, source, scope: "user"\|"project"\|"temporary", origin: "package"\|"top-level", baseDir? }` | same |
| `tool_call` handler may return `{ block?: boolean; reason?: string; terminate?: boolean }`; mutate `event.input` in place to change args | same |
| `tool_result` handler may return `{ content?, details?, isError?, usage? }` | same |
| `context` handler may return `{ messages?: AgentMessage[] }` | same |
| `input` handler returns `{action:"continue"}` \| `{action:"transform", text, images?}` \| `{action:"handled"}` | same |
| `ctx.ui.custom<T>(factory: (tui, theme, keybindings, done: (r:T)=>void) => Component & {dispose?})` | same |
| `ctx.ui.notify(message, "info"\|"warning"\|"error")`, `ctx.ui.setStatus(key, text \| undefined)` | same |
| `Theme` and `ToolDefinition` ARE exported from `@earendil-works/pi-coding-agent`. `Box` and `Text` are NOT — import them from `@earendil-works/pi-tui`. | verified by grep on `dist/index.d.ts` |
| `copyToClipboard` IS exported from the pi root | same |
| `fauxProvider(opts)`, `fauxToolCall(name, args, {id?})`, `fauxAssistantMessage(content, opts?)` are exported from `@earendil-works/pi-ai`; the handle exposes `.provider`, `.getModel()`, `.setResponses(steps)`, `.state` | `dist/providers/faux.d.ts` |
| `createAgentSession(options)` takes `{cwd, modelRuntime, model, resourceLoader, sessionManager, tools?, customTools?}` | `dist/core/sdk.d.ts` |
| `SessionManager.create(cwd, sessionDir?, options?)` — pass an explicit temp `sessionDir` | `dist/core/session-manager.d.ts:319` |
| `DefaultResourceLoaderOptions` **requires `agentDir: string`** (the plan's snippet omits it and will not compile) | `dist/core/resource-loader.d.ts:67` |
| `ModelRuntime.setRuntimeApiKey(providerId, apiKey)` exists — use it if a turn fails with "no configured auth" | `dist/core/model-runtime.d.ts:82` |

## Module-API corrections (Task 17 already changed `capture.ts`)

The plan's Task 8 snippet is written against an OLD `capture.ts`. Current exports:

```ts
findCandidates(text: string): Candidate[]                       // Candidate = {value,start,end,confidence,hint?}
suggestNames(candidates: Candidate[], text: string, opts?: { taken?: string[];
    existingNameForValue?: (value: string) => string | undefined }): string[]
applyCapture(text: string, items: CapturedItem[]):
    { text: string; captured: CapturedItem[]; skipped: { nameConflict: number; staleSpan: number } }
// CapturedItem = { candidate: Candidate; name: string }
// `suggestName` (singular) no longer exists and must NOT be reintroduced.
```

So `captureFromText` must be: `findCandidates` → `suggestNames` → zip into `CapturedItem[]` →
`applyCapture` → **write to the vault from `out.captured` only** (each `{candidate, name}`), then
return `out.text` plus a receipt list built from `vault.add(...)`'s `PublicEntry`
(`name`/`length`/`fingerprint`). Never vault a name that was skipped. `suggestNames` may throw only
on a genuine internal invariant violation; treat a throw as "capture nothing, log nothing, return
the original text" so a paste is never lost.

## Non-negotiable invariants (spec §1–§4; reviewer will check these)

1. A secret value must never appear in: a command string, a tool result, a session file, a custom
   entry, a log/notify string, or a provider payload.
2. Never interpolate `event.input` into any string you emit (it holds **expanded** args).
3. `bash` must receive values through the **child env only**, and must **never spawn** when a ref
   was left unsubstituted.
4. `write`/`edit` content and `read`/`grep`/`find`/`ls` paths/patterns containing a ref → hard
   block. Bash redirects (`>`, `tee`) → user-only notify, never into model context.
5. `/sec restore` copies to the clipboard and has **no editor channel at all** — the interface must
   make `setEditorText` unrepresentable, not merely unused.
6. There is no `sec_reveal` tool, and no tool may ever return a value.
7. Scrub failure must fail **closed** (`{{sec:redacted}}`), never open.
8. The vault is memory-only and dropped on `new`/`fork`/`resume`/`quit`, kept on `reload`.

## Working rules

### Budgeted exploration (revised after root-cause analysis)

An early launch stalled: ~200 tool calls, zero files written. The traced cause was NOT a lazy model.
Two rules in this brief collided — it forbade `bash` for file inspection while the agent definition
mandated it, so the child re-read its own instructions to re-decide. It also imposed a write
deadline while the child was genuinely blocked on an unresolved SDK type, with no cheap oracle
available. The fixes: remove the contradiction, and give the child a feedback loop.

1. **The prompt is the only source of what to read.** Read the files it names, and no others. There
   is no conventions file, lessons file, or plan file you should be looking for because it "usually"
   exists here — if it is not named, it is not part of the task.
2. **Use the dedicated tool per job.** `read` to read, `grep` to search contents, `find`/`ls` to
   locate paths, `edit`/`write` to change files, `bash` to run commands (tests, builds, typechecks,
   git). Do not route file reading or searching through `bash`.
3. **Never read the same file twice with identical arguments.** That repetition was the actual
   observed pathology. If a read did not answer your question, change the question.
4. **Write-first when the task is blocked on a type or an API shape.** Create the file with your
   best reading of the signature, then run `npx tsc --noEmit` and let the compiler answer. Do not
   resolve SDK types by grepping `node_modules` — a stub that compiles is faster than an
   investigation, and `skipLibCheck: true` means missing types in dependency `.d.ts` files are not
   even errors. Note `@earendil-works/pi-agent-core` is referenced by pi's own typings but is NOT
   installed here; do not go looking for it.
5. Prefer implementing from this brief's prose over mining the plan for code blocks. If the plan's
   snippet conflicts with this brief, the brief wins and you do not need to re-read the plan.

TDD order still holds: test file first, then implementation — but both happen early, and the test
run is the feedback loop, not a source of answers about the SDK.

- Write the tests from the plan's Step 1 first; make them pass. Keep the plan's test bodies — they
  encode the spec. If a plan test cannot compile against the verified API above, fix the *test* to
  the real API and say so in your report.
- `npx vitest run <your test files>` green, and the whole suite still green (`npx vitest run`).
- `npx tsc --noEmit` clean. `any`/`as any` is a failure unless the type genuinely cannot be
  expressed; `as unknown as X` in a test double is acceptable.
- **No `git` commands.** Do not commit, add, stash, or branch. The parent integrates.
- **Touch only the files your task owns** (listed in each task brief). Other agents are writing
  sibling files in this same working tree concurrently; a shared-file edit corrupts their work.
- Match the existing code style: no semicolon-free code, explicit return types on exported
  functions, one-line "why" comments carrying the *reason* a rule exists, and a task/requirement tag
  where the plan names one.

## Task ownership (file-level, enforced)

| Task | Files you may create/edit |
|---|---|
| 7 | `src/substitute/guard.ts`, `test/guard.test.ts`, and ONLY the `src/substitute.ts` re-export lines |
| 11 | `src/restore.ts`, `test/restore.test.ts` |
| 13 | `src/masked-input.ts`, `test/masked-input.test.ts` |
| 14 | `src/tools/sec-list.ts`, `test/sec-list.test.ts` |
| 8 | `src/glue.ts`, `test/glue.test.ts` |
| 9 | `src/tools/bash.ts`, `test/bash-tool.test.ts` |
| 10 | `src/index.ts`, `src/commands.ts`, `src/state.ts`, `src/receipt.ts`, `test/wiring.test.ts` |
| 12 | `test/helpers/session.ts`, `test/integration/canary.test.ts`, `scripts/canary-sweep.mjs`, `package.json` (`test:canary` script ONLY) |

Tasks 7, 11, 13, 14 have no dependency on each other and run in parallel. Task 8 runs after 7.
Task 9 runs after 8. Task 10 runs after 8+9+11+13+14. Task 12 runs after 10.