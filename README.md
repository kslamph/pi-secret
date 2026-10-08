# pi-secure

pi-secure is an extension for the [pi](https://github.com/badlogic/pi-mono) coding agent that keeps credentials out of everything an LLM endpoint can see — request bodies, session files, transcripts, exports — while letting the model *use* those credentials in shell commands and tool calls without friction. You should never have to paste a token into a conversation, and if you do, it should not end up in the conversation.

> **Status:** the extension is wired and the canary sweep passes — `npm test` and
> `npm run test:canary` (7 end-to-end scenarios plus a filesystem sweep) are green, and the vault,
> capture, injection and scrubbing paths all run inside pi. Known gaps are listed under **Status and
> known gaps** below; read them before relying on this for anything you cannot afford to leak.

## The `{{sec:NAME}}` contract

The model learns exactly one rule:

- Reference credentials as `{{sec:NAME}}` in bash commands and tool arguments. The value is substituted at execution time and is never visible to the model.
- Names match `/^[a-z][a-z0-9_-]{0,63}$/`.
- Use the `sec_list` tool to see available names. Never ask the user to paste a secret, token, password, or API key.
- If a `sec:` reference is rejected, call `sec_list` and retry with a valid name.

Round-trip property: masking replaces a value with **the ref**, not `***`. When a command echoes a token or an error page dumps one, the model reads back `Authorization: Bearer {{sec:gh_token}}` and can paste that straight into its next command.

Secrets live in memory for the current session only — never persisted, never reused across `/new`, `/fork`, `/resume`.

## `/sec`

One command, and with no arguments it opens a **menu** — you should never have to remember a
subcommand:

```
/sec
```

```
─ pi-secure — this session only ─────────────────────────────

  ❯ gh_pat        ghp_A1b2…Q7R8 · len 40 · paste · 2m ago
    db_url        sha256:a1b2c3d4 · len 41 · prompt · 1h ago

    Add a secret…                                        a
    Disable for this session                            t · clears the values

 ↑/↓ move · enter select · a/t shortcuts · esc close
```

Enter on a secret opens what you can do with it:

| Row | Key | What it does |
|---|---|---|
| Copy value to clipboard | `c` | The only way to see the value. It goes to your clipboard, never to the editor line — typing it there would persist it in the transcript. |
| Rename… | `r` | Asks for the new name, validated before anything moves. |
| Remove from this session | `d` | Asks for confirmation first. |
| Back | `esc` | |

`Add a secret…` asks for a name, then shows the masked prompt where every character renders as
`•`; the length and preview are shown on confirm. `Disable for this session` (`t`) stops ref
injection and capture and **clears the values**; `Enable` re-enables the mechanism but does not
restore them.

Without a terminal to draw a menu in (headless, scripted), `/sec` prints the same list as text.
The argument form still works everywhere and is the escape hatch:

| Form | Effect |
|---|---|
| `/sec add <name>` | Masked prompt, then store. This session only. |
| `/sec list` | Name, masked preview, length, source and time, one per line. |
| `/sec remove <name>` / `/sec rename <old> <new>` | Forget or rename. |
| `/sec restore <name>` | Copy the value to the clipboard — not into the input line, not into chat, not into a tool result. There is no `sec_reveal` tool, and there never will be one. |

Pasting a credential into the conversation also works: high-confidence secrets are captured into the vault and rewritten to a ref before anything is persisted, with a receipt line left in the transcript (name, length, fingerprint — never the value).

## Install

```sh
# local checkout
pi install /home/kslam/piext/pi-secure

# published release
pi install git:github.com/kslamph/pi-secure@vX.Y.Z
```

## Status and known gaps

Working: capture-on-paste, the `/sec` command family, masked entry, clipboard-only restore,
`{{sec:NAME}}` expansion through bash (child env only) and other tool arguments, value-exact and
shape scrubbing at `tool_result`, `message_end`, `context` and `before_provider_request`, rewriting
of pi's truncated-output snapshot, and amendment of compaction summaries in the session file (the one
model-authored text pi persists without passing through `message_end`).

The canary suite asserts on what actually leaves the machine, not only on files: pi-ai's real
provider implementations invoke `options.onPayload` but the faux provider does not, so the harness
injects that callback itself — otherwise `before_provider_request` would never run under test and the
central claim above would be asserted by nothing.

Also working now: `{{sec:NAME}}` completes in the editor from the vault (names only), and a bash
command that would write a ref to a file warns **you** — never the model — while still running.

### What is actually load-bearing

`context`, `message_end` and `tool_result` are the guarantee: they fire on every request and
before anything is persisted. `before_provider_request` is an **extra, provider-dependent** layer —
pi-ai invokes it from inside each provider's own api implementation, and pi-secure measures whether
it actually ran (it tells you once if a provider never invokes it, rather than degrading silently).

spec §3's table of pi internals is executable: `test/mechanics.test.ts` asserts each one, so a pi
upgrade that moves something fails by name instead of surfacing later as a mystery.

Known gaps, in rough order of how much they should worry you:

1. **`read`/`grep` on a credential file re-opens the hole** if you turn the flag off. Masking is
   now the **default** (it used to be opt-in, which left this as the design's largest hole: the flag
   only ever affected `read`/`grep`/`find`/`ls`, while `cat` of the same file through `bash` was
   always masked, so the old default closed one side door and left the front one open). Pass
   `--sec-file-reads=false` only when you need to round-trip a credential-bearing file through
   `read` → `edit`; the cost is that the raw contents reach your endpoint.
2. **Transformed secrets escape masking.** `base64`, `cut`, `rev`, hashing — shape matching is
   hygiene, not a boundary. A *truncated* encoding is now masked (Task 16, window match on the
   head/tail of each derived encoding); only a run cut mid-wrap degrades to masked-up-to-the-wrap,
   which is pinned as an accepted residual.
3. **Bash lexical coverage was partial; Task 15 phase 2 closed it.** Unusual heredoc delimiters
   (`<<1`, `<<E-O-F`, `<<EOF.txt`), heredoc operators inside comments, `$((…<<…))` arithmetic
   context, and subshell-vs-command-substitution `)` are all handled by the single-pass scanner.
4. **`!` user-bash pastes are not captured** (known hole). `/export` round-trip is now covered by
   an integration test that exports the real session to HTML and greps the payload.
5. **A child process's environment is readable by any process of the same user.** `bash` already
   hands the model your user's full read access (`~/.ssh`, `~/.aws/credentials`, pi's own
   `auth.json`), so this is not a new hole — but it belongs in the record: the value is delivered
   through the child's environment, which is `owner`-readable at `/proc/<pid>/environ` for as long
   as the command runs. A fd-based handoff would avoid it and needs spawn support from pi.
6. No defense against an actively hostile endpoint — see the threat model below.

## Explicit threat model

**What we are defending against:** a model endpoint that **records** what you send it — a reseller, a random OpenAI-compatible proxy, a gateway with retention, a human reviewing logs. The token must simply never be in the bytes that leave the machine, nor in the transcript that would reveal it on a later turn.

**What we are explicitly *not* defending against:** an endpoint that **actively attacks you** by steering the model to exfiltrate. That is not solvable at this layer, and pretending otherwise is worse than saying so:

- `bash` gives the model (and therefore its puppeteer) full read access as your user: `~/.aws/credentials`, `~/.ssh`, `~/.pi/agent/auth.json`, any `.env` in the repo.
- A ref is a capability handle. Anyone who can direct the model can spend it, and can reconstruct any secret by slicing it in a shell (`printf '%s' "$VAR" | cut -c1-8`), because redaction matches whole known values.
- pi ships **no sandbox** by design.

For an actively hostile endpoint the answer is a sandbox boundary with egress substitution — see pi's `docs/containerization.md` (the `sbx` pattern). pi-secure is a complement to that, not a substitute.

## License

MIT
