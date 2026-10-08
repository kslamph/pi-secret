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

## `/sec` commands

One command, `/sec`, with eight subcommands:

| Subcommand | Effect |
|---|---|
| `/sec add <name>` | Enter a value via a masked prompt (characters render as `•`); length + fingerprint shown on confirm. This session only. |
| `/sec list` | List entries: name, length, fingerprint, provenance. Never values. |
| `/sec remove NAME` | Remove an entry from the vault. |
| `/sec rename OLD NEW` | Rename an entry. |
| `/sec test NAME` | Reprint a secret's length + fingerprint so you can confirm a capture without echoing it. |
| `/sec restore NAME` | Copy a captured value back to your clipboard — not into the input line, not into chat, not into a tool result. There is no `sec_reveal` tool, and there never will be one. |
| `/sec off` | Suspend ref injection and capture for this session. A bash command containing `{{sec:…}}` is **refused** with a reason (it is not run with a literal placeholder, which would look like a working credential). Output scrubbing deliberately stays on — extra masking can only cost context, un-masking would leak. |
| `/sec on` | Re-enable pi-secure after `/sec off`. |

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

Known gaps, in rough order of how much they should worry you:

1. **`read`/`grep` on a credential file sends raw secrets to the endpoint** by default. This is the
   largest accepted hole — it trades file round-trip fidelity for logger protection. Flip
   `--sec-file-reads` to mask shapes in file reads too, at the cost of being unable to `edit` a
   credential-bearing file.
2. **Transformed secrets escape masking.** `base64`, `cut`, `rev`, hashing — shape matching is
   hygiene, not a boundary. A *truncated* encoding is now masked (Task 16, window match on the
   head/tail of each derived encoding); only a run cut mid-wrap degrades to masked-up-to-the-wrap,
   which is pinned as an accepted residual.
3. **Bash lexical coverage was partial; Task 15 phase 2 closed it.** Unusual heredoc delimiters
   (`<<1`, `<<E-O-F`, `<<EOF.txt`), heredoc operators inside comments, `$((…<<…))` arithmetic
   context, and subshell-vs-command-substitution `)` are all handled by the single-pass scanner.
4. **`!` user-bash pastes are not captured** (known hole). `/export` round-trip is now covered by
   an integration test that exports the real session to HTML and greps the payload.
5. No defense against an actively hostile endpoint — see the threat model below.

## Explicit threat model

**What we are defending against:** a model endpoint that **records** what you send it — a reseller, a random OpenAI-compatible proxy, a gateway with retention, a human reviewing logs. The token must simply never be in the bytes that leave the machine, nor in the transcript that would reveal it on a later turn.

**What we are explicitly *not* defending against:** an endpoint that **actively attacks you** by steering the model to exfiltrate. That is not solvable at this layer, and pretending otherwise is worse than saying so:

- `bash` gives the model (and therefore its puppeteer) full read access as your user: `~/.aws/credentials`, `~/.ssh`, `~/.pi/agent/auth.json`, any `.env` in the repo.
- A ref is a capability handle. Anyone who can direct the model can spend it, and can reconstruct any secret by slicing it in a shell (`printf '%s' "$VAR" | cut -c1-8`), because redaction matches whole known values.
- pi ships **no sandbox** by design.

For an actively hostile endpoint the answer is a sandbox boundary with egress substitution — see pi's `docs/containerization.md` (the `sbx` pattern). pi-secure is a complement to that, not a substitute.

## License

MIT
