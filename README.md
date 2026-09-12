# pi-secure

pi-secure is an extension for the [pi](https://github.com/badlogic/pi-mono) coding agent that keeps credentials out of everything an LLM endpoint can see — request bodies, session files, transcripts, exports — while letting the model *use* those credentials in shell commands and tool calls without friction. You should never have to paste a token into a conversation, and if you do, it should not end up in the conversation.

> **Status:** as of v0.0.1 this repository ships the package scaffold only (entry stub + tests); the behavior described below lands in Tasks 2–14.

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
| `/sec add [name]` | Enter a value via a masked prompt (characters render as `•`); length + fingerprint shown on confirm. This session only. |
| `/sec list` | List entries: name, length, fingerprint, provenance. Never values. |
| `/sec remove NAME` | Remove an entry from the vault. |
| `/sec rename OLD NEW` | Rename an entry. |
| `/sec test NAME` | Reprint a secret's length + fingerprint so you can confirm a capture without echoing it. |
| `/sec restore NAME` | Copy a captured value back to your clipboard — never into chat, never into a tool result. There is no `sec_reveal` tool. |
| `/sec off` | Suspend pi-secure for this session. |
| `/sec on` | Re-enable pi-secure after `/sec off`. |

Pasting a credential into the conversation also works: high-confidence secrets are captured into the vault and rewritten to a ref before anything is persisted, with a receipt line left in the transcript (name, length, fingerprint — never the value).

## Install

```sh
# local checkout
pi install /home/kslam/piext/pi-secure

# published release
pi install git:github.com/kslamph/pi-secure@vX.Y.Z
```

## Explicit threat model

**What we are defending against:** a model endpoint that **records** what you send it — a reseller, a random OpenAI-compatible proxy, a gateway with retention, a human reviewing logs. The token must simply never be in the bytes that leave the machine, nor in the transcript that would reveal it on a later turn.

**What we are explicitly *not* defending against:** an endpoint that **actively attacks you** by steering the model to exfiltrate. That is not solvable at this layer, and pretending otherwise is worse than saying so:

- `bash` gives the model (and therefore its puppeteer) full read access as your user: `~/.aws/credentials`, `~/.ssh`, `~/.pi/agent/auth.json`, any `.env` in the repo.
- A ref is a capability handle. Anyone who can direct the model can spend it, and can reconstruct any secret by slicing it in a shell (`printf '%s' "$VAR" | cut -c1-8`), because redaction matches whole known values.
- pi ships **no sandbox** by design.

For an actively hostile endpoint the answer is a sandbox boundary with egress substitution — see pi's `docs/containerization.md` (the `sbx` pattern). pi-secure is a complement to that, not a substitute.

## License

MIT
