# pi-secret

**Give the agent your API keys without ever showing it your API keys.**

pi-secret is an extension for the [pi](https://pi.dev/) coding agent. You paste a
credential once; from then on the model uses it by *name* — `{{sec:github_token}}` — and the real value is
substituted only at the moment the command runs.

Nothing else changes. Your token is not in the prompt, not in the request body, not in the session
file, not in `/export`, not in a resumed transcript. But the command that needs it still works.

```
you:    /sec add github_token          →  paste it once, masked
model:  curl -H "Authorization: Bearer {{sec:github_token}}" https://api.github.com/user
        └─ the shell gets the real token; the model only ever sees that line
```

If a command echoes the token back in its output, the model reads `{{sec:github_token}}` again — not `***`, not a
redaction marker. It can hand that straight to its next command, which is the whole point: masking
that destroys the name breaks the round trip, so this one doesn't.

## Install

```sh
pi install npm:pi-secret
```

Other ways in:

```sh
pi install /path/to/pi-secret                    # working checkout
pi install git:github.com/kslamph/pi-secret      # straight from git
pi -e npm:pi-secret                              # try it ephemerally, no install
```

## Quick start

```
/sec add github_token      masked prompt; paste, press enter
/sec                       the menu: what's stored, and what you can do with it
```

Then just tell the agent to use it. It reads `{{sec:NAME}}` and runs
`curl -H "Authorization: Bearer {{sec:github_token}}" https://api.github.com/user`. To see the value yourself, use
`/sec` → the entry → **Copy value to clipboard** (`/sec restore github_token` headless). It goes to
the clipboard and nowhere else — not to the input line, because an editor line is text you submit,
and that would put it back in the transcript.

## What it does

- **Masked entry.** `/sec add` shows a pi dialog where every character renders as a bullet. The
  value never reaches a rendered node, so there is no frame to screenshot.
- **Refs, not replacements.** `{{sec:NAME}}` works in bash commands and tool arguments. The value is
  injected into the child process's environment for that one call — `process.env` itself stays clean,
  so one command's secret cannot reach another concurrent command.
- **Round-trip masking.** Values are masked by *equality* — including base64, hex, URL-encoded and
  uppercase-hex forms — and by *shape*: provider prefixes (`ghp_`, `sk-`, `AKIA…`, `xox…`, `glpat-`,
  `npm_`, `hf_`), PEM blocks, JWTs, and `password=` / `api_key:` / `token:` pairs.
- **Capture on paste.** Paste a credential into the conversation by accident and it is captured into
  the vault and rewritten to a ref *before* anything is persisted. A receipt line names it — the
  name, length and a masked preview, never the value.
- **Import from a file.** `/sec add-from-file` reads a `.env` you name, lists what it found, and adds
  the ones you tick. It shows variable *names* only, hides what does not look like a secret (`TAB`
  reveals everything), and reads nothing until you type a path. Your file is never written to.
- **File reads are masked too.** `read`, `grep`, `find` and `ls` output has credential shapes masked
  by default (`--sec-file-reads=false` to opt out).
- **Session-scoped.** Values live in memory, keyed to one session file. They survive `/reload` and
  are gone on `/new`, `/fork`, `/resume` and exit. `/sec off` clears them immediately, and asks first.
- **Autocomplete.** Typing the ref prefix in the editor completes from the vault — names only, never
  values.
- **Model-facing list.** `sec_list` tells the model which names exist, with a masked preview and the
  length. There is no reveal tool, and there never will be one.

## `/sec`

With no arguments it opens a menu, so you never have to remember a subcommand:

```
─ pi-secret — this session only ──────────────────────────────

  ON · refs expand · output scrubbed · 2 secrets this session

  ❯ gh_pat                    ghp_A1b2…Q7R8 · len 40 · paste · 2m ago
    db_url                    sha256:a1b2c3d4 · len 41 · prompt · 1h ago

    Add a secret…                                              a
    Add from a file…                                           f
    Turn pi-secret off (clears these secrets)                  t

 ↑/↓ move · enter select · a/f/t shortcuts · esc close
```

Enter on a secret opens what you can do with it:

| Row | Key | What it does |
|---|---|---|
| Copy value to clipboard | `c` | The only way to see the value. Clipboard only — never the editor line. |
| Rename… | `r` | Validated before anything moves. |
| Remove from this session | `d` | Asks for confirmation first. |
| Back | `esc` | |

The argument form works everywhere, including headless sessions:

| Form | Effect |
|---|---|
| `/sec add <name>` | Masked prompt, then store. This session only. |
| `/sec add-from-file [path]` | Pick a `.env` (or pass a path), tick the variables to add. |
| `/sec list` | Name, masked preview, length, source and age, one per line. |
| `/sec rename <old> <new>` | Rename, or `/sec remove <name>` to forget it. |
| `/sec restore <name>` | Copy the value to the clipboard. |
| `/sec off` / `/sec on` | Stop or resume. `off` clears this session's values, after a confirmation. |

## How it works

Three ideas, and the interesting one is the third:

1. **A vault, in memory only.** Never written to the session JSONL, custom entries, tool `details`,
   logs or temp files. Keyed by session file, so `/reload` keeps it and `/new` does not.
2. **A reference the model can read but not resolve.** The model writes the ref; that text is what
   gets persisted, so every transcript, export and resume carries the ref.
3. **Expansion at the last moment.** For a bash call, the ref is rewritten to a per-call environment
   variable that exists only in that child process.

Every outbound surface is then scrubbed as a backstop: `tool_result`, `context`, `message_end` and
`before_provider_request`, plus pi's truncated-output snapshots and compaction summaries (the one
model-authored text pi persists without passing through `message_end`).

*Why it is built this way* — and what each layer is actually load-bearing for — is in
[`docs/superpowers/specs/2026-09-12-pi-secret-design.md`](docs/superpowers/specs/2026-09-12-pi-secret-design.md).

## Security model — read this

**Defending against:** an endpoint that *records* what you send it. A reseller, a random
OpenAI-compatible proxy, a gateway with retention, a human reading logs. The token must not be in the
bytes that leave the machine, nor in the transcript that would reveal it on a later turn.

**Not defending against:** an endpoint that *actively attacks* you by steering the model to
exfiltrate. That is not solvable at this layer, and pretending otherwise would be worse than saying
so:

- `bash` gives the model your user's full read access — `~/.aws/credentials`, `~/.ssh`,
  `~/.pi/agent/auth.json`, any `.env` in the repo.
- A ref is a capability handle. Whoever can direct the model can spend it, and can reconstruct a
  value with shell slicing (`printf '%s' "$VAR" | cut -c1-8`), because masking matches whole known
  values.
- Values are delivered through the child's environment, which is readable at `/proc/<pid>/environ`
  by anything running as you, for as long as the command runs.
- pi ships no sandbox by design.

For a hostile endpoint the answer is a sandbox boundary with egress substitution — see pi's
`docs/containerization.md` (the `sbx` pattern). pi-secret complements that; it does not replace it.

### Known gaps

1. **Transformed secrets can escape masking.** `base64 | cut` in combination, hashing, or a slice
   taken mid-encoding degrades to masked-up-to-the-wrap. Shape matching is hygiene, not a boundary.
2. **`!` user-bash output is not captured** into the vault.
3. **A child process's environment is readable by the same user** (above) — a file-descriptor
   handoff would avoid it and needs spawn support from pi.
4. **File imports are dotenv only** — no JSON/YAML/INI, and no `$VAR` interpolation: values are
   stored exactly as written and flagged when they contain an unexpanded reference.

## Development

```sh
npm test             # unit, component and integration tests
npm run typecheck    # tsc --noEmit
npm run test:canary  # end-to-end: assert secrets never reach a transcript, then sweep the filesystem
```

The canary suite is the gate that matters: it drives real sessions and asserts on what actually
leaves the machine, including the provider payload — pi-ai's real providers invoke `options.onPayload`
and the faux provider does not, so the harness injects that callback itself. A separate sweep then
greps every session, snapshot and temp file for the canary and fails the build on a hit.

## License

MIT
