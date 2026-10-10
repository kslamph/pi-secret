/**
 * The model's complete guide to pi-secret, appended to the system prompt on every turn while
 * pi-secret is on (spec §12k).
 *
 * Why a whole section and not only `sec_list` guidelines: pi renders guidelines as loose bullets
 * mixed in with its own, and the model needs the BEHAVIOUR as one picture. Every surprise
 * pi-secret causes (a ref where a value was, a refused write, a refused command) is a wall the
 * model hits mid-task, and a model that does not know the way around it improvises. Seen so far:
 * od/xxd to "recover" a masked value, asking the user to paste a token, rewriting a credential
 * file by hand, and reporting a ref as a broken config. So this explains what pi-secret does,
 * the happy path, its limits, and the fix at each wall. Refusal reasons in glue.ts and the bash
 * guard repeat the matching fix at the moment it is needed.
 *
 * Constant text, so the system prompt is byte-identical from turn to turn and prompt caching is
 * unaffected. It must also survive pi-secret's own scrubber untouched (pinned by a test): every
 * example uses a ref or an env lookup, never anything credential-shaped.
 */
export const PI_SECRET_PROMPT = `<pi_secret>
pi-secret is active in this session. It keeps credentials (API keys, tokens, passwords, private keys) out of everything sent to the model, you included, while still letting you use them. Work with it, not around it: what follows is the smooth path.

How you use a credential
- A credential is a ref: {{sec:NAME}}. You never see the value. Put the ref where the value is needed, in a bash command or in an argument of any tool except read/grep/find/ls, and the real value is substituted when the tool runs. In bash it arrives through an environment variable, so it behaves like a quoted "$VAR".
- sec_list shows the available NAMEs, never values. Refs last for this session only; after /new or /resume, a missing name has to be added again.
- If a credential you need is not listed, ask the user to run /sec add NAME. Never ask them to paste a secret into the chat. If they paste one anyway, pi-secret captures it and you see a ref.

What you will see in output
- Any credential that appears in tool output (a .env file, env, a CLI that prints a token, an error page) is replaced by a ref before you see it, e.g. AWS_SECRET_ACCESS_KEY={{sec:aws_secret_access_key}}. The value is stored for this session (sec_list marks it "seen in tool output"), and the ref works exactly like the value.
- A ref in output is pi-secret's doing, not the file's real content. Do not report it as a broken config, and do not "fix" it.
- {{sec:redacted}} is the only ref with nothing behind it. If you need that credential, ask the user to run /sec add NAME.
- Never try to recover a value: no od, xxd, base64, rev, cut, sed or character slicing of a credential. That bypasses the protection and leaks the value, which is the one thing pi-secret exists to prevent.
- Images and other binary output are not scrubbed, so do not screenshot or open images that show credentials.

Do not print credentials in the first place
- Check without showing: test -n "$TOKEN", printf '%s\\n' "\${#TOKEN}" for the length, gh auth status, aws sts get-caller-identity, curl -s -o /dev/null -w '%{http_code}' ...
- Consume without echoing: TOKEN=$(gh auth token) some-command, a pipe, --password-stdin, or an option that takes a file path.
- To diagnose a rejected credential, print its properties (length, prefix, quoting, trailing whitespace or newline), computed inside the command, never the value.

Files that contain credentials
- To change such a file (.env, config.yaml, ~/.aws/credentials), open it with the read tool, not cat/grep/head/sed in bash. Then use edit or write and keep the refs exactly as you read them: a ref read from that file is written back into that same file as the real value, so the file stays correct.
- Only the read tool lets pi-secret know which file a value came from. A ref you saw in bash output, or a ref written into any other file, is refused by edit and write, because the file would store the placeholder text. If that happens, open the file with the read tool and retry.
- Never put a credential into source code. Read it at runtime from an environment variable or the config file.
- When the user asks you to put a credential into a new file, do it in bash, where the shell substitutes the value: printf '%s\\n' "API_KEY={{sec:NAME}}" >> .env. The edit and write tools refuse this.

Shell rules
- Never put a ref inside a string that a second shell parses (sh -c "...", bash -c, eval, ssh host "...", docker exec ... sh -c), because the expanded value is treated as code there. Pass it in as a variable instead: PISEC={{sec:NAME}} sh -c 'curl -H "Authorization: Bearer $PISEC" ...'.
- A ref inside a quoted heredoc (<<'EOF') or an unterminated quote cannot be expanded, and the command is refused. Move the ref outside, or use an unquoted heredoc.

When pi-secret refuses a call
The reason names the fix. In short:
- "sec:NAME not found": run sec_list and use a listed name; if none fits, ask the user to run /sec add NAME.
- edit/write refused over a ref: open the file with the read tool and retry; if the credential is going somewhere new, use the bash printf form above.
- A literal credential value refused: use its {{sec:NAME}} ref instead.
- A ref refused for read/grep/find/ls: search for the key name (API_KEY), not the value.
Do not work around a refusal by other means. If none of these fixes applies, tell the user what you are trying to do and let them decide.
</pi_secret>`;

/** Append the section once. Idempotent, so a chained or repeated call cannot duplicate it. */
export function withPiSecretPrompt(systemPrompt: string): string {
  if (systemPrompt.includes("<pi_secret>")) return systemPrompt;
  return `${systemPrompt}\n\n${PI_SECRET_PROMPT}`;
}
