import type { ToolDefinition } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import type { Vault } from "../vault.ts";

/**
 * The model's only window into the vault, and the carrier of the one rule it has to
 * learn. It never carries a value, or ANY PART of one.
 *
 * It used to print the truncated preview label (`ghp_A1b2…Q7R8`) that the human-facing
 * `/sec list` shows. That is a value-derived string, and this tool's output goes to the
 * provider, so a handful of characters of every real secret were reaching the endpoint
 * — deliberately bounded, but still characters of the secret, on the one surface whose
 * whole purpose is to not send them. The name identifies an entry; the preview only
 * helped a human recognise it, and `/sec list` still shows it where it is read by a
 * person and not by a model (`ctx.ui.notify`, which never enters the transcript).
 *
 * What is left is metadata: the name, the length, and the tier. Length and tier are
 * properties of the entry, not slices of its value.
 */
export function createSecListTool(getVault: () => Vault): ToolDefinition {
  return {
    name: "sec_list",
    label: "sec_list",
    description:
      "List the secret references available in this session. Values are never shown; reference them as {{sec:NAME}} in bash commands or tool arguments.",
    promptSnippet: "List {{sec:NAME}} secret references available in this session",
    promptGuidelines: [
      "Use {{sec:NAME}} in bash commands and tool arguments wherever a credential is needed; sec_list shows the valid NAMEs and the value is substituted at execution time, which you never see.",
      "Use sec_list to find the right secret name before running a command that needs one; if a sec: reference is rejected, run sec_list and retry with a listed name.",
      "Never ask the user to paste a secret, token, password or API key — sec_list is the only source of credentials.",
      // Added 2026-10-10 after a real session where this cost seven thinking blocks. A grep
      // of ~/.bashrc came back masked, and the model could not tell a redaction from file
      // content, so it hypothesised ("maybe bashrc value is literally {{sec:redacted}}",
      // "maybe it's a scrub-marker-wrapped secret") and then went hunting for the credential
      // with od/xxd pipelines. It never learned what to do INSTEAD. The rule needed is not
      // "don't run commands that print secrets" — that is unknowable in advance and the
      // model already tries — but: a redaction is not recoverable, and a value with no name
      // is the user's to store.
      "pi-secret is active: a credential shown as {{sec:NAME}} or {{sec:redacted}} in tool output has been redacted — it is not file content, and it is never recoverable: od, xxd, base64, sed or slicing only bypass the mask and expose the value, which is a leak rather than a workaround. To USE a credential without seeing it, write {{sec:NAME}}; if it has no name, ask the user to run /sec add.",
      // Added the same day for the OTHER half of that incident: diagnosis. Telling the model
      // "never recoverable" and nothing else reads as "don't look", so it either refuses to
      // inspect a credential file or goes back to od/xxd anyway. The session being diagnosed
      // had already invented the right technique on its own — `line chars=84 valuelen=52
      // quoted=no commented=no` — and then discarded it for a raw dump. So the clause names the
      // technique: print the FACTS about a value, never the value, and keep it in the shell.
      "To diagnose a rejected credential, print only its properties — length, prefix class, quoting, trailing whitespace — computed inside the command (e.g. printf '%s' \"${#T}\"), never the value itself; keep the value in the shell.",
      'Never expand a {{sec:NAME}} ref inside a string that a second shell will parse — sh -c, bash -c, eval, ssh host "...", docker exec ... sh -c. There the expanded value is treated as source and can execute; export it for the inner command instead, e.g. PISEC="$__PISEC_GH_PAT" sh -c \'curl -H "Authorization: Bearer $PISEC"\'.',
    ],
    parameters: Type.Object({}),
    async execute() {
      const entries = getVault().entries();
      if (!entries.length) {
        return {
          content: [
            { type: "text" as const, text: "No secrets in this session. The user can add one with /sec add <name>." },
          ],
          details: { names: [] as string[] },
        };
      }
      const lines = entries.map((e) => `sec:${e.name} · len ${e.length} · ${e.tier}-only`);
      return {
        content: [
          { type: "text" as const, text: `Available secrets (values are never shown):\n${lines.join("\n")}` },
        ],
        // Names only — details are persisted, so they must be value-free by
        // construction rather than by filtering.
        details: { names: entries.map((e) => e.name) },
      };
    },
  } as ToolDefinition;
}
