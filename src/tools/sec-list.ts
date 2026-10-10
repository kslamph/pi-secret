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
      // Prevention. The cheapest leak to handle is the one that never prints: the model
      // usually CAN verify or consume a credential without echoing it, it just reaches for
      // `cat`/`echo` first. Naming the alternatives is what changes that habit.
      "Avoid commands that print credential values. Check a credential without showing it (test -n \"$TOKEN\", printf '%s' \"${#TOKEN}\", gh auth status, aws sts get-caller-identity) and pass it straight to its consumer (TOKEN=$(gh auth token) cmd, a pipe, --password-stdin) instead of echoing it.",
      // The cure, rewritten 2026-10-11. The previous text told the model a masked value was
      // "never recoverable" and to ask the user for /sec add, because masked shapes all became
      // {{sec:redacted}}. A session on 2026-10-10 spent seven thinking blocks guessing what
      // that marker meant and then hunted the value with od/xxd. Shape matches are now stored
      // in the vault and come back as usable refs, so the instruction is simply: use it.
      "pi-secret is active: a credential that appears in tool output is shown to you as a {{sec:NAME}} ref; the real value is kept for this session. It is not file content. Use the ref directly in your next bash command or tool argument and it behaves exactly like the value. Do not try to recover the value with od, xxd, base64, sed or slicing; that bypasses the mask and leaks it. Only {{sec:redacted}} is unusable; if you need that credential, ask the user to run /sec add.",
      // §12j. Without this the model avoids editing a credential file it has read, or rewrites
      // the ref line by hand; it does not know the ref goes back in for that file.
      "When you edit or write a file you read with the read tool, keep its {{sec:NAME}} refs as they are: a ref read from that file is written back into it as the real value. A ref written into any other file is refused.",
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
      const lines = entries.map(
        (e) => `sec:${e.name} · len ${e.length} · ${e.tier}-only${e.source === "output" ? " · seen in tool output" : ""}`,
      );
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
