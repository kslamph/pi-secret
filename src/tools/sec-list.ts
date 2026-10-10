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
    // The full guide is the <pi_secret> system-prompt section (src/prompt.ts, spec §12k).
    // These are the rules that must hold even where that section is absent: a host that never
    // fires before_agent_start still lists sec_list, and with it these lines.
    promptGuidelines: [
      "Use {{sec:NAME}} in bash commands and tool arguments wherever a credential is needed; the value is substituted at execution time and you never see it. sec_list lists the NAMEs; if a credential is missing, ask the user to run /sec add NAME. Never ask the user to paste a secret.",
      "A {{sec:NAME}} ref in tool output is a credential pi-secret masked, not file content; use it like the value. Never recover a value with od, xxd, base64, cut or slicing, and never print one: check with test -n or ${#VAR}, and consume it through a pipe or --password-stdin.",
      "To edit a file that holds credentials, open it with the read tool (not cat in bash) and keep its refs as read; they go back into that file as the real values. Refs written to any other file are refused. A refusal's reason names the fix.",
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
