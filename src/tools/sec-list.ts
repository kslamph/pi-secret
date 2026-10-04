import type { ToolDefinition } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import type { Vault } from "../vault.ts";

/**
 * The model's only window into the vault, and the carrier of the one rule it has to
 * learn. Value-free by construction: entries are the vault's `PublicEntry`
 * projection, which has no `value` field to leak.
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
      const lines = entries.map((e) => `sec:${e.name} · len ${e.length} · sha256:${e.fingerprint} · ${e.tier}-only`);
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
