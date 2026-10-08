import type { ExtensionAPI, ExtensionCommandContext } from "@earendil-works/pi-coding-agent";
import { activeVault, dropActiveVault, type Vault } from "./vault.ts";
import { isValidName } from "./refs.ts";
import { promptMaskedSecret } from "./masked-input.ts";
import { setEnabled } from "./state.ts";

const SEC_USAGE = "usage: /sec add|list|remove|rename|test|restore|off|on [name]";

const VERBS = ["add ", "list", "remove ", "rename ", "test ", "restore ", "off", "on"];

/**
 * One dispatcher rather than eight commands: pi's `registerCommand` takes a bare
 * name, and a single `/sec` means one autocomplete surface and one place where a
 * new verb can be added without touching the registry.
 */
export function registerCommands(pi: ExtensionAPI): void {
  pi.registerCommand("sec", {
    description: "Manage this session's secrets: add | list | remove | rename | test | restore | off | on",
    getArgumentCompletions: (prefix: string) => {
      const trimmed = prefix.trim();
      const items = VERBS.map((v) => ({ value: v, label: `/sec ${v.trim()}` })).filter(
        (i) => trimmed.length === 0 || i.value.startsWith(trimmed),
      );
      return items.length ? items : null;
    },
    handler: async (args, ctx) => {
      await runSecCommand((args ?? "").trim(), activeVault(), ctx);
    },
  });
}

export async function runSecCommand(
  input: string,
  vault: Vault,
  ctx: ExtensionCommandContext,
): Promise<void> {
  const [verb = "", ...rest] = input.split(/\s+/);
  const arg = rest.join(" ").replace(/^sec:/, "");
  switch (verb) {
    case "":
    case "help":
      ctx.ui.notify(SEC_USAGE, "info");
      return;

    case "list": {
      const entries = vault.entries();
      ctx.ui.notify(
        entries.length
          ? entries
              .map((e) => `sec:${e.name} · len ${e.length} · sha256:${e.fingerprint} · ${e.source}`)
              .join("\n")
          : "no secrets in this session",
        "info",
      );
      return;
    }

    case "add": {
      // Validate BEFORE prompting: a bad name must cost the user nothing, and must
      // never reach the masked prompt (which would ask them to paste a value we
      // could not then store).
      if (!isValidName(arg)) {
        ctx.ui.notify(`invalid name (want /^[a-z][a-z0-9_-]{0,63}$/) — ${SEC_USAGE}`, "warning");
        return;
      }
      const value = await promptMaskedSecret(ctx, `Value for sec:${arg} — paste is fine, it is never echoed`);
      if (value === undefined) {
        ctx.ui.notify("cancelled — nothing was stored", "info");
        return;
      }
      try {
        const entry = vault.add(arg, value, "prompt");
        ctx.ui.notify(
          `captured sec:${entry.name} · len ${entry.length} · sha256:${entry.fingerprint} · this session only`,
          "info",
        );
      } catch (error) {
        ctx.ui.notify(`not stored: ${error instanceof Error ? error.message : String(error)}`, "error");
      }
      return;
    }

    case "remove": {
      const removed = vault.remove(arg);
      ctx.ui.notify(
        removed ? `forgot sec:${arg}` : `sec:${arg} was not in the vault`,
        removed ? "info" : "warning",
      );
      return;
    }

    case "rename": {
      const [from = "", to = ""] = arg.split(/\s+/).map((s) => s.replace(/^sec:/, ""));
      try {
        // rename() returns false for unknown/invalid/taken but THROWS on a
        // shell-variable collision, so both channels have to be handled.
        const ok = vault.rename(from, to);
        ctx.ui.notify(
          ok
            ? `sec:${from} is now sec:${to}`
            : `could not rename sec:${from} (unknown, invalid, or sec:${to} already exists)`,
          ok ? "info" : "warning",
        );
      } catch (error) {
        ctx.ui.notify(error instanceof Error ? error.message : String(error), "warning");
      }
      return;
    }

    case "test": {
      const entry = vault.get(arg);
      // Length + fingerprint only: this is how a capture is confirmed without
      // echoing the value back into the terminal or the transcript.
      ctx.ui.notify(
        entry
          ? `sec:${arg} · len ${entry.length} · sha256:${entry.fingerprint} · added ${new Date(entry.addedAt).toISOString()}`
          : `sec:${arg} is not in this session`,
        entry ? "info" : "warning",
      );
      return;
    }

    case "restore": {
      const [{ restoreSecret }, { copyToClipboard }] = await Promise.all([
        import("./restore.ts"),
        import("@earendil-works/pi-coding-agent"),
      ]);
      // The RESULT is the user's only feedback. restoreSecret returns { ok:false,
      // reason } without notifying when the name is unknown, and discarding it made
      // `/sec restore <typo>` completely silent — the user would then paste whatever
      // was already on the clipboard and believe it was the secret they asked for.
      const outcome = await restoreSecret(arg, vault, {
        copy: copyToClipboard,
        notify: (message, level) => ctx.ui.notify(message, level),
      });
      if (!outcome.ok && outcome.reason) ctx.ui.notify(outcome.reason, "warning");
      return;
    }

    case "off":
      setEnabled(false);
      // The values go too. Leaving them in memory would mean "off" stopped handing out
      // new capabilities while every existing ref stayed spendable, which is not what
      // someone who just typed `/sec off` is asking for. Output scrubbing deliberately
      // stays ON: masking is a filter, not a capability — extra masking can only cost the
      // model context it was going to lose anyway, while un-masking would leak.
      dropActiveVault();
      ctx.ui.notify(
        "pi-secure disabled for this session — refs will not expand, and this session's values were cleared. " +
          "Add them again with /sec add if you need them back.",
        "warning",
      );
      return;

    case "on":
      setEnabled(true);
      ctx.ui.notify("pi-secure enabled", "info");
      return;

    default:
      ctx.ui.notify(`unknown subcommand "${verb}" — ${SEC_USAGE}`, "warning");
  }
}
