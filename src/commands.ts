import type { ExtensionAPI, ExtensionCommandContext } from "@earendil-works/pi-coding-agent";
import { activeVault, dropActiveVault, type Vault } from "./vault.ts";
import { isValidName } from "./refs.ts";
import { promptMaskedSecret } from "./masked-input.ts";
import { setEnabled } from "./state.ts";
import { secretLabel } from "./preview.ts";
import { canShowMenu, entryRows, secretRows, selectList, type SecAction } from "./menu.ts";
import { isEnabled } from "./state.ts";
import type { PublicEntry } from "./vault.ts";

/** The public entry carries its own preview; short values fall back to the digest. */
const labelOf = (e: PublicEntry): string => e.preview ?? `sha256:${e.fingerprint}`;

const SEC_USAGE = "usage: /sec [add <name> | list | remove <name> | rename <old> <new> | restore <name> | off | on]";

// Argument form. The MENU is the primary surface — `/sec` with no arguments opens it — and
// this list exists as the escape hatch for scripting, for headless sessions where there is no
// menu to draw, and for the completion provider. `test` used to be here; it printed one entry
// with a timestamp, which is now a column in the list, so it was redundant and confusingly
// named (it never contacted any provider, so "test" invited an expectation it never met).
const VERBS = ["add ", "list", "remove ", "rename ", "restore ", "off", "on"];

/**
 * One dispatcher rather than eight commands: pi's `registerCommand` takes a bare
 * name, and a single `/sec` means one autocomplete surface and one place where a
 * new verb can be added without touching the registry.
 */
export function registerCommands(pi: ExtensionAPI): void {
  pi.registerCommand("sec", {
    description: "This session's secrets — opens a menu; or add | list | remove | rename | restore | off | on",
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
      // No arguments: the menu, when there is a terminal to draw one in. Otherwise the same
      // content as plain text, so headless and scripted use still work.
      if (canShowMenu(ctx)) {
        await runSecMenu(ctx, vault);
        return;
      }
      ctx.ui.notify(`${formatSecretList(vault.entries())}\n${SEC_USAGE}`, "info");
      return;

    case "help":
      ctx.ui.notify(SEC_USAGE, "info");
      return;

    case "list": {
      ctx.ui.notify(formatSecretList(vault.entries()), "info");
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
          `captured sec:${entry.name} · ${labelOf(entry)} · len ${entry.length} · this session only`,
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

/** The plain-text form of the list, shared by `/sec list` and by a headless `/sec`. */
export function formatSecretList(entries: readonly PublicEntry[]): string {
  if (!entries.length) return "no secrets in this session";
  return entries
    .map(
      (e) =>
        `sec:${e.name} · ${labelOf(e)} · len ${e.length} · ${e.source} · added ${new Date(e.addedAt).toISOString()}`,
    )
    .join("\n");
}

/**
 * The `/sec` menu loop.
 *
 * Two levels and a loop rather than one long verb string: the top level is what the user sees
 * when they type `/sec`, and every action lives one keypress away from there. Rename and
 * removal use the BUILT-IN input and confirm dialogs instead of hand-rolled ones — they need
 * no shortcuts, and reusing them means one less input implementation to keep correct.
 */
export async function runSecMenu(ctx: ExtensionCommandContext, vault: Vault): Promise<void> {
  for (;;) {
    const choice = await selectList(
      ctx,
      "pi-secure — this session only",
      secretRows(vault.entries(), { enabled: isEnabled() }),
      { a: { kind: "add" }, t: { kind: "toggle" } },
    );
    if (!choice) return;
    if (choice.kind === "add") {
      await addViaMenu(ctx, vault);
      continue;
    }
    if (choice.kind === "toggle") {
      setEnabled(!isEnabled());
      if (isEnabled()) {
        // Re-enabling never restores values: /sec off cleared them, and silently bringing
        // secrets back would make the switch meaningless.
        ctx.ui.notify("pi-secure enabled — add secrets again with /sec", "info");
      } else {
        dropActiveVault();
        ctx.ui.notify("pi-secure disabled and this session's values were cleared", "warning");
      }
      continue;
    }
    if (choice.kind === "entry") {
      await entryMenuLoop(ctx, vault, choice.name);
      continue;
    }
  }
}

async function entryMenuLoop(
  ctx: ExtensionCommandContext,
  vault: Vault,
  name: string,
): Promise<void> {
  for (;;) {
    const choice = await selectList(ctx, `sec:${name}`, entryRows(name), {
      c: { kind: "copy", name },
      r: { kind: "rename", name },
      d: { kind: "remove", name },
    });
    if (!choice || choice.kind === "back") return;
    if (choice.kind === "copy") {
      await runSecCommand(`restore ${name}`, vault, ctx);
      continue;
    }
    if (choice.kind === "rename") {
      const next = await ctx.ui.input(`Rename sec:${name}`, "new name");
      if (next === undefined) continue;
      const target = next.trim().replace(/^sec:/, "");
      if (!isValidName(target)) {
        ctx.ui.notify(`invalid name (want /^[a-z][a-z0-9_-]{0,63}$/)`, "warning");
        continue;
      }
      try {
        await runSecCommand(`rename ${name} ${target}`, vault, ctx);
      } catch {
        /* runSecCommand already reported it */
      }
      return;
    }
    if (choice.kind === "remove") {
      const ok = await ctx.ui.confirm("Remove secret", `Remove sec:${name} from this session?`);
      if (ok) await runSecCommand(`remove ${name}`, vault, ctx);
      continue;
    }
  }
}

/** Add from the menu: name first (validated before any prompt), then the masked value. */
async function addViaMenu(ctx: ExtensionCommandContext, vault: Vault): Promise<void> {
  const entered = await ctx.ui.input("New secret name", "github_token");
  if (entered === undefined) return;
  const name = entered.trim().replace(/^sec:/, "");
  if (!isValidName(name)) {
    ctx.ui.notify(`invalid name (want /^[a-z][a-z0-9_-]{0,63}$/)`, "warning");
    return;
  }
  if (vault.has(name)) {
    ctx.ui.notify(`sec:${name} already exists — rename or remove it first`, "warning");
    return;
  }
  const value = await promptMaskedSecret(ctx, `Value for sec:${name} — paste is fine, it is never echoed`);
  if (value === undefined) {
    ctx.ui.notify("cancelled — nothing was stored", "info");
    return;
  }
  try {
    const entry = vault.add(name, value, "prompt");
    ctx.ui.notify(`captured sec:${entry.name} · ${labelOf(entry)} · len ${entry.length} · this session only`, "info");
  } catch (error) {
    ctx.ui.notify(`not stored: ${error instanceof Error ? error.message : String(error)}`, "error");
  }
}
