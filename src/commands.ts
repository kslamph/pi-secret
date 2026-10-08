import type { ExtensionAPI, ExtensionCommandContext } from "@earendil-works/pi-coding-agent";
import { activeVault, dropActiveVault, type Vault } from "./vault.ts";
import { isValidName } from "./refs.ts";
import { promptMaskedSecret } from "./masked-input.ts";
import { setEnabled } from "./state.ts";
import { secretLabel } from "./preview.ts";
import { canShowMenu, entryRows, secretRows, selectList, statusLine } from "./menu.ts";
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

/**
 * The question `/sec off` used to skip.
 *
 * `/sec remove` asked before deleting ONE value while `/sec off` deleted EVERY value in the
 * session and asked nothing — the more destructive verb was the unguarded one, and the menu's
 * toggle reached the same action with no guard at all. Both doors go through here.
 *
 * Declining means the whole operation is cancelled, not just the clearing: the question is
 * "clean all keys AND disable sec?", so "no" leaves the extension on with its values spendable.
 *
 * Two cases skip the question. An empty vault has nothing to lose, and asking there is pure
 * ceremony. A context with no UI cannot ask, and silently refusing to disable would be a worse
 * failure than the one this guard prevents — headless `/sec off` keeps working.
 */
async function confirmClearAll(ctx: ExtensionCommandContext, vault: Vault): Promise<boolean> {
  if (!ctx.hasUI || vault.size() === 0) return true;
  return ctx.ui.confirm("Disable pi-secure", "CLEAN ALL KEYS, and disable SEC?");
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
      const off = !isEnabled();
      const header = off
        ? "pi-secure is OFF for this session — refs do not expand and no values are stored."
        : `pi-secure is ON — ${vault.size()} secret(s) this session.`;
      ctx.ui.notify(`${header}\n${formatSecretList(vault.entries())}\n${SEC_USAGE}`, "info");
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
      // Ask BEFORE anything changes: a declined answer must leave the extension enabled with
      // its values intact, which is only possible if the prompt comes first.
      if (!(await confirmClearAll(ctx, vault))) return;
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
      statusLine(isEnabled(), vault.size()),
    );
    if (!choice) return;
    if (choice.kind === "add") {
      await addViaMenu(ctx, vault);
      continue;
    }
    if (choice.kind === "toggle") {
      if (isEnabled()) {
        // Same guard as the verb form: this shortcut clears the session's values, so it asks
        // the same question. Declining changes nothing.
        if (!(await confirmClearAll(ctx, vault))) continue;
        setEnabled(false);
        dropActiveVault();
        ctx.ui.notify("pi-secure disabled and this session's values were cleared", "warning");
      } else {
        setEnabled(true);
        // Re-enabling never restores values: /sec off cleared them, and silently bringing
        // secrets back would make the switch meaningless.
        ctx.ui.notify("pi-secure enabled — add secrets again with /sec", "info");
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
    if (!vault.has(name)) {
      // The entry can disappear while this menu is open — `/sec off` clears the vault from the
      // same UI. Offering rename/remove for something that is gone is worse than returning.
      return;
    }
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
      // Also back to the list: the title of this menu is the OLD name, which no longer resolves.
      return;
    }
    if (choice.kind === "remove") {
      const ok = await ctx.ui.confirm("Remove secret", `Remove sec:${name} from this session?`);
      if (ok) await runSecCommand(`remove ${name}`, vault, ctx);
      // Back to the LIST, not to this entry's menu: the entry is gone now, so staying here
      // would leave the user staring at actions for a secret that no longer exists.
      return;
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
    // Storing a secret while injection is off produces one that cannot be used, and the user
    // would only find out at the point of use. Say so at the point of storage instead.
    ctx.ui.notify(
      isEnabled()
        ? `captured sec:${entry.name} · ${labelOf(entry)} · len ${entry.length} · this session only`
        : `stored sec:${entry.name} · ${labelOf(entry)} · but pi-secure is OFF, so {{sec:${entry.name}}} will NOT expand until you turn it on`,
      isEnabled() ? "info" : "warning",
    );
  } catch (error) {
    ctx.ui.notify(`not stored: ${error instanceof Error ? error.message : String(error)}`, "error");
  }
}
