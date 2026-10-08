import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { activeVault, dropSessionVault, setActiveScopeKey, vaultForSession, type Vault } from "./vault.ts";
import {
  captureFromText,
  injectToolCall,
  scrubCompactionSummaryFile,
  scrubDeepFailClosed,
  scrubOutputSnapshot,
  scrubToolResult,
} from "./glue.ts";
import { bashIsOwnedByPiSecure, registerSecureBash } from "./tools/bash.ts";
import { createSecListTool } from "./tools/sec-list.ts";
import { bashRedirectWarning } from "./redirect.ts";
import { createSecAutocompleteProvider } from "./autocomplete.ts";
import { RECEIPT_TYPE, buildReceiptComponent, type Receipt, type ReceiptItem } from "./receipt.ts";
import { isEnabled } from "./state.ts";
import { registerCommands } from "./commands.ts";

export const VERSION = "0.0.1";

/**
 * "Session" means one session FILE (spec §7). Keying the vault by it is what makes
 * `/reload` survive — pi re-evaluates this module on reload, so ordinary module
 * state is destroyed — while `/new`, `/fork` and `/resume` land on a different key
 * and therefore a different vault.
 */
function sessionScope(ctx: ExtensionContext): string {
  return ctx.sessionManager.getSessionFile() ?? `ephemeral:${ctx.sessionManager.getSessionId()}`;
}

/**
 * Deliberately NOT `activeVault()`: the dispatcher and tools may be invoked before
 * any session_start has bound a scope, and activeVault() throws when none is. The
 * ctx always carries the session file, so this is total.
 */
function vault(ctx: ExtensionContext): Vault {
  return vaultForSession(sessionScope(ctx));
}

/**
 * The receipt is for auditability, not correctness: if it cannot be written the
 * capture is still valid, so a throwing appendEntry must never cost the user their
 * (already vaulted) secret or abort the turn.
 */
function appendReceipt(pi: ExtensionAPI, captured: ReceiptItem[]): void {
  try {
    pi.appendEntry(RECEIPT_TYPE, { captured } satisfies Receipt);
  } catch {
    /* best-effort: the capture already happened and the vault already holds it */
  }
}

function fileReadsEnabled(pi: ExtensionAPI): boolean {
  try {
    return Boolean(pi.getFlag("sec-file-reads"));
  } catch {
    return false;
  }
}

/**
 * Among extensions the FIRST registration of a tool name wins, so another loaded
 * extension can take `bash` from us silently: refs would then reach the child as
 * literal `{{sec:…}}` text with no error from pi at all. That is worth saying out
 * loud, once per session, but never at the cost of failing session start.
 */
/**
 * Tracks whether pi's provider-level payload hook actually ran. See the `turn_end`
 * handler for why this is measured rather than assumed.
 */
let providerHookFired = false;
let providerHookWarned = false;

function ownsBash(pi: ExtensionAPI): boolean {
  try {
    return bashIsOwnedByPiSecure(pi);
  } catch {
    return true;
  }
}

export default function piSecure(pi: ExtensionAPI): void {
  /**
   * DEFAULT TRUE, which inverts the original design.
   *
   * It shipped as opt-in because masking a credential file's contents was assumed to
   * break the edit round-trip: the model reads `~/.aws/credentials`, gets masked shapes,
   * and can no longer write the file back faithfully. That reasoning was right about the
   * cost and wrong about its size, because of something the original analysis missed:
   * shape masking already applied to EVERY other source of file content. Only
   * `read`/`grep`/`find`/`ls` were excluded, and `cat ~/.aws/credentials` through bash
   * was masked all along. So the flag was closing one side door while leaving the front
   * one open by default — and spec §13.3 called that front door the largest hole in the
   * design.
   *
   * Turning it OFF is still meaningful and is now the escape hatch rather than the
   * default: a user who needs to round-trip a credential-bearing file through
   * read → edit can turn it off and accept that the raw contents reach the endpoint.
   */
  pi.registerFlag("sec-file-reads", {
    description: "Mask credential shapes in read/grep/find/ls output (default on; turn off only to round-trip a credential file through edit)",
    type: "boolean",
    default: true,
  });

  pi.on("session_start", async (_event, ctx) => {
    // A reload rebuilds the extension but not the process, so these two must not be
    // sticky across sessions or the warning would never fire for a later session.
    providerHookFired = false;
    providerHookWarned = false;
    setActiveScopeKey(sessionScope(ctx));
    registerSecureBash(pi, ctx.cwd, { vault: () => vault(ctx) });
    pi.registerTool(createSecListTool(() => vault(ctx)));
    // spec §5's discovery surface: `{{sec:` completes from the vault. It lives on the UI
    // context, not the ExtensionAPI, so it is registered here rather than at load. The
    // provider itself handles being asked before a vault exists (activeVault throws, and
    // the provider returns null) — an autocomplete popup that throws would take the
    // editor's key handling down with it.
    try {
      ctx.ui.addAutocompleteProvider(() => createSecAutocompleteProvider(activeVault));
    } catch {
      // Headless (no UI context): there is no editor to complete in.
    }

    if (!ownsBash(pi)) {
      ctx.ui.notify(
        "pi-secure: another extension owns `bash`, so {{sec:…}} refs will NOT expand. Load pi-secure after it, or disable that extension.",
        "error",
      );
    }
    if (ctx.hasUI) ctx.ui.setStatus("pi-secure", `sec: ${vault(ctx).size()} active`);
  });

  pi.on("session_shutdown", async (event, ctx) => {
    const reason = (event as { reason?: string }).reason;
    // reload keeps the vault (the module is re-evaluated but the registry is not);
    // every other reason is a different session and must not inherit these values.
    if (reason && reason !== "reload") dropSessionVault(sessionScope(ctx));
    if (ctx.hasUI) ctx.ui.setStatus("pi-secure", undefined);
  });

  pi.on("input", async (event, ctx) => {
    if (!isEnabled() || event.source === "extension") return undefined;
    const out = captureFromText(event.text, vault(ctx));
    if (!out.captured.length) return undefined;
    appendReceipt(pi, out.captured);
    ctx.ui.notify(
      out.captured
        .map((c) => `captured sec:${c.name} · len ${c.length} · sha256:${c.fingerprint}`)
        .join("\n"),
      "info",
    );
    if (ctx.hasUI) ctx.ui.setStatus("pi-secure", `sec: ${vault(ctx).size()} active`);
    // The value is already in the vault and the text now carries only the ref, so
    // this transform runs BEFORE persistence — nothing sensitive reaches the file.
    return { action: "transform" as const, text: out.text };
  });

  pi.on("tool_call", async (event, ctx) => {
    if (event.toolName === "bash" && isEnabled()) {
      // spec §9's notify-only row. The command still runs — blocking would break
      // `printf '%s' {{sec:x}} > ~/.netrc`, which is a real thing to want, and the file it
      // lands in is outside our protection anyway.
      //
      // The warning goes to ctx.ui.notify ONLY. It must never enter model context: a model
      // told "your command wrote a masked ref to a file" reliably tries to fix it by
      // rewriting the file, which is exactly the corruption this row exists to avoid. So
      // this hook still returns undefined on the warn path.
      const rawCommand = (event.input as { command?: unknown }).command;
      const warning = bashRedirectWarning(typeof rawCommand === "string" ? rawCommand : "");
      if (warning) ctx.ui.notify(warning.message, "warning");
    }
    if (!isEnabled()) return undefined;
    const out = injectToolCall(event.toolName, event.input as Record<string, unknown>, vault(ctx));
    if (out.blocked) return { block: true, reason: out.blocked.reason };
    return undefined;
  });

  pi.on("tool_result", async (event, ctx) => {
    const v = vault(ctx);
    const out = scrubToolResult(
      { toolName: event.toolName, content: event.content as unknown[], details: event.details },
      v,
      { fileReads: fileReadsEnabled(pi) },
    );
    // pi writes an UNSCRUBBED snapshot when bash truncates, and hands the model a
    // path to read it from — rewrite or drop it before the result is persisted.
    scrubOutputSnapshot(out.details ?? event.details, v);
    if (out.hits && ctx.hasUI) {
      // Never interpolate event.input here: it carries EXPANDED args with real values.
      ctx.ui.notify(`pi-secure masked ${out.hits} secret occurrence(s) in ${event.toolName} output`, "info");
    }
    // Returned unconditionally, including when hits === 0: this hook is the primary
    // guarantee (it runs before the result message is built and persisted), so the
    // caller must never be left deciding what to do with unsanitised text.
    return { content: out.content as never, details: out.details as never, isError: event.isError };
  });

  pi.on("context", async (event, ctx) => {
    if (!isEnabled()) return undefined;
    const out = scrubDeepFailClosed(event.messages as unknown, vault(ctx), { shapes: true }, (cls) =>
      ctx.ui.notify(`pi-secure: context scrub failed closed (${cls})`, "error"),
    );
    return out.hits ? { messages: out.value as never } : undefined;
  });

  /**
   * The assistant's own message is persisted BEFORE any tool result exists, so
   * `tool_result` cannot clean it. If the model ever emits a secret literally in a
   * tool-call argument — which it should never be able to, since refs are the only
   * thing it can see — that literal lands in the session JSONL, and from there in
   * /export and every resume.
   *
   * pi runs message_end handlers BEFORE appendMessage and rewrites the finalized
   * message object in place, so returning a scrubbed copy here is what keeps the
   * literal off disk. Blocking the tool call would not help: the model has already
   * written the message, and refusing to run it leaves the text in the transcript.
   *
   * This is the round-trip property applied to the model's own output: the value is
   * replaced by its ref, so a command written with a literal still executes — the
   * spawnHook expands the ref we put back.
   */
  pi.on("message_end", (event, ctx) => {
    if (!isEnabled()) return undefined;
    const out = scrubDeepFailClosed(event.message as unknown, vault(ctx), { shapes: true }, (cls) =>
      ctx.ui.notify(`pi-secure: message scrub failed closed (${cls})`, "error"),
    );
    return out.hits ? { message: out.value as never } : undefined;
  });

  pi.on("before_provider_request", (event, ctx) => {
    // Recorded BEFORE the enabled check on purpose: this measures whether the HOST
    // provides the hook, which is a property of the provider, not of our switch. A
    // deliberate `/sec off` must not read as a provider defect — and that case is
    // suppressed separately in turn_end.
    providerHookFired = true;
    if (!isEnabled()) return undefined;
    // Last mile: the bytes actually leaving the machine. Note the layering, because it is
    // not uniform: `context` fires on EVERY provider request, while this hook only exists
    // where the provider's own api invokes onPayload (all of pi-ai 0.85.1's do; the faux
    // provider does not, which is why the canary harness has to inject the callback
    // itself). The durable guarantee is context + message_end + tool_result; this is a
    // provider-dependent extra layer, and `turn_end` below measures whether it exists.
    const out = scrubDeepFailClosed(event.payload as unknown, vault(ctx), { shapes: true }, (cls) =>
      ctx.ui.notify(`pi-secure: provider payload scrub failed closed (${cls})`, "error"),
    );
    return out.hits ? (out.value as never) : undefined;
  });

  pi.on("turn_end", async (_event, ctx) => {
    if (providerHookFired || providerHookWarned || !isEnabled()) return;
    providerHookWarned = true;
    ctx.ui.notify(
      "pi-secure: this provider never invoked the payload hook, so the provider-level net is absent. " +
        "The transcript, tool results and model context are still scrubbed — only the final " +
        "provider-specific request body is not double-checked.",
      "warning",
    );
  });

  pi.registerEntryRenderer(RECEIPT_TYPE, (entry, _options, theme) =>
    buildReceiptComponent(entry.data as Receipt, theme),
  );



  /**
   * Compaction is the ONE model-authored text pi persists without passing it through
   * `message_end`, so the summary reaches the session file before this extension has
   * any chance to look at it. The wire is already safe (`context` and
   * `before_provider_request` both scrub outbound), but the file is the transcript of
   * record, and a summary outlives the turn that produced it. So the entry is amended
   * in place, and only when it actually contains something.
   *
   * There is no `message_end` for this text and no public API to amend an entry, hence
   * the targeted rewrite of one JSONL line.
   */
  pi.on("session_compact", async (event, ctx) => {
    const file = ctx.sessionManager.getSessionFile();
    if (!file) return;
    const entry = (event as { compactionEntry?: { id?: string } }).compactionEntry;
    if (!entry?.id) return;
    const out = scrubCompactionSummaryFile(file, entry.id, vault(ctx));
    if (out.rewritten && ctx.hasUI) {
      ctx.ui.notify(`pi-secure masked ${out.hits} secret occurrence(s) in a compaction summary`, "info");
    }
  });

  registerCommands(pi);
}
