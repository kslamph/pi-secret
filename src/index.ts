import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { dropSessionVault, setActiveScopeKey, vaultForSession, type Vault } from "./vault.ts";
import { captureFromText, injectToolCall, scrubOutputSnapshot, scrubToolResult } from "./glue.ts";
import { bashIsOwnedByPiSecure, registerSecureBash } from "./tools/bash.ts";
import { createSecListTool } from "./tools/sec-list.ts";
import { scrubDeep } from "./scrub.ts";
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
function ownsBash(pi: ExtensionAPI): boolean {
  try {
    return bashIsOwnedByPiSecure(pi);
  } catch {
    return true;
  }
}

export default function piSecure(pi: ExtensionAPI): void {
  pi.registerFlag("sec-file-reads", {
    description: "Also mask credential shapes in read/grep output (may break edit round-trips)",
    type: "boolean",
    default: false,
  });

  pi.on("session_start", async (_event, ctx) => {
    setActiveScopeKey(sessionScope(ctx));
    registerSecureBash(pi, ctx.cwd, { vault: () => vault(ctx) });
    pi.registerTool(createSecListTool(() => vault(ctx)));
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
    const out = scrubDeep(event.messages as unknown, vault(ctx), { shapes: true });
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
    const out = scrubDeep(event.message as unknown, vault(ctx), { shapes: true });
    return out.hits ? { message: out.value as never } : undefined;
  });

  pi.on("before_provider_request", (event, ctx) => {
    if (!isEnabled()) return undefined;
    // Last mile: the bytes actually leaving the machine.
    const out = scrubDeep(event.payload as unknown, vault(ctx), { shapes: true });
    return out.hits ? (out.value as never) : undefined;
  });

  pi.registerEntryRenderer(RECEIPT_TYPE, (entry, _options, theme) =>
    buildReceiptComponent(entry.data as Receipt, theme),
  );

  registerCommands(pi);
}
