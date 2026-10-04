import type { Vault } from "./vault.ts";

export interface RestoreIo {
  copy(text: string): Promise<void>;
  notify(message: string, level: "info" | "warning" | "error"): void;
  // Deliberately NO editor/setEditor channel: ctx.ui.setEditorText() prefills the
  // input the user submits, which would write the secret into the session
  // transcript. Omitting the parameter makes that leak unrepresentable rather
  // than merely commented against (controller ruling, spec 6.2).
}

/**
 * The escape hatch that makes silent capture safe: the user gets the value back
 * through their own machine — the clipboard — and never through the transcript.
 */
export async function restoreSecret(
  name: string,
  vault: Vault,
  io: RestoreIo,
): Promise<{ ok: boolean; reason?: string }> {
  const entry = vault.get(name);
  if (!entry) return { ok: false, reason: `sec:${name} is not in this session` };
  try {
    await io.copy(entry.value);
  } catch (error) {
    const reason = `clipboard unavailable (${error instanceof Error ? error.message : "unknown"}) — nothing was revealed`;
    // The failure is told to the user and to the caller separately; neither
    // message carries the value.
    io.notify(`could not restore sec:${name} to the clipboard`, "error");
    return { ok: false, reason };
  }
  io.notify(`sec:${name} is on your clipboard · len ${entry.length} · sha256:${entry.fingerprint}`, "info");
  io.notify("the value was not placed in the editor — typing it there would persist it", "warning");
  return { ok: true };
}
