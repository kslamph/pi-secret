import { Box, Text, type Component } from "@earendil-works/pi-tui";
import type { Theme } from "@earendil-works/pi-coding-agent";

export interface ReceiptItem {
  name: string;
  length: number;
  fingerprint: string;
  source: "prompt" | "paste";
}

export interface Receipt {
  captured: ReceiptItem[];
}

/**
 * Custom entries do not participate in LLM context, so a receipt is the one place
 * a capture can be recorded without putting anything sensitive in front of the
 * model. It is value-free by construction: name, length, fingerprint only.
 */
export const RECEIPT_TYPE = "pi-secure-receipt";

export function buildReceiptComponent(receipt: Receipt, theme: Theme): Component {
  const box = new Box(1, 1, (t) => theme.bg("customMessageBg", t));
  for (const c of receipt.captured) {
    box.addChild(
      new Text(
        `${theme.fg("accent", "captured")} ${theme.fg("toolTitle", `sec:${c.name}`)} · ` +
          theme.fg("dim", `len ${c.length} · sha256:${c.fingerprint} · this session only`),
        0,
        0,
      ),
    );
  }
  box.addChild(
    new Text(
      theme.fg("dim", "  /sec restore copies it back to your clipboard · /sec list manages · the value never entered the transcript"),
      0,
      0,
    ),
  );
  return box;
}
