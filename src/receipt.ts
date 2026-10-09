import { Box, Text, type Component } from "@earendil-works/pi-tui";
import type { Theme } from "@earendil-works/pi-coding-agent";

export interface ReceiptItem {
  name: string;
  length: number;
  fingerprint: string;
  label: string;
  source: "prompt" | "paste";
  /**
   * Why this was captured, when the reason is a judgement rather than a format.
   *
   * Rendered in the dim tail so a shape-only capture is distinguishable from a
   * keyword hit after the fact, which is the whole difference between "the tool was
   * wrong and I can find out why" and a mystery.
   */
  evidence?: string;
}

export interface Receipt {
  captured: ReceiptItem[];
}

/**
 * Custom entries do not participate in LLM context, so a receipt is the one place
 * a capture can be recorded without putting anything sensitive in front of the
 * model. It carries name, length and a LABEL — a truncated, value-derived preview like
 * `ghp_A1b2…Q7R8`, which is what lets a person recognise the key they just pasted without
 * reading it out. Nothing here ever carries the value itself.
 */
export const RECEIPT_TYPE = "pi-secret-receipt";

export function buildReceiptComponent(receipt: Receipt, theme: Theme): Component {
  const box = new Box(1, 1, (t) => theme.bg("customMessageBg", t));
  for (const c of receipt.captured) {
    box.addChild(
      new Text(
        `${theme.fg("accent", "captured")} ${theme.fg("toolTitle", `sec:${c.name}`)} · ` +
          theme.fg("dim", `${c.label} · len ${c.length} · this session only${c.evidence ? ` · ${c.evidence}` : ""}`),
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
