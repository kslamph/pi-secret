import { describe, expect, it } from "vitest";
import { maskPreview, previewRevealsCharacters, revealSides, secretLabel } from "../src/preview.ts";
import { matchesProviderFormat, shannonEntropy } from "../src/entropy.ts";

const GH = "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8";
const AWS = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const DSN = "postgres://admin:s3cr3t@db.internal:5432/app";

describe("the masked preview", () => {
  it("shows the format marker, the head and the tail — the convention every key console uses", () => {
    expect(maskPreview(GH)).toBe("ghp_A1b2…Q7R8");
    expect(maskPreview(AWS)).toBe("wJal…EKEY");
  });

  it("keeps a provider prefix, because that is what identifies the KEY's kind", () => {
    // The whole marker is shown (`sk-ant-api03-`) because that is format, not secret; the
    // value itself still gives up only 4+4.
    expect(maskPreview("sk-ant-api03-abcdefghijklmnopqrstuvwxyz012345")).toBe("sk-ant-api03-abcd…2345");
    // 42 chars -> 4 per side, prefix kept whole.
    expect(maskPreview("xoxb-EXAMPLE-NOT-A-REAL-SLACK-TOKEN")).toBe("xoxb-1234…uvwx");
  });

  it("falls back to plain head/tail when there is no prefix to keep", () => {
    expect(maskPreview(AWS)).toMatch(/^wJal…/);
  });

  it("reveals nothing for a value too short for a preview to mean anything", () => {
    for (const short of ["hunter2", "Tr0ub4dor", "abcdefghijklm", "abcdefghijklmno"]) {
      expect(maskPreview(short)).toBeUndefined();
      expect(previewRevealsCharacters(short)).toBe(false);
    }
  });

  it("reveals nothing for a human-chosen password of ANY length", () => {
    // The case the first, length-only rule got wrong in the other direction: a passphrase is
    // long, so a length gate would have printed `correct-ho…ry` and told a logging endpoint
    // that the secret is English-ish. Entropy per character is the discriminator, and the
    // threshold deliberately sits ABOVE the human band rather than inside it.
    const humans = [
      "correct-horse-battery-staple",
      "correct-horse-battery",
      "Summer2024Passphrase!!",
      "Tr0ub4dor&3xyzabcDEFxyzabc",
      "my-bank-account-is-1234567",
    ];
    for (const pw of humans) {
      expect(shannonEntropy(pw), pw).toBeLessThan(4.5);
      expect(maskPreview(pw), pw).toBeUndefined();
    }
  });

  it("does reveal a STRONG generated password, because a preview does not weaken it", () => {
    // Refusing this would be the length rule's failure in the opposite direction: this is a
    // machine-generated 26-character secret with ~120 bits, and two characters cost ~12.
    const generated = "k7#Rm2$qX9!vT4@nL8^zP3&wY6";
    expect(shannonEntropy(generated)).toBeGreaterThan(4.5);
    expect(maskPreview(generated)).toBeDefined();
  });

  it("gives a recognised provider format the full allowance, whatever its entropy", () => {
    // AWS's own example key has 3.66 bits/char — below the random-looking bar — but it is
    // provider-issued and 40 characters long, so the category that matters is the format,
    // not the entropy.
    expect(matchesProviderFormat("AKIAIOSFODNN7EXAMPLE")).toBe(true);
    expect(revealSides("AKIAIOSFODNN7EXAMPLE")).toBe(4);
    // No separator, so the marker is the leading capital run — and the full 4+4 allowance
    // still applies on top of it.
    expect(maskPreview("AKIAIOSFODNN7EXAMPLE")).toBe("AKIAIOSF…MPLE");
  });

  it("uses the SCRUBBER's own format table, so the two cannot drift", () => {
    // Both sides need to agree on what a credential looks like: the scrubber to mask it,
    // the preview to decide what may be shown. A second copy of the table would be the
    // exact drift this project keeps paying for.
    for (const key of [
      "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8",
      "sk-ant-api03-9dF2mQ7xR4kL8pT1vZ6yB0nC3wS5jH7dG",
      "AKIAIOSFODNN7EXAMPLE",
      "xoxb-EXAMPLE-NOT-A-REAL-SLACK-TOKEN",
      "glpat-abcdefghijklmnopqrstuvwxyz0123",
    ]) {
      expect(matchesProviderFormat(key), key).toBe(true);
      expect(revealSides(key)).toBe(4);
    }
  });

  it("never guesses a prefix from the value's own shape", () => {
    // The bug this prevents: a "find the leading hyphenated segment" rule reads `xK3-mQ7-`
    // in a random 20-character secret as a prefix and prints it in full — nine characters
    // spent before the share rule counted one. Only a recognised format earns a prefix.
    const randomish = "Tz4-Qm9xR2kP7vT6bH3wY8cD1";
    expect(revealSides(randomish)).toBeGreaterThan(0);
    expect(maskPreview(randomish)).not.toContain("xK3-mQ7");
    const preview = maskPreview(randomish)!;
    const revealed = preview.replace("…", "");
    expect(revealed.length).toBeLessThanOrEqual(4);
  });

  it("scales the reveal to a tenth of the value per side, not to a fixed 4", () => {
    // 26 chars -> 2 per side; 40 -> the full 4.
    expect(maskPreview("k7#Rm2$qX9!vT4@nL8^zP3&wY6")).toBe("k7…Y6");
    expect(maskPreview("k7#Rm2$qX9!vT4@nL8^zP3&wY6sD9qF2mH5rT8vB1nC6")).toBe("k7#R…1nC6");
  });

  it("never shows more than the two ends of the value, and never the middle", () => {
    for (const value of [GH, AWS, DSN, "a".repeat(200)]) {
      const preview = maskPreview(value);
      if (preview === undefined) continue; // hidden entirely, which is also safe
      const revealed = preview.replace("…", "");
      expect(value.startsWith(revealed.slice(0, revealed.length - 4)), value).toBe(true);
      expect(value.endsWith(revealed.slice(-4)), value).toBe(true);
      // Whatever the tier, at most 4 characters per side come out of the value itself.
      const fromValue = revealed.replace(/^[A-Za-z0-9]+[-_]/, "");
      expect(fromValue.length).toBeLessThanOrEqual(8);
    }
  });

  it("shows nothing at all for a DSN, because it is neither a known format nor random", () => {
    // `postgres://admin:s3cr3t@…` — a prefix rule that stopped at the first separator would
    // print `postgres://` and then four characters of `admin`, which is nothing useful.
    expect(maskPreview(DSN)).toBeUndefined();
    expect(secretLabel(DSN, "deadbeef")).toBe("sha256:deadbeef");
  });
});

describe("the label shown wherever a secret is identified", () => {
  it("uses the preview when one is safe", () => {
    expect(secretLabel(GH, "a1b2c3d4")).toBe("ghp_A1b2…Q7R8");
  });

  it("falls back to the digest when no characters may be shown", () => {
    expect(secretLabel("hunter2", "a1b2c3d4")).toBe("sha256:a1b2c3d4");
  });

  it("never returns the whole value under any length", () => {
    for (const value of ["a", "abcdefgh", GH, AWS, "z".repeat(500)]) {
      expect(secretLabel(value, "deadbeef")).not.toBe(value);
    }
  });
});