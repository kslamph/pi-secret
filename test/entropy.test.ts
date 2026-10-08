import { describe, expect, it } from "vitest";
import { isDigestShaped, looksCredentialish, shannonEntropy } from "../src/entropy.ts";

/**
 * B3 (2026-08): these lived in src/scrub.ts, which is where they were written when
 * capture and scrubbing were young enough that sharing a module beat making a new file.
 * They then inverted — the scrubber stopped consuming `looksCredentialish`, leaving
 * capture.ts as the only caller — and a capture-precision predicate living in the masking
 * module is a drift trap.
 *
 * `isDigestShaped` is shared on purpose, and the anchoring is the load-bearing part: a
 * credential with a long hex tail CONTAINS a 40-hex run, so exempting a substring would
 * leave the real secret fully visible. Only a wholly digest-shaped candidate is exempt.
 */
describe("looksCredentialish", () => {
  it("flags entropy-bearing strings", () => {
    expect(looksCredentialish("ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8")).toBe(true);
  });
  it("does not flag git SHAs or prose", () => {
    expect(looksCredentialish("4f9c1a7e2b8d0a3c5e7f1b3d9a2c4e6f8b0d2a4c")).toBe(false);
    expect(looksCredentialish("the quick brown fox jumps over the lazy dog")).toBe(false);
  });
});


describe("isDigestShaped", () => {
  it("exempts a whole digest", () => {
    expect(isDigestShaped("4f9c1a7e2b8d0a3c5e7f1b3d9a2c4e6f8b0d2a4c")).toBe(true);
    expect(isDigestShaped("01890d5c-8c5b-4e1f-9a2b-1c3d4e5f6a7b")).toBe(true);
  });

  it("never exempts a digest that is merely CONTAINED in a credential", () => {
    // The reason this predicate is anchored. `4f9c…a4c` is a git SHA on its own and a
    // 40-hex run inside a real key; only the second one must be judged as a credential.
    const withShaTail = "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R84f9c1a7e2b8d0a3c5e7f1b3d9a2c4e6f8b0d2a4c";
    expect(withShaTail).toContain("4f9c1a7e2b8d0a3c5e7f1b3d9a2c4e6f8b0d2a4c");
    expect(isDigestShaped(withShaTail)).toBe(false);
  });
});

describe("shannonEntropy", () => {
  it("is 0 for an empty string and maximal-ish for uniform randomness", () => {
    expect(shannonEntropy("")).toBe(0);
    expect(shannonEntropy("aaaa")).toBe(0);
    expect(shannonEntropy("abcdefgh")).toBeCloseTo(3, 5);
  });
});
