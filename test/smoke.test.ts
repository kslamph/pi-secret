import { describe, expect, it } from "vitest";
import piSecure, { VERSION } from "../src/index.ts";

describe("extension entry", () => {
  it("exports a zero-arg-style factory taking ExtensionAPI", () => {
    expect(typeof piSecure).toBe("function");
    expect(piSecure.length).toBe(1);
  });

  it("reports its version", () => {
    expect(VERSION).toMatch(/^\d+\.\d+\.\d+/);
  });
});
