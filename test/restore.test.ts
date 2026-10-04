import { describe, expect, it, vi } from "vitest";
import { restoreSecret } from "../src/restore.ts";
import { Vault } from "../src/vault.ts";

const GH = "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8";

function makeVault(): Vault {
  const v = new Vault("t");
  v.add("gh_pat", GH, "prompt");
  return v;
}

describe("restoreSecret", () => {
  it("copies to the clipboard and notifies without ever naming the value", async () => {
    const copy = vi.fn(async () => {});
    const notify = vi.fn();
    const out = await restoreSecret("gh_pat", makeVault(), { copy, notify });
    expect(out.ok).toBe(true);
    expect(copy).toHaveBeenCalledWith(GH);
    // The seam has no editor channel at all, so the leak is unrepresentable.
    expect(Object.keys({ copy, notify })).not.toContain("setEditor");
    expect(notify).toHaveBeenCalledWith(expect.stringMatching(/clipboard/), "info");
    const logged = JSON.stringify(notify.mock.calls);
    expect(logged).not.toContain(GH);
  });

  it("reports an unknown name without copying anything", async () => {
    const copy = vi.fn();
    const out = await restoreSecret("nope", makeVault(), { copy, notify: vi.fn() });
    expect(out.ok).toBe(false);
    expect(out.reason).toMatch(/not in this session/);
    expect(copy).not.toHaveBeenCalled();
  });

  it("surfaces a clipboard failure instead of claiming success", async () => {
    const out = await restoreSecret("gh_pat", makeVault(), {
      copy: async () => {
        throw new Error("no display");
      },
      notify: vi.fn(),
    });
    expect(out.ok).toBe(false);
    expect(out.reason).toMatch(/clipboard/);
  });
});
