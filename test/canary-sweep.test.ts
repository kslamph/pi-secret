import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

/**
 * The standalone sweep is a CI step (`npm run test:canary` -> node
 * scripts/canary-sweep.mjs) whose entire job is to be an SDK-independent backstop:
 * grep the filesystem for the canary and fail the build on a hit.
 *
 * A 2026-10-08 review found it could not fail. `SWEEP_ROOTS` defaulted to
 * `${cwd}/.pi/sessions`, while every session the integration suite creates lives under
 * `mkdtempSync(tmpdir(), "pi-secret-sessions-")`. Nothing in CI ever writes to
 * `.pi/sessions`, `walk()` swallows a missing directory, and the script printed
 * "canary sweep clean across 1 roots" and exited 0 — unconditionally, whether or not
 * scrubbing worked. It was reporting success while examining nothing.
 *
 * So these tests assert two things, and the second is the one that generalises: a
 * sweep that examined no files at all must NOT report clean.
 */
const SWEEP = new URL("../scripts/canary-sweep.mjs", import.meta.url).pathname;
const FIXTURE_CANARY = "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8";

const created: string[] = [];
function scratch(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  created.push(dir);
  return dir;
}

function sweep(env: Record<string, string> = {}): { status: number; out: string } {
  try {
    const out = execFileSync(process.execPath, [SWEEP], {
      encoding: "utf8",
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { status: 0, out };
  } catch (error) {
    const e = error as { status?: number; stdout?: string; stderr?: string };
    return { status: e.status ?? -1, out: `${e.stdout ?? ""}${e.stderr ?? ""}` };
  }
}

afterEach(() => {
  for (const dir of created.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("canary sweep", () => {
  it("fails the build when a canary is present in a scanned root", () => {
    const root = scratch("pi-secret-sweep-hit-");
    writeFileSync(join(root, "session.jsonl"), `{"text":"token=${FIXTURE_CANARY}"}`);
    const result = sweep({ SWEEP_ROOTS: root });
    expect(result.status).not.toBe(0);
    expect(result.out).toContain("contains a canary");
  });

  it("passes on a root that is scanned and clean", () => {
    const root = scratch("pi-secret-sweep-clean-");
    writeFileSync(join(root, "session.jsonl"), '{"text":"token={{sec:gh_pat}}"}');
    expect(sweep({ SWEEP_ROOTS: root }).status).toBe(0);
  });

  it("refuses to report clean when it examined no files at all", () => {
    // The failure mode this project cannot afford twice: a safety gate that cannot
    // fail. An empty root means the sweep proved nothing, which is not the same as
    // proving nothing was found.
    const root = scratch("pi-secret-sweep-empty-");
    const result = sweep({ SWEEP_ROOTS: root });
    expect(result.status).not.toBe(0);
    expect(result.out).toMatch(/no files|examined nothing|clean across 0/i);
  });

  it("refuses to report clean when the root does not exist", () => {
    const result = sweep({ SWEEP_ROOTS: join(tmpdir(), "pi-secret-sweep-does-not-exist") });
    expect(result.status).not.toBe(0);
  });

  it("reaches the real session directories by default, with no SWEEP_ROOTS", () => {
    // The suite writes sessions under os.tmpdir()/pi-secret-sessions-*. The default
    // roots must cover that location, or the standalone CI step audits nothing.
    const sessionDir = scratch("pi-secret-sessions-");
    writeFileSync(join(sessionDir, "leaked.jsonl"), `{"text":"${FIXTURE_CANARY}"}`);
    const result = sweep();
    expect(result.status).not.toBe(0);
    expect(result.out).toContain("contains a canary");
  });

  it("reaches pi's bash truncation snapshots by default", () => {
    const snapshot = join(tmpdir(), `pi-bash-${process.pid}-canary-sweep`);
    created.push(snapshot);
    writeFileSync(snapshot, `full output: ${FIXTURE_CANARY}`);
    try {
      const result = sweep();
      expect(result.status).not.toBe(0);
      expect(result.out).toContain("contains a canary");
    } finally {
      rmSync(snapshot, { force: true });
    }
  });

  it("scans the repo-local .pi/sessions when a real session lives there", () => {
    // Guard the other direction: a repo-local sweep must keep working, so the fix
    // is not simply "delete the root".
    const root = scratch("pi-secret-repo-sessions-");
    mkdirSync(root, { recursive: true });
    writeFileSync(join(root, "s.jsonl"), FIXTURE_CANARY);
    expect(sweep({ SWEEP_ROOTS: root }).status).not.toBe(0);
  });
});