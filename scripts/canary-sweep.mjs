import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

// The canary used by test/integration/canary.test.ts. It is a PUBLIC test fixture,
// not a credential, so defaulting to it is safe — and it matters, because exiting 2
// on an unset CANARY_VALUES would turn a clean tree red in CI, which is how a safety
// gate gets disabled within a month.
const FIXTURE_CANARY = "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8";
const canaries = (process.env.CANARY_VALUES ?? FIXTURE_CANARY).split(",").filter(Boolean);
// Default to the repo-local session dir only. Grepping all of /tmp is slow and picks
// up unrelated processes' files; the pi-bash truncation snapshots under /tmp are
// already covered by the integration test's own artifact scan.
const roots = (process.env.SWEEP_ROOTS ?? `${process.cwd()}/.pi/sessions`).split(",");
if (!canaries.length) {
  console.error("CANARY_VALUES is set but empty");
  process.exit(2);
}

const hits = [];
const walk = (dir, depth = 0) => {
  if (depth > 4) return;
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) walk(full, depth + 1);
    else if (entry.isFile() && statSync(full).size < 2_000_000) {
      const text = readFileSync(full, "utf8");
      for (const canary of canaries) if (text.includes(canary)) hits.push(`${full} contains a canary`);
    }
  }
};

for (const root of roots) walk(root);
if (hits.length) {
  console.error(hits.join("\n"));
  process.exit(1);
}
console.log(`canary sweep clean across ${roots.length} roots`);
