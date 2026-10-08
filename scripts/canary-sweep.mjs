import { readdirSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// The canary used by test/integration/canary.test.ts. It is a PUBLIC test fixture,
// not a credential, so defaulting to it is safe — and it matters, because exiting 2
// on an unset CANARY_VALUES would turn a clean tree red in CI, which is how a safety
// gate gets disabled within a month.
const FIXTURE_CANARY = "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8";
const canaries = (process.env.CANARY_VALUES ?? FIXTURE_CANARY).split(",").filter(Boolean);
if (!canaries.length) {
  console.error("CANARY_VALUES is set but empty");
  process.exit(2);
}

/**
 * Where the sweep must actually look.
 *
 * This list used to be `${cwd}/.pi/sessions` alone, which is a directory nothing in
 * this repo ever writes to: the integration suite builds every session under
 * `mkdtempSync(tmpdir(), "pi-secret-sessions-")`, and pi's bash truncation snapshots
 * are `tmpdir()/pi-bash*`. With a missing directory silently walked as zero files,
 * the sweep printed "clean" and exited 0 no matter what pi-secure did. A safety gate
 * that cannot fail is worse than no gate, because it buys the appearance of one.
 *
 * tmpdir is enumerated by NAME PREFIX rather than walked wholesale, so this stays
 * cheap and does not read unrelated processes' files.
 */
const tmp = tmpdir();
const tmpEntries = (() => {
  try {
    return readdirSync(tmp);
  } catch {
    return [];
  }
})();
const DEFAULT_ROOTS = [
  join(process.cwd(), ".pi", "sessions"),
  ...tmpEntries.filter((n) => n.startsWith("pi-secret-sessions-")).map((n) => join(tmp, n)),
  ...tmpEntries.filter((n) => n.startsWith("pi-secret-cwd-")).map((n) => join(tmp, n)),
  ...tmpEntries.filter((n) => n.startsWith("pi-bash")).map((n) => join(tmp, n)),
];
const roots = (process.env.SWEEP_ROOTS ? process.env.SWEEP_ROOTS.split(",") : DEFAULT_ROOTS).filter(Boolean);

const hits = [];
let examined = 0;
/** Roots may be a single snapshot FILE (pi writes `tmpdir()/pi-bash*` as files), not
 *  just a directory, so readdirSync-then-recurse cannot be the only path: on a file
 * root it throws ENOTDIR, walk() returns, and the snapshot goes unread. */
const scanFile = (full) => {
  let size;
  try {
    size = statSync(full).size;
  } catch {
    return;
  }
  if (size >= 2_000_000) return;
  examined++;
  const text = readFileSync(full, "utf8");
  for (const canary of canaries) if (text.includes(canary)) hits.push(`${full} contains a canary`);
};
const walk = (target, depth = 0) => {
  if (depth > 4) return;
  let stat;
  try {
    stat = statSync(target);
  } catch {
    return;
  }
  if (stat.isFile()) {
    scanFile(target);
    return;
  }
  if (!stat.isDirectory()) return;
  let entries;
  try {
    entries = readdirSync(target, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) walk(join(target, entry.name), depth + 1);
};

for (const root of roots) walk(root);

if (hits.length) {
  console.error(hits.join("\n"));
  process.exit(1);
}

/**
 * Examined nothing is NOT the same as examined everything and found nothing. Exiting
 * 0 here is what let the gate pass vacuously; a mis-pointed root must now turn the
 * build red instead of quietly vouching for the whole design.
 */
if (examined === 0) {
  console.error(
    `canary sweep examined no files — that is a vacuous pass, not a clean result.\n` +
      `roots tried (${roots.length}): ${roots.slice(0, 8).join(", ") || "<none>"}${roots.length > 8 ? ", …" : ""}\n` +
      `set SWEEP_ROOTS to the directories that actually hold session and snapshot output.`,
  );
  process.exit(2);
}
console.log(`canary sweep clean across ${roots.length} roots (${examined} files examined)`);