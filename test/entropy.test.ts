import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { isDigestShaped, isLikelySecret, looksCredentialish, shannonEntropy } from "../src/entropy.ts";
import { parseDotenv } from "../src/env-file.ts";

const FIXTURE = fileURLToPath(new URL("./fixtures/realistic-bashrc.env", import.meta.url));

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

/**
 * Golden vector: a realistic shell profile, and the reason it exists.
 *
 * Importing a real `~/.bashrc` marked six of eight rows "likely secret" — `PS1`,
 * `LD_LIBRARY_PATH`, `__conda_setup`, `NODE_EXTRA_CA_CERTS`, `BETTERWRIGHT_CHROMIUM_ARGS`,
 * `debian_chroot`. Every one of them is shell *structure*: braces, backslashes, `$`, spaces, path
 * lists, argument lists. Entropy alone cannot tell those apart from a token, so the predicate now
 * also refuses anything shaped like shell syntax, a filesystem path or a list.
 *
 * `test/fixtures/realistic-bashrc.env` holds the shapes with fabricated values. The test reads the
 * file rather than embedding a copy, so the vector and the contract cannot drift — and the third
 * case fails if a line is added without declaring what it should do.
 */
describe("the file-import classifier (golden vector)", () => {
  const parsed = parseDotenv(readFileSync(FIXTURE, "utf8"));

  const NOT_A_SECRET = [
    "histcontrol", "histsize", "histfilesize", "debian_chroot", "ps1", "cuda_home", "path",
    "ld_library_path", "goproxy", "nvm_dir", "node_extra_ca_certs", "__conda_setup", "qlty_install",
    "kubeconfig", "llama_cpp_base_url", "android_home", "gradle_home", "pnpm_home", "bun_install",
    "betterwright_chromium_path", "betterwright_chromium_args", "_oldifs", "ifs",
    "cloudflare_account_id", "editor", "visual",
  ];
  const A_SECRET = [
    "cline_api_key", "cloudflare_api_token", "opencode_api_key", "zai_coding_cn_api_key",
    "sentry_secret", "gh_pat", "legacy_key", "database_url",
  ];

  const verdicts = () =>
    Object.fromEntries(parsed.assignments.map((a) => [a.key.toLowerCase(), isLikelySecret(a.key, a.value)]));

  it("parses the vector as a dotenv file (and collapses the duplicate PS1)", () => {
    expect(parsed.duplicates).toBe(1);
    // `if …; then`, `fi`, and the `case … esac` line are not assignments.
    expect(parsed.skipped).toBe(3);
  });

  it("never calls shell structure a secret", () => {
    const got = verdicts();
    for (const name of NOT_A_SECRET) {
      expect(got[name], `${name} must NOT look like a secret`).toBe(false);
    }
  });

  it("still finds every real secret, one signal each", () => {
    const got = verdicts();
    for (const name of A_SECRET) {
      expect(got[name], `${name} must look like a secret`).toBe(true);
    }
  });

  it("covers the whole vector — a new line needs a declared verdict", () => {
    expect(parsed.assignments.map((a) => a.key.toLowerCase()).sort()).toEqual(
      [...NOT_A_SECRET, ...A_SECRET].sort(),
    );
  });

  it("pins the false-positive count, which is what regressed", () => {
    const likely = parsed.assignments.filter((a) => isLikelySecret(a.key, a.value));
    expect(likely.length).toBe(A_SECRET.length);
    expect(likely.map((a) => a.key.toLowerCase()).sort()).toEqual([...A_SECRET].sort());
  });

  it("takes the name signal when the value is too small to judge", () => {
    // A six-character value is below every shape threshold; `*secret*` is why it still shows.
    expect(looksCredentialish("abc123")).toBe(false);
    expect(isLikelySecret("SENTRY_SECRET", "abc123")).toBe(true);
  });

  it("takes the value signal when the name says nothing", () => {
    expect(isLikelySecret("LEGACY_KEY", "mF7kQ2pL9vN4wR8tY3uJ6hB1nC5dF0gA2sD4fG7hK1mN3")).toBe(true);
    expect(isLikelySecret("GH_PAT", "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE")).toBe(true);
  });

  it("flags a URL only when it carries credentials", () => {
    expect(isLikelySecret("DATABASE_URL", "postgres://admin:s3cr3tpass@db.internal:5432/app")).toBe(true);
    expect(isLikelySecret("LLAMA_CPP_BASE_URL", "http://127.0.0.1:8080")).toBe(false);
    expect(isLikelySecret("DOCS", "https://example.com/some/long/opaque/path/segment")).toBe(false);
  });

  it("keeps the shapes it was always supposed to reject", () => {
    for (const shape of [
      "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8".replace("Q7R8", "Q7R8"), // provider format: a secret
    ]) {
      expect(looksCredentialish(shape)).toBe(true);
    }
    for (const shape of [
      "4f9c1a7e2b8d0a3c5e7f1b3d9a2c4e6f8b0d2a4c", // git SHA
      "the quick brown fox jumps over the lazy dog", // prose
      "/usr/local/cuda/lib64:/usr/lib/x86_64-linux-gnu", // path list
      "--no-sandbox,--disable-dev-shm-usage", // argument list
      "~/.local/share/mkcert/rootCA.pem", // tilde path
      "https://proxy.golang.org,direct", // URL
      '${debian_chroot:+($debian_chroot)}\\u@\\h:\\w\\$ ', // prompt
    ]) {
      expect(looksCredentialish(shape), shape).toBe(false);
    }
  });
});
