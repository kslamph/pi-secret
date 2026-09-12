import { envVarName } from "../src/substitute.ts";

export interface BashCase {
  it: string;
  input: string;
  /** Literal command text expected after expansion. */
  command: string;
  /** env var name → expected runtime word (resolved and single-quoted). */
  env: Record<string, string>;
  missing?: string[];
}

export const GH = "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8";
export const DB = "postgres://admin:s3cr3t@db.internal:5432/app";
export const SPACED = "a b 'c' $(echo pwned)";

// Derive, never hardcode: the 4-hex suffix is a digest of the name (Task 3).
export const GH_ENV = envVarName("gh_pat");
export const DB_ENV = envVarName("db_url");
export const SPACED_ENV = envVarName("spaced");

export const bashCases: BashCase[] = [
  {
    it: "unquoted ref becomes a quoted env reference",
    input: "curl -H Authorization:Bearer {{sec:gh_pat}} https://api.github.com",
    command: `curl -H Authorization:Bearer "$${GH_ENV}" https://api.github.com`,
    env: { [GH_ENV]: GH },
  },
  {
    it: "double-quoted ref expands without word splitting",
    input: 'curl -H "Authorization: Bearer {{sec:gh_pat}}"',
    command: `curl -H "Authorization: Bearer $${GH_ENV}"`,
    env: { [GH_ENV]: GH },
  },
  {
    it: "single-quoted ref closes and reopens the quote",
    input: "curl -H 'Authorization: Bearer {{sec:gh_pat}}'",
    command: `curl -H 'Authorization: Bearer '"$${GH_ENV}"''`,
    env: { [GH_ENV]: GH },
  },
  {
    it: "two refs in one command",
    input: 'psql "{{sec:db_url}}" -t "{{sec:gh_pat}}"',
    command: `psql "$${DB_ENV}" -t "$${GH_ENV}"`,
    env: { [DB_ENV]: DB, [GH_ENV]: GH },
  },
  {
    // Braces are load-bearing here: without them the shell reads `$VARsuffix`
    // as a different, empty variable.
    it: "uses braces when a ref is followed by word characters",
    input: 'echo "--token={{sec:gh_pat}}done"',
    command: `echo "--token=\${${GH_ENV}}done"`,
    env: { [GH_ENV]: GH },
  },
  {
    it: "leaves unknown refs in place and reports them",
    input: "echo {{sec:nope}} {{sec:gh_pat}}",
    command: `echo {{sec:nope}} "$${GH_ENV}"`,
    env: { [GH_ENV]: GH },
    missing: ["nope"],
  },
  {
    it: "leaves an uppercase-name ref alone (never matches)",
    input: "echo {{sec:GH_PAT}}",
    command: "echo {{sec:GH_PAT}}",
    env: {},
  },
  {
    it: "command with no refs passes through untouched",
    input: "git commit -m 'ship it'",
    command: "git commit -m 'ship it'",
    env: {},
  },
  {
    it: "spaced and hostile value is only ever used as a quoted var",
    input: 'run --token "{{sec:spaced}}"',
    command: `run --token "$${SPACED_ENV}"`,
    env: { [SPACED_ENV]: SPACED },
  },
  {
    it: "heredoc body with an unquoted delimiter expands",
    input: "cat <<EOF\ntoken={{sec:gh_pat}}\nEOF",
    command: `cat <<EOF\ntoken=\${${GH_ENV}}\nEOF`,
    env: { [GH_ENV]: GH },
  },
  {
    it: "heredoc body with a quoted delimiter is left alone and reported",
    input: "cat <<'EOF'\ntoken={{sec:gh_pat}}\nEOF",
    command: "cat <<'EOF'\ntoken={{sec:gh_pat}}\nEOF",
    env: {},
    missing: ["gh_pat"],
  },
  {
    it: "multi-line command",
    input: 'set -e\ncurl -H "Authorization: Bearer {{sec:gh_pat}}"\n',
    command: `set -e\ncurl -H "Authorization: Bearer $${GH_ENV}"\n`,
    env: { [GH_ENV]: GH },
  },
];
