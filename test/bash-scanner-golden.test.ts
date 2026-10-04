import { describe, expect, it } from "vitest";
import { expandBash } from "../src/substitute.ts";

/**
 * PHASE-1 BASELINE GOLDEN CORPUS for the single-pass bash lexical scanner
 * (Task 15). These expectations were GENERATED from the pre-refactor
 * implementation (src/substitute/bash.ts as of commit 11fc419) by running
 * expandBash over a fixed corpus and serializing its REAL output — they were
 * not hand-written. They pin CURRENT behavior, including behaviors that are
 * WRONG and that Task 15 phase 2 must change.
 *
 * The proof of the refactor (phase 1) is that these goldens still pass AFTER
 * the single-pass extraction, unchanged in count and content. A green full
 * suite alone is not the proof; the proof is that goldens generated BEFORE the
 * refactor still pass AFTER it.
 *
 * Pinned fields per golden: command, env (keys + values), used, missing, and
 * block (derived: missing.length > 0 — the caller's "refuse to run" signal
 * when a ref cannot be safely substituted).
 *
 * Goldens carrying a `note` encode a known defect. Phase 2's diff is expected
 * to FLIP those (and only those) deliberately; a silent change anywhere else
 * is a regression. See the brief's requirements 2, 3, 4 and the continuation
 * rule for the intended phase-2 values.
 */

const resolve = (name: string): string | undefined => {
  switch (name) {
    case "x":
      return "SECRETVALUE";
    case "gh_pat":
      return "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8";
    case "db_url":
      return "postgres://admin:s3cr3t@db.internal:5432/app";
    case "spaced":
      return "a b 'c' $(echo pwned)";
    case "t":
      return "TOKEN_T";
    default:
      return undefined;
  }
};

interface Golden {
  name: string;
  input: string;
  command: string;
  env: Record<string, string>;
  used: string[];
  missing: string[];
  block: boolean;
  note?: string;
}

// Generated from src/substitute/bash.ts @ 11fc419 (pre-refactor).
const GOLDENS: Golden[] = [
  {
    "name": "unquoted ref",
    "input": "curl -H Authorization:Bearer {{sec:gh_pat}} https://api.github.com",
    "command": "curl -H Authorization:Bearer \"$__PISEC_GH_PAT_a71b5583e6c0f446\" https://api.github.com",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false
  },
  {
    "name": "dq ref expands",
    "input": "curl -H \"Authorization: Bearer {{sec:gh_pat}}\"",
    "command": "curl -H \"Authorization: Bearer $__PISEC_GH_PAT_a71b5583e6c0f446\"",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false
  },
  {
    "name": "sq ref splices",
    "input": "curl -H 'Authorization: Bearer {{sec:gh_pat}}'",
    "command": "curl -H 'Authorization: Bearer '\"$__PISEC_GH_PAT_a71b5583e6c0f446\"''",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false
  },
  {
    "name": "two refs",
    "input": "psql \"{{sec:db_url}}\" -t \"{{sec:gh_pat}}\"",
    "command": "psql \"$__PISEC_DB_URL_6698cda00c747094\" -t \"$__PISEC_GH_PAT_a71b5583e6c0f446\"",
    "env": {
      "__PISEC_DB_URL_6698cda00c747094": "postgres://admin:s3cr3t@db.internal:5432/app",
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "db_url",
      "gh_pat"
    ],
    "missing": [],
    "block": false
  },
  {
    "name": "braces after ref",
    "input": "echo \"--token={{sec:gh_pat}}done\"",
    "command": "echo \"--token=${__PISEC_GH_PAT_a71b5583e6c0f446}done\"",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false
  },
  {
    "name": "unknown ref missing",
    "input": "echo {{sec:nope}} {{sec:gh_pat}}",
    "command": "echo {{sec:nope}} \"$__PISEC_GH_PAT_a71b5583e6c0f446\"",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [
      "nope"
    ],
    "block": true
  },
  {
    "name": "uppercase no match",
    "input": "echo {{sec:GH_PAT}}",
    "command": "echo {{sec:GH_PAT}}",
    "env": {},
    "used": [],
    "missing": [],
    "block": false
  },
  {
    "name": "no refs",
    "input": "git commit -m 'ship it'",
    "command": "git commit -m 'ship it'",
    "env": {},
    "used": [],
    "missing": [],
    "block": false
  },
  {
    "name": "spaced value",
    "input": "run --token \"{{sec:spaced}}\"",
    "command": "run --token \"$__PISEC_SPACED_4cf28831d09470e8\"",
    "env": {
      "__PISEC_SPACED_4cf28831d09470e8": "a b 'c' $(echo pwned)"
    },
    "used": [
      "spaced"
    ],
    "missing": [],
    "block": false
  },
  {
    "name": "heredoc expand",
    "input": "cat <<EOF\ntoken={{sec:gh_pat}}\nEOF",
    "command": "cat <<EOF\ntoken=${__PISEC_GH_PAT_a71b5583e6c0f446}\nEOF",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false
  },
  {
    "name": "heredoc inert",
    "input": "cat <<'EOF'\ntoken={{sec:gh_pat}}\nEOF",
    "command": "cat <<'EOF'\ntoken={{sec:gh_pat}}\nEOF",
    "env": {},
    "used": [],
    "missing": [
      "gh_pat"
    ],
    "block": true
  },
  {
    "name": "two heredocs one line",
    "input": "cat <<A <<'B'\nX {{sec:gh_pat}}\nA\nY {{sec:gh_pat}}\nB\n",
    "command": "cat <<A <<'B'\nX ${__PISEC_GH_PAT_a71b5583e6c0f446}\nA\nY {{sec:gh_pat}}\nB\n",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [
      "gh_pat"
    ],
    "block": true
  },
  {
    "name": "<< in dq not operator",
    "input": "echo \"<<EOF\" {{sec:gh_pat}}",
    "command": "echo \"<<EOF\" \"$__PISEC_GH_PAT_a71b5583e6c0f446\"",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false
  },
  {
    "name": "here-string tail",
    "input": "cat <<<word\n{{sec:gh_pat}}\n",
    "command": "cat <<<word\n\"$__PISEC_GH_PAT_a71b5583e6c0f446\"\n",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false
  },
  {
    "name": "<<- tabs stripped",
    "input": "cat <<-EOF\ntoken={{sec:gh_pat}}\n\tEOF\n",
    "command": "cat <<-EOF\ntoken=${__PISEC_GH_PAT_a71b5583e6c0f446}\n\tEOF\n",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false
  },
  {
    "name": "unterminated heredoc",
    "input": "cat <<EOF\ntoken={{sec:gh_pat}}\n",
    "command": "cat <<EOF\ntoken=${__PISEC_GH_PAT_a71b5583e6c0f446}\n",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false
  },
  {
    "name": "comment prose quotes",
    "input": "# don't\necho {{sec:gh_pat}} > /tmp/o  # it's",
    "command": "# don't\necho \"$__PISEC_GH_PAT_a71b5583e6c0f446\" > /tmp/o  # it's",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false
  },
  {
    "name": "comment double-quote",
    "input": "# note \"a\necho {{sec:gh_pat}}\n# \" done",
    "command": "# note \"a\necho \"$__PISEC_GH_PAT_a71b5583e6c0f446\"\n# \" done",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false
  },
  {
    "name": "$' span",
    "input": "echo $'{{sec:gh_pat}}'",
    "command": "echo $''\"$__PISEC_GH_PAT_a71b5583e6c0f446\"''",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false
  },
  {
    "name": "unterminated quote",
    "input": "echo 'x\nrun {{sec:gh_pat}}",
    "command": "echo 'x\nrun {{sec:gh_pat}}",
    "env": {},
    "used": [],
    "missing": [
      "gh_pat"
    ],
    "block": true
  },
  {
    "name": "a#b word",
    "input": "echo a#b{{sec:gh_pat}}",
    "command": "echo a#b\"$__PISEC_GH_PAT_a71b5583e6c0f446\"",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false
  },
  {
    "name": "x=#hello value (= non-boundary)",
    "input": "echo x=#hello{{sec:gh_pat}}",
    "command": "echo x=#hello\"$__PISEC_GH_PAT_a71b5583e6c0f446\"",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false
  },
  {
    "name": "$\" locale span",
    "input": "echo $\"{{sec:gh_pat}}\"",
    "command": "echo $\"$__PISEC_GH_PAT_a71b5583e6c0f446\"",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false
  },
  {
    "name": "nested sq inside dq",
    "input": "echo \"a '{{sec:gh_pat}}' b\"",
    "command": "echo \"a '$__PISEC_GH_PAT_a71b5583e6c0f446' b\"",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false
  },
  {
    "name": "nested dq inside sq",
    "input": "echo 'a \"{{sec:gh_pat}}\" b'",
    "command": "echo 'a \"'\"$__PISEC_GH_PAT_a71b5583e6c0f446\"'\" b'",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false
  },
  {
    "name": ";|& comment",
    "input": "echo hi;#don't\necho {{sec:gh_pat}} is here;#it's",
    "command": "echo hi;#don't\necho \"$__PISEC_GH_PAT_a71b5583e6c0f446\" is here;#it's",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false
  },
  {
    "name": "() word starts",
    "input": "(cd .)#don't\necho {{sec:gh_pat}}\n(ls)#it's",
    "command": "(cd .)#don't\necho \"$__PISEC_GH_PAT_a71b5583e6c0f446\"\n(ls)#it's",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false
  },
  {
    "name": "escaped semicolon",
    "input": "echo a\\;#b'c {{sec:gh_pat}} d'",
    "command": "echo a\\;#b'c '\"$__PISEC_GH_PAT_a71b5583e6c0f446\"' d'",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false
  },
  {
    "name": "heredoc odd apostrophe",
    "input": "cat <<EOF\ndon't\nEOF\necho {{sec:gh_pat}}",
    "command": "cat <<EOF\ndon't\nEOF\necho \"$__PISEC_GH_PAT_a71b5583e6c0f446\"",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false
  },
  {
    "name": "heredoc even apostrophe",
    "input": "cat <<EOF\ndon't\nEOF\necho {{sec:gh_pat}} && echo 'x'",
    "command": "cat <<EOF\ndon't\nEOF\necho \"$__PISEC_GH_PAT_a71b5583e6c0f446\" && echo 'x'",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false
  },
  {
    "name": "heredoc body opens with quote",
    "input": "cat <<EOF\n'don't\nEOF\necho {{sec:gh_pat}}",
    "command": "cat <<EOF\n'don't\nEOF\necho \"$__PISEC_GH_PAT_a71b5583e6c0f446\"",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false
  },
  {
    "name": "escape clears wordStart",
    "input": "echo $(printf a)\\;#b'c {{sec:gh_pat}} d'",
    "command": "echo $(printf a)\\;#b'c '\"$__PISEC_GH_PAT_a71b5583e6c0f446\"' d'",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false
  },
  {
    "name": "two heredocs odd prose",
    "input": "cat <<'MSG'\nDon't do this\nMSG\ncat <<EOF\nIt's fine\nEOF\necho {{sec:gh_pat}}",
    "command": "cat <<'MSG'\nDon't do this\nMSG\ncat <<EOF\nIt's fine\nEOF\necho \"$__PISEC_GH_PAT_a71b5583e6c0f446\"",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false
  },
  {
    "name": "two heredocs even prose",
    "input": "cat <<'MSG'\nDon't do this\nMSG\ncat <<EOF\nIt's fine\nEOF\necho {{sec:gh_pat}} && echo 'x'",
    "command": "cat <<'MSG'\nDon't do this\nMSG\ncat <<EOF\nIt's fine\nEOF\necho \"$__PISEC_GH_PAT_a71b5583e6c0f446\" && echo 'x'",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false
  },
  {
    "name": "operator swallowed by quote",
    "input": "echo '<<EOF'\ndon't\nEOF\necho {{sec:gh_pat}}",
    "command": "echo '<<EOF'\ndon't\nEOF\necho {{sec:gh_pat}}",
    "env": {},
    "used": [],
    "missing": [
      "gh_pat"
    ],
    "block": true
  },
  {
    "name": "inert then expanding body",
    "input": "cat <<'EOF'\nx {{sec:gh_pat}}\nEOF\ncat <<EOF\ny {{sec:gh_pat}}\nEOF",
    "command": "cat <<'EOF'\nx {{sec:gh_pat}}\nEOF\ncat <<EOF\ny ${__PISEC_GH_PAT_a71b5583e6c0f446}\nEOF",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [
      "gh_pat"
    ],
    "block": true
  },
  {
    "name": "<<- spaces not stripped",
    "input": "cat <<-EOF\n    indented text\nEOF\n",
    "command": "cat <<-EOF\n    indented text\nEOF\n",
    "env": {},
    "used": [],
    "missing": [],
    "block": false
  },
  {
    "name": "body line merely starts with delimiter",
    "input": "cat <<EOF\nEOFX={{sec:gh_pat}}\nEOF",
    "command": "cat <<EOF\nEOFX=${__PISEC_GH_PAT_a71b5583e6c0f446}\nEOF",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false
  },
  {
    "name": "<<EOF>> operator",
    "input": "cat <<EOF>>/tmp/o\ntoken={{sec:gh_pat}}\nEOF",
    "command": "cat <<EOF>>/tmp/o\ntoken=${__PISEC_GH_PAT_a71b5583e6c0f446}\nEOF",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false
  },
  {
    "name": "<<EOF 2>&1",
    "input": "cat <<EOF 2>&1\ntoken={{sec:gh_pat}}\nEOF",
    "command": "cat <<EOF 2>&1\ntoken=${__PISEC_GH_PAT_a71b5583e6c0f446}\nEOF",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false
  },
  {
    "name": "new: <<1 non-word delimiter (req2)",
    "input": "cat <<1\ntoken={{sec:gh_pat}}\n1\necho {{sec:gh_pat}} && echo 'x'",
    "command": "cat <<1\ntoken=${__PISEC_GH_PAT_a71b5583e6c0f446}\n1\necho \"$__PISEC_GH_PAT_a71b5583e6c0f446\" && echo 'x'",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false,
    "note": "RESOLVED (req2). Phase 1 rejected the numeric delimiter `1` (charset was `[A-Za-z_][A-Za-z0-9_]*`), so the body was scanned as CODE and the ref was rewritten in code form `\"$VAR\"`. Phase 2 widens the delimiter class to `[^\\s|&<>();]+`, recognizes `1`, and the body is now scanned as a heredoc body — hence `${VAR}` instead of `\"$VAR\"`. block stays false in both phases, and the phase-1 note's claim that phase 2 should flip it to true was WRONG: measured against bash, an UNQUOTED heredoc delimiter leaves the body subject to parameter expansion (`cat <<1` with `token=$MYVAR` in the body prints the value), so the body is NOT inert and correctly delivers the secret. Only the rewrite shape changed. A quoted delimiter (`<<'EOF'`) is the inert case, and that is pinned separately."
  },
  {
    "name": "new: <<E-O-F delimiter (req2)",
    "input": "cat <<E-O-F\ntoken={{sec:gh_pat}}\nE-O-F",
    "command": "cat <<E-O-F\ntoken=${__PISEC_GH_PAT_a71b5583e6c0f446}\nE-O-F",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false,
    "note": "RESOLVED (req2). `E-O-F` contains `-`, which the phase-1 charset rejected. Phase 2 accepts it and the body is scanned as a heredoc body. This expectation already recorded the `${VAR}` body form and did not change across phase 2 — the phase-1 note's claim about phase-1 output was stale. block stays false: an unquoted delimiter does not make the body inert (measured)."
  },
  {
    "name": "new: <<EOF.txt delimiter (req2)",
    "input": "cat <<EOF.txt\ntoken={{sec:gh_pat}}\nEOF.txt",
    "command": "cat <<EOF.txt\ntoken=${__PISEC_GH_PAT_a71b5583e6c0f446}\nEOF.txt",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false,
    "note": "RESOLVED (req2). `EOF.txt` contains `.`, which the phase-1 charset rejected. Phase 2 accepts it and the body is scanned as a heredoc body. Expectation unchanged across phase 2 — the phase-1 note's claim about phase-1 output was stale. block stays false: an unquoted delimiter does not make the body inert (measured)."
  },
  {
    "name": "new: # cat <<EOF comment operator (req4)",
    "input": "# cat <<EOF\ntoken={{sec:gh_pat}}\nEOF\necho {{sec:gh_pat}}",
    "command": "# cat <<EOF\ntoken=\"$__PISEC_GH_PAT_a71b5583e6c0f446\"\nEOF\necho \"$__PISEC_GH_PAT_a71b5583e6c0f446\"",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false,
    "note": "RESOLVED (req4). Phase 1 was comment-unaware for heredocs, so the `<<EOF` on the commented line still registered an operator. Phase 2 makes operators inside comments inert, so this registers nothing: the `token={{sec:gh_pat}}` line is no longer a heredoc body and the ref expands as plain code (`\"$VAR\"`, not `${VAR}`). The trailing `echo` still expands. Deliberate flip, exactly as the phase-1 note predicted."
  },
  {
    "name": "new: arithmetic $((1<<2)) (req3)",
    "input": "echo $((1<<2)) {{sec:t}}",
    "command": "echo $((1<<2)) \"$__PISEC_T_e3b98a4da31a127d\"",
    "env": {
      "__PISEC_T_e3b98a4da31a127d": "TOKEN_T"
    },
    "used": [
      "t"
    ],
    "missing": [],
    "block": false
  },
  {
    "name": "new: line-continuation (brief shape, odd apostrophe, coincidental block)",
    "input": "echo x \\\n#don't {{sec:gh_pat}}",
    "command": "echo x \\\n#don't {{sec:gh_pat}}",
    "env": {},
    "used": [],
    "missing": [
      "gh_pat"
    ],
    "block": true
  },
  {
    "name": "new: line-continuation (balanced apostrophe, real defect)",
    "input": "echo x \\\n#don''t {{sec:gh_pat}}",
    "command": "echo x \\\n#don''t {{sec:gh_pat}}",
    "env": {},
    "used": [],
    "missing": [
      "gh_pat"
    ],
    "block": true,
    "note": "RESOLVED (also-owed / req4). A backslash-newline is not an escape pair: bash deletes both characters and continues in the SAME parser state, so the `\\` must leave `wordStart` alone and `#don''t` opens a comment. The ref is comment text bash discards, so it is left literal and reported missing. Phase 1 expanded it (block=false) because the `\\` cleared `wordStart` (Task 4 req7 blanket clear) and the balanced apostrophes avoided fail-closed. Predicted flip false->true; observed flip false->true."
  },
  {
    "name": "new: public-key heredoc unquoted",
    "input": "cat <<EOF\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIxxxxxxxxxxxxxxxxxxxxxxxx user@host\n{{sec:gh_pat}}\nEOF",
    "command": "cat <<EOF\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIxxxxxxxxxxxxxxxxxxxxxxxx user@host\n${__PISEC_GH_PAT_a71b5583e6c0f446}\nEOF",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false
  },
  {
    "name": "new: public-key heredoc quoted inert",
    "input": "cat <<'KEY'\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIxxxxxxxxxxxxxxxxxxxxxxxx user@host\n{{sec:gh_pat}}\nKEY\necho {{sec:gh_pat}}",
    "command": "cat <<'KEY'\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIxxxxxxxxxxxxxxxxxxxxxxxx user@host\n{{sec:gh_pat}}\nKEY\necho \"$__PISEC_GH_PAT_a71b5583e6c0f446\"",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [
      "gh_pat"
    ],
    "block": true
  },
  {
    "name": "new: x>#f redirection boundary",
    "input": "echo x>#{{sec:gh_pat}}",
    "command": "echo x>#{{sec:gh_pat}}",
    "env": {},
    "used": [],
    "missing": [
      "gh_pat"
    ],
    "block": true,
    "note": "RESOLVED (also-owed / req4). `>` then `#` is a comment (measured: bash exits 2 and creates no file), so the ref is comment text bash discards: left literal and blocked. Phase 1 expanded it (block=false). Predicted flip false->true; observed flip false->true."
  },
  {
    "name": "new: x<#f redirection boundary",
    "input": "echo x<#{{sec:gh_pat}}",
    "command": "echo x<#{{sec:gh_pat}}",
    "env": {},
    "used": [],
    "missing": [
      "gh_pat"
    ],
    "block": true,
    "note": "RESOLVED (also-owed / req4). `<` then `#` is a comment, so the ref is comment text: left literal and blocked. Phase 1 expanded it (block=false). Predicted flip false->true; observed flip false->true."
  },
  {
    "name": "new: x<<<#f redirection boundary",
    "input": "echo x<<<#{{sec:gh_pat}}",
    "command": "echo x<<<#{{sec:gh_pat}}",
    "env": {},
    "used": [],
    "missing": [
      "gh_pat"
    ],
    "block": true,
    "note": "RESOLVED (also-owed / req4). `<<<` then `#` is a comment, so the ref is comment text: left literal and blocked. Phase 1 expanded it (block=false). Predicted flip false->true; observed flip false->true."
  },
  {
    "name": "new: public-key non-word delimiter (req2 mis-lex)",
    "input": "cat <<id_rsa.pub\nssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIxxxxxxxx user@host\n{{sec:gh_pat}}\nid_rsa.pub",
    "command": "cat <<id_rsa.pub\nssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIxxxxxxxx user@host\n${__PISEC_GH_PAT_a71b5583e6c0f446}\nid_rsa.pub",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false,
    "note": "RESOLVED (req2). The delimiter `id_rsa.pub` contains `.`, so phase 1's `[A-Za-z_][A-Za-z0-9_]*` class rejected it and the public-key body was scanned as code. Phase 2 accepts it, so the body is scanned as a heredoc body and the ref is rewritten as `${VAR}`. block stays false: measured against bash, an unquoted delimiter leaves the body subject to parameter expansion, so this body is NOT inert. The phase-1 note's prediction that phase 2 would block was wrong on that point — same correction as the `<<1` golden."
  }
];

describe("bash scanner golden corpus (phase-1 baseline — must stay identical after the single-pass refactor)", () => {
  it(`pins at least 40 inputs (got ${GOLDENS.length})`, () => {
    expect(GOLDENS.length).toBeGreaterThanOrEqual(40);
  });

  for (const g of GOLDENS) {
    it(g.name, () => {
      const out = expandBash(g.input, resolve);
      expect(out.command).toBe(g.command);
      expect(out.env).toEqual(g.env);
      expect(out.used).toEqual(g.used);
      expect(out.missing).toEqual(g.missing);
      // block is a derived signal; assert it tracks missing exactly.
      expect(out.missing.length > 0).toBe(g.block);
    });
  }
});

describe("goldens whose notes document a defect and how phase 2 resolved it", () => {
  const noted = GOLDENS.filter((g) => g.note);
  it(`documents ${noted.length} defect notes`, () => {
    expect(noted.length).toBeGreaterThan(0);
  });

  // The binding per-golden assertion is the pin in the suite above. This block
  // exists so each note is visible in test output and so the documented outcome is
  // itself checked: any note that promised a block flip must now block.
  //
  // Phase 1 asserted `block === false` for every noted golden ("today these wrongly
  // do NOT block"). That was true then and is the opposite of true now, so it was
  // replaced rather than kept — an assertion that is always-false-in-the-future is
  // worse than no assertion.
  it("every golden whose note predicted a block flip now blocks", () => {
    const predicted = noted.filter((g) => /flip(s)? false->true/.test(g.note ?? ""));
    expect(predicted.length).toBeGreaterThan(0);
    for (const g of predicted) {
      expect(g.block, `${g.name} promised a block flip`).toBe(true);
      expect(g.missing, `${g.name} promised to report the ref missing`).not.toHaveLength(0);
    }
  });

  // The other noted goldens were unquoted delimiters, whose bodies bash still
  // expands — measured. They must NOT block, or the scanner would be refusing to
  // deliver a secret that bash would have delivered correctly.
  it("unquoted non-word delimiters do not block (their bodies expand in bash)", () => {
    for (const name of ["<<1 non-word delimiter (req2)", "<<E-O-F delimiter (req2)", "<<EOF.txt delimiter (req2)", "public-key non-word delimiter (req2 mis-lex)"]) {
      const g = GOLDENS.find((x) => x.name.includes(name));
      expect(g, name).toBeDefined();
      expect(g!.block, name).toBe(false);
    }
  });
});
