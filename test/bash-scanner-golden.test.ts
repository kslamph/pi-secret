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
    "command": "cat <<1\ntoken=\"$__PISEC_GH_PAT_a71b5583e6c0f446\"\n1\necho \"$__PISEC_GH_PAT_a71b5583e6c0f446\" && echo 'x'",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false,
    "note": "DEFECT (req2): the numeric delimiter `1` is rejected by the `[A-Za-z_][A-Za-z0-9_]*` charset, so the body is scanned as code and the ref is expanded (block=false). In bash `cat <<1` is a valid heredoc, so the body is inert. Phase 2 widens the delimiter class to `[^\\s|&<>();]+` (req2), recognizes `1`, excludes the body, leaves the ref literal and reports it missing (block flips false->true)."
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
    "note": "DEFECT (req2): delimiter `E-O-F` (contains `-`) is rejected by the word-char charset, so the body ref is expanded (block=false). bash accepts `E-O-F` as a heredoc delimiter, so the body is inert. Phase 2 recognizes it and blocks (block flips false->true)."
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
    "note": "DEFECT (req2): delimiter `EOF.txt` (contains `.`) is rejected by the word-char charset, so the body ref is expanded (block=false). bash accepts `EOF.txt` as a heredoc delimiter, so the body is inert. Phase 2 recognizes it and blocks (block flips false->true)."
  },
  {
    "name": "new: # cat <<EOF comment operator (req4)",
    "input": "# cat <<EOF\ntoken={{sec:gh_pat}}\nEOF\necho {{sec:gh_pat}}",
    "command": "# cat <<EOF\ntoken=${__PISEC_GH_PAT_a71b5583e6c0f446}\nEOF\necho \"$__PISEC_GH_PAT_a71b5583e6c0f446\"",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false,
    "note": "DEFECT (req4): the current scanner is comment-UNAWARE for heredocs, so the `<<EOF` on the commented operator line is still matched as a heredoc operator (pre-refactor behavior, pinned faithfully). Phase 2 (req4) makes operators inside comments inert, so this `<<EOF` will register nothing: the `token={{sec:gh_pat}}` line will no longer be a heredoc body and the ref will expand as plain code (command changes from `token=${VAR}` to `token=\"$VAR\"`). Marked so phase 2 shows this deliberate flip."
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
    "command": "echo x \\\n#don''t \"$__PISEC_GH_PAT_a71b5583e6c0f446\"",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false,
    "note": "DEFECT (also-owed / req4): `\\<newline>` joins the next line in the SAME parser state, so `#don''t` is a comment and the ref is text bash discards. Current impl expands it (block=false) because the `\\` clears wordStart (Task 4 req7 blanket clear) and the balanced apostrophes avoid fail-closed. Phase 2 leaves the ref literal + blocks (block flips false->true). The brief's literal `echo x \\<newline>#don't` shape coincidentally blocks today — the lone apostrophe trips fail-closed for the WRONG reason — see the 'odd apostrophe' golden."
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
    "command": "echo x>#\"$__PISEC_GH_PAT_a71b5583e6c0f446\"",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false,
    "note": "DEFECT (also-owed / req4): `>` then `#` is a comment (bash exits 2, creates no file), so the ref is comment text. Current impl expands it (block=false). Phase 2 treats the ref as comment text: leaves it literal + blocks (block flips false->true)."
  },
  {
    "name": "new: x<#f redirection boundary",
    "input": "echo x<#{{sec:gh_pat}}",
    "command": "echo x<#\"$__PISEC_GH_PAT_a71b5583e6c0f446\"",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false,
    "note": "DEFECT (also-owed / req4): `<` then `#` is a comment, so the ref is comment text. Current impl expands it (block=false). Phase 2 leaves literal + blocks (block flips false->true)."
  },
  {
    "name": "new: x<<<#f redirection boundary",
    "input": "echo x<<<#{{sec:gh_pat}}",
    "command": "echo x<<<#\"$__PISEC_GH_PAT_a71b5583e6c0f446\"",
    "env": {
      "__PISEC_GH_PAT_a71b5583e6c0f446": "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8"
    },
    "used": [
      "gh_pat"
    ],
    "missing": [],
    "block": false,
    "note": "DEFECT (also-owed / req4): `<<<` then `#` is a comment, so the ref is comment text. Current impl expands it (block=false). Phase 2 leaves literal + blocks (block flips false->true)."
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
    "note": "DEFECT (req2) — the 'public-key body line currently mis-lexes' case from the brief. The delimiter `id_rsa.pub` is rejected (contains `.`), so the public-key body — including the ref — is scanned as code and the ref is expanded (block=false). Phase 2 recognizes the non-word delimiter, excludes the body, and blocks (block flips false->true)."
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

describe("goldens encoding known defects (phase-2 deliberate-flip targets)", () => {
  const defects = GOLDENS.filter((g) => g.note);
  it(`documents ${defects.length} known defects`, () => {
    expect(defects.length).toBeGreaterThan(0);
  });
  for (const g of defects) {
    it(`${g.name} — ${g.note}`, () => {
      // Pure documentation of intent; the binding assertion is the baseline
      // pin in the suite above. Phase 2 is expected to flip command/block here.
      expect(g.block).toBe(false); // today these wrongly do NOT block
    });
  }
});
