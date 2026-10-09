# Vendored third-party reference material — NOT shipped, NOT our code

`detect.ts`, `index.ts`, `test.ts` here are Claude's secret detector, fetched verbatim
from a Claude session on 2026-10-09 as reference input for the pi-secret capture fix.
They are kept for provenance so the rules we lift can be reviewed side by side with the
source we took them from.

Three things a reader must know:

- **Nothing here is published.** `package.json`'s `files` is `src`, `README.md`,
  `LICENSE`, so `from_claude/` never reaches npm consumers. It is a study aid.
- **No license was granted for it.** No license header or SPDX tag ships in these
  files, so it must not be copied into `src/` as-is. What we may adopt are the
  *ideas and predicates* (word-run ratio, lower+upper+digit requirement, reference
  veto, CJK keywords), reimplemented in our own code with our own tests — see
  `docs/superpowers/specs/` for the design this fed.
- **`tsconfig.json` does not include it**, and it does not typecheck under this repo's
  settings (`from_claude/detect.ts` uses `m.indices` in a way `noUncheckedIndexedAccess`
  rejects). Keep it that way: if it ever appears in `npx tsc --noEmit` output, an
  import leaked in somewhere.

Measured against pi-secret's detector on 2026-10-09, for the record: recall 22/22 vs
15/22, false positives 0/24 vs 10/24. Its high-entropy tier also has two recall holes
we deliberately do not copy — its charset excludes `# $ ! % ~ & *`, and its
kebab-segment rule drops `sk-proj-…` tokens.
