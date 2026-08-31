# Vendored: 0xdea/semgrep-rules

Marco Ivaldi's (`raptor`) curated Semgrep rules for C/C++ vulnerability research.

| | |
|---|---|
| Upstream | https://github.com/0xdea/semgrep-rules |
| Commit | `33155497b25b4639193db016962af2df46290b10` |
| Vendored | 2026-08-31 |
| License | MIT — see `LICENSE`, retained verbatim |
| Contents | `rules/c/` (49 rules), `rules/noisy/generic/` (1 rule) |

## Why vendored rather than fetched

Keystone's rule sets are stored YAML, and `keystone_engine.rulesets.materialize`
only ever hands Semgrep local paths it just wrote. Nothing fetches a registry or a
URL at scan time, so the worker needs no network egress. Pinning to a commit also
means a rule change upstream is a deliberate, reviewable re-vendor rather than a
silent shift in what an analysis means.

## What is here, and what is not

The `.c` / `.cpp` files beside each rule are **upstream's own test fixtures**,
annotated with `// ruleid:` / `// ok:` markers. Keystone never scans them — they
are kept so `semgrep --test rules/c` can verify the vendored copy still behaves
(see `tests/test_vendored_rules.py`). `sarif-example/` (1.1 MB) and `.github/` are
not vendored.

## Re-vendoring

```bash
curl -sSL https://codeload.github.com/0xdea/semgrep-rules/tar.gz/refs/heads/<sha> \
  | tar xz --strip-components=1 -C /tmp/0xdea
cp -r /tmp/0xdea/rules/{c,noisy} backend/semgrep-rules/0xdea/rules/
cp /tmp/0xdea/LICENSE backend/semgrep-rules/0xdea/LICENSE
# then update the commit above, and:
#   pytest tests/test_vendored_rules.py     -- every rule still validates
#   python -m keystone_api.cli bootstrap    -- changed groups append a new version
```

Grouping into Keystone rule sets is **not** done here — it lives in
`keystone_api/rule_import.py`, so this tree stays a faithful upstream copy that
`diff -r` can check.
