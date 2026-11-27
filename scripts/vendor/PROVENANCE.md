# gitleaks corpus provenance

- **Source:** https://github.com/gitleaks/gitleaks
- **Tag:** `v8.30.1`
- **Commit SHA:** `83d9cd684c87d95d656c1458ef04895a7f1cbd8e`
- **Fetched:** 2026-11-27
- **Files:** `gitleaks.toml` (`config/gitleaks.toml` at the tag), `COPYING.gitleaks` (`LICENSE` at the tag)

## License

MIT License, Copyright (c) 2019 Zachary Rice — full text in
[COPYING.gitleaks](./COPYING.gitleaks). Ported rules must retain attribution:
this vendor directory + the generated-file header in the converted TOML are the
attribution chain.

## Port policy

One-shot conversion via `scripts/convert_gitleaks.py` (coordinator ruling
2026-11-27): skip `path`-scoped rules (file-tree scoping is meaningless for
transcript scans); port `entropy` rules WITH their per-rule Shannon thresholds
(gitleaks' anti-FP mechanism, applied by token-hunt's `regex_scanner`); rewrite
mid-pattern `(?i)` to scoped-group form and Go's `\z` anchor to Python's `\Z`;
prefix ids with `gitleaks-`; map `secretGroup` -> `secret_group`; omit
`rotate_url`.
