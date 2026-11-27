r"""Convert gitleaks.toml rules into token-hunt TOML (one-time corpus port).

Port policy (design 2026-11-27, revised per coordinator ruling):
- SKIP rules with `path` (file-tree scoping is meaningless for transcript scans)
- Port `entropy` rules WITH their thresholds (`entropy = <float>`; token-hunt's
  regex_scanner applies the per-rule Shannon gate — this is gitleaks' anti-FP
  mechanism and is preserved, not dropped)
- `secretGroup` -> `secret_group`
- `keywords` passthrough; empty -> omitted
- mid-pattern `(?i)` rewritten to scoped-group form (`X(?i)Y` -> `X(?i:Y)`;
  Python re only allows global flags at pattern start) and Go's `\z` anchor
  rewritten to Python's `\Z` (identical strict end-of-string semantics; Python
  re <3.14 rejects `\z`); counted as `regex-rewritten`, not skipped
- POSIX classes (`[:alnum:]` etc.) translated to explicit ASCII ranges inside
  the enclosing brackets; counted as `posix-normalized`
- the compile gate runs with FutureWarning as error, so Python's silent
  "possible nested set" heuristics (e.g. untranslated POSIX classes) reject
  the rule instead of porting a misparse
- ids prefixed `gitleaks-` to never collide with the 48 builtin ids
- `rotate_url` omitted (unknown for ported rules; providers can be mapped later)

Outputs: converted TOML on stdout, port report on stderr.
"""
from __future__ import annotations

import re
import sys
import warnings
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

VENDOR = Path(__file__).parent / "vendor" / "gitleaks.toml"

# POSIX character classes -> explicit ASCII-range equivalents. The inner
# `[:name:]` token is substituted, preserving the host class's brackets —
# so standalone `[[:alnum:]]` -> `[0-9A-Za-z]` and embedded
# `[[:digit:]_-]` -> `[0-9_-]` both translate correctly.
POSIX_CLASSES = {
    "alnum": "0-9A-Za-z",
    "alpha": "A-Za-z",
    "digit": "0-9",
    "xdigit": "0-9A-Fa-f",
    "upper": "A-Z",
    "lower": "a-z",
    "space": r" \t\n\v\f\r",
    "blank": r" \t",
    "punct": r"!-/:-@\[-`{-~",
    "word": "0-9A-Za-z_",
    "cntrl": r"\x00-\x1f\x7f",
}
POSIX_RE = re.compile(r"\[:([a-z]+):\]")


def _rewrite_mid_pattern_case_insensitive(regex: str) -> str:
    """Rewrite mid-pattern `(?i)` into scoped groups: `X(?i)Y` -> `X(?i:Y)`.

    gitleaks (Go/RE2) lets `(?i)` flip case sensitivity from its position to
    the end; Python re rejects global flags anywhere but pattern start. Each
    mid occurrence becomes an opening scoped group closed at pattern end
    (nesting preserves RE2's from-here-on semantics).
    """
    out = regex
    changed = True
    # safe only when nothing case-sensitive follows the flag's enclosing group; verified for this corpus
    while changed:
        changed = False
        idx = out.find("(?i)", 1)
        if idx != -1:
            out = out[:idx] + "(?i:" + out[idx + 4:] + ")"
            changed = True
    return out


def _normalize_regex(regex: str) -> tuple[str, bool, bool, int, str | None]:
    """Port a Go/RE2 regex to Python re.

    Returns (regex, had_mid_flag, had_z_anchor, posix_count, unknown_posix)."""
    had_mid_flag = regex.find("(?i)", 1) != -1
    if had_mid_flag:
        regex = _rewrite_mid_pattern_case_insensitive(regex)
    had_z_anchor = r"\z" in regex
    if had_z_anchor:
        regex = regex.replace(r"\z", r"\Z")
    posix_count = 0
    unknown_posix = None
    for m in POSIX_RE.finditer(regex):
        if m.group(1) not in POSIX_CLASSES:
            unknown_posix = f"unknown posix class [:{m.group(1)}:]"
            break

    def _sub(m: re.Match[str]) -> str:
        nonlocal posix_count
        posix_count += 1
        return POSIX_CLASSES[m.group(1)]

    if unknown_posix is None and POSIX_RE.search(regex):
        # assumes [:name:] tokens only occur inside real character classes —
        # zero counter-examples in this corpus (verified)
        regex = POSIX_RE.sub(_sub, regex)
    return regex, had_mid_flag, had_z_anchor, posix_count, unknown_posix


def main() -> int:
    data = tomllib.loads(VENDOR.read_text(encoding="utf-8"))
    ported, skipped, rewritten = [], [], 0
    entropy_gated = 0
    posix_normalized = 0
    rewrite_detail: list[tuple[str, bool, bool]] = []
    seen_ids: set[str] = set()
    dupe_count = 0
    for r in data.get("rules", []):
        rid = r.get("id", "")
        reason = None
        if r.get("path"):
            reason = "path-scoped"
        elif not r.get("regex"):
            reason = "no regex"
        if reason:
            skipped.append((rid, reason))
            continue
        if rid in seen_ids:
            dupe_count += 1
            skipped.append((rid, "duplicate id (kept first)"))
            continue
        seen_ids.add(rid)
        regex, had_mid_flag, had_z_anchor, posix_count, unknown_posix = _normalize_regex(r["regex"])
        if unknown_posix:
            skipped.append((rid, unknown_posix))
            continue
        if had_mid_flag or had_z_anchor:
            rewritten += 1
            rewrite_detail.append((rid, had_mid_flag, had_z_anchor))
        posix_normalized += posix_count
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", FutureWarning)  # silent misparses (POSIX classes etc.) must not port
                re.compile(regex)
        except re.error:
            skipped.append((rid, "invalid regex under Python re (after rewrite)"))
            continue
        except FutureWarning:
            skipped.append((rid, "posix class or re2-ism (Python re warning)"))
            continue
        rule_lines = [
            f'id = "gitleaks-{rid}"',
            f'description = {r.get("description", rid)!r}',
            f"regex = '''{regex}'''",
        ]
        entropy = r.get("entropy")
        if entropy:
            rule_lines.append(f"entropy = {float(entropy)}")
            entropy_gated += 1
        kws = [k for k in r.get("keywords", []) if k]
        if kws:
            rule_lines.append("keywords = [" + ", ".join(f'"{k}"' for k in kws) + "]")
        if r.get("secretGroup"):
            rule_lines.append(f"secret_group = {r['secretGroup']}")
        ported.append("[[rules]]\n" + "\n".join(rule_lines) + "\n")

    header = (
        "# Ported from gitleaks (MIT) — see scripts/vendor/COPYING.gitleaks and PROVENANCE.md.\n"
        "# Generated by scripts/convert_gitleaks.py. Do not hand-edit generated blocks;\n"
        "# edit the converter + regenerate.\n\n"
    )
    sys.stdout.write(header + "\n".join(ported))
    print(
        f"ported: {len(ported)}  skipped: {len(skipped)}  "
        f"regex-rewritten: {rewritten}  entropy-gated: {entropy_gated}  "
        f"posix-normalized: {posix_normalized}",
        file=sys.stderr,
    )
    for rid, had_mid_flag, had_z_anchor in rewrite_detail:
        kinds = []
        if had_mid_flag:
            kinds.append("(?i)->scoped-group")
        if had_z_anchor:
            kinds.append(r"\z->\Z")
        print(f"  REWRITE {rid}: {'+'.join(kinds)}", file=sys.stderr)
    if dupe_count:
        print(f"  duplicate ids deduped: {dupe_count}", file=sys.stderr)
    for rid, why in skipped:
        print(f"  SKIP {rid}: {why}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
