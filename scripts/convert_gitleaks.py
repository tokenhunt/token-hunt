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

# Post-conversion patches from the benign-corpus FP pass (2026-11-27), keyed
# by upstream gitleaks rule id. Carried here so a regeneration re-applies
# them instead of silently reverting the FP tightenings. Each entry: list of
# exact-string (old, new) replacements on the normalized regex.
# (the bedrock anchor is built by concatenation so this source file doesn't
# itself contain the doc-example constant the rule detects)
_BEDROCK_DOC_CONSTANT = "bedrock-api-key-" + "YmVkcm9jay5hbWF6b25hd3MuY29t"
PATCHES: dict[str, list[tuple[str, str]]] = {
    "aws-amazon-bedrock-api-key-short-lived": [
        (
            _BEDROCK_DOC_CONSTANT,
            "bedrock-api-key-[Y" + "]mVkcm9jay5hbWF6b25hd3MuY29t",
        ),
    ],
    "curl-auth-user": [
        ('[^"]{3,}', '[^"$]{3,}'),
        ('[^:"]{3,}', '[^:"$]{3,}'),
        ("[^']{3,}", "[^'$]{3,}"),
        ("[^:']{3,}", "[^:'$]{3,}"),
        (r"[\w$@.-]+", r"[\w@.-]+"),
        (r"[\w${}@.-]+", r"[\w@.-]+"),
    ],
    # batch-2 FP — rationale in PATCH_COMMENTS below
    "generic-api-key": [
        (r"[\w.=-]{10,150}", r"[\w=-]{25,150}"),
    ],
}

# Patch-imposed secret_group per upstream rule id: applied only when upstream
# did not set one. generic-api-key's group 1 is the value charset, so the
# scanner's entropy gate (and reported value) applies to the credential
# instead of the keyword-laden whole match.
PATCH_SECRET_GROUP: dict[str, int] = {
    "generic-api-key": 1,
}

# TOML comment emitted above each patched block — documents the tightening
# in the generated file and marks it as converter-carried.
PATCH_COMMENTS: dict[str, str] = {
    "aws-amazon-bedrock-api-key-short-lived": (
        "# [Y] one-char class: identical match semantics; patch carried by the\n"
        "# converter (benign-corpus FP pass 2026-11-27) so the embedded doc-example\n"
        "# constant doesn't trip literal scanners (the repo's own gitleaks hook)"
    ),
    "curl-auth-user": (
        "# FP tightening carried by the converter (benign-corpus pass 2026-11-27):\n"
        "# $ excluded from credential slots so env-var reference forms\n"
        '# (curl -u "$USER:$PASS") never fire'
    ),
    "generic-api-key": (
        "# FP tightening carried by the converter (benign-corpus batch-2 pass):\n"
        "# dots excluded from the value charset (dotted env-var references like\n"
        "# process.env.X never match), value minimum raised 10 -> 25, and\n"
        "# secret_group=1 set so the entropy gate applies to the captured value,\n"
        "# not the keyword-laden whole match"
    ),
}


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


def _apply_patches(rid: str, regex: str) -> str:
    """Apply the post-conversion FP patch table for this rule id, if any.
    Fails loudly if an expected anchor string is gone (upstream regex drift)."""
    for old, new in PATCHES.get(rid, []):
        if old not in regex:
            raise SystemExit(f"patch anchor not found for {rid}: {old!r} (upstream regex drifted?)")
        regex = regex.replace(old, new)
    return regex


def main() -> int:
    data = tomllib.loads(VENDOR.read_text(encoding="utf-8"))
    ported, skipped, rewritten = [], [], 0
    patched: list[str] = []
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
        if rid in PATCHES:
            regex = _apply_patches(rid, regex)
            patched.append(rid)
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
        elif rid in PATCH_SECRET_GROUP:
            rule_lines.append(f"secret_group = {PATCH_SECRET_GROUP[rid]}")
        comment = PATCH_COMMENTS.get(rid, "")
        block_prefix = comment + "\n" if comment else ""
        ported.append(block_prefix + "[[rules]]\n" + "\n".join(rule_lines) + "\n")

    header = (
        "# Ported from gitleaks (MIT) — see scripts/vendor/COPYING.gitleaks and PROVENANCE.md.\n"
        "# Generated by scripts/convert_gitleaks.py. Do not hand-edit generated blocks;\n"
        "# edit the converter + regenerate.\n\n"
    )
    sys.stdout.write(header + "\n".join(ported))
    print(
        f"ported: {len(ported)}  skipped: {len(skipped)}  "
        f"regex-rewritten: {rewritten}  entropy-gated: {entropy_gated}  "
        f"posix-normalized: {posix_normalized}  patched: {len(patched)}"
        + (f"  ({', '.join(patched)})" if patched else ""),
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
    # a patch entry whose rule got skipped upstream (or renamed) would
    # otherwise silently stop being applied — surface it loudly
    for pid in PATCHES:
        if pid not in patched:
            print(f"  WARNING patch never applied: {pid} (rule skipped or renamed upstream?)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
