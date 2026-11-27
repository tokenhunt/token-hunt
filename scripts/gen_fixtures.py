r"""Synthesize per-rule positive/negative fixtures for a token-hunt port TOML.

For every rule in the given TOML, walks the parsed regex (Python sre parse tree)
and builds a deterministic sample that the rule must fire on, plus a negative
(the positive truncated ~1/7 of its length, min 1 char) that must NOT fire.

Supported shapes: LITERAL, NOT_LITERAL, ANY, IN (literals / RANGES / category
escapes; NEGATE unsupported), MAX_REPEAT/MIN_REPEAT (n picked in
[lo, min(hi, max(lo, 6))], MAXREPEAT clamped to 6), SUBPATTERN, BRANCH (first
branch), AT anchors (skipped), category escapes outside classes (\d -> digit
pool etc.).

Anything else (lookarounds, backreferences, negated classes, atomic groups)
is refused: `NEEDS-HAND-FIXTURE <id>: <reason>` on stderr, non-zero exit when
any rule needs a hand fixture.

Output: python-sourceable ("id", "positive", "negative") tuples on stdout.
Every emitted string literal is chunked so no contiguous secret-shaped literal
appears in the source (the repo's own gitleaks pre-commit hook scans staged
files; chunking puts quote characters between fragments).

Keyword-gated rules get a realistic `<KEYWORD>_KEY=`-style prefix on BOTH
positive and negative, so the negative fails on shape, not on pre-filter.
Verification runs through the real scanner (token_hunt.regex_scanner), so
keyword pre-filter, entropy gate and secret_group are all exercised.
"""
from __future__ import annotations

import random
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import re._constants as sre_constants
    import re._parser as sre_parse
else:
    import sre_constants
    import sre_parse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from token_hunt.patterns_loader import load_rules_from_path
from token_hunt.regex_scanner import scan_regex
from token_hunt.types import ScanContext

MAX_REPEAT_LEN = 6
ATTEMPTS = 40
DIGITS = "0123456789"
LOWERS = "abcdefghijklmnopqrstuvwxyz"
UPPERS = LOWERS.upper()
WORD_CHARS = LOWERS + UPPERS + DIGITS + "_"
SPACE_CHARS = " \t"
ANY_CHARS = (LOWERS + UPPERS + DIGITS + "+/=_-.,:;()[]{}<>@#$%^&*!~`|\\'\"")
NEWLINES = "\n\r"

Ctx = ScanContext(detection_point="UserPromptSubmit")

# 3.11+ ops absent from 3.10's sre_constants — getattr keeps the 3.10 matrix green
_ATOMIC_GROUP = getattr(sre_constants, "ATOMIC_GROUP", None)
_POSSESSIVE_REPEAT = getattr(sre_constants, "POSSESSIVE_REPEAT", None)


class Unsupported(Exception):
    """The parse tree contains a construct we refuse to synthesize."""


def _pick(rng: random.Random, pool: str) -> str:
    ch = rng.choice(pool)
    # samples are scanned line-by-line; a literal newline would split the match
    while ch in NEWLINES:
        ch = rng.choice(pool)
    return ch


def _range_char(rng: random.Random, lo: str, hi: str) -> str:
    ch = chr(rng.randint(ord(lo), ord(hi)))
    return "?" if ch in NEWLINES else ch


def _category_pool(category) -> str:
    name = str(category).rsplit("_", 1)[-1].lower()
    return {
        "digit": DIGITS,
        "word": WORD_CHARS,
        "space": SPACE_CHARS,
    }.get(name, "")


def _char_for_in_item(rng: random.Random, op, av) -> str:
    if op is sre_constants.LITERAL:
        ch = chr(av)
        return "?" if ch in NEWLINES else ch  # newline would split the line scan
    if op is sre_constants.RANGE:
        lo, hi = av
        return _range_char(rng, chr(lo), chr(hi))
    if op is sre_constants.CATEGORY:
        pool = _category_pool(av)
        if not pool:
            raise Unsupported(f"category escape {av!r} inside char class")
        return _pick(rng, pool)
    raise Unsupported(f"{op!r} inside char class")


def _in_item_weight(op, av) -> int:
    # weight class items by their char-set size so chars are drawn ~uniformly
    # over the class — uniform item choice would make [\w-] 50% dashes and
    # sink entropy-gated rules below their thresholds
    if op is sre_constants.RANGE:
        return min(max(av[1] - av[0] + 1, 1), 512)
    if op is sre_constants.CATEGORY:
        return len(_category_pool(av)) or 1
    return 1  # LITERAL and anything else


def _sample(rng: random.Random, parsed, depth: int = 0) -> str:
    if depth > 50:
        raise Unsupported("pattern nested too deeply")
    out = []
    for op, av in parsed:
        if op is sre_constants.LITERAL:
            ch = chr(av)
            if ch in NEWLINES:
                raise Unsupported("pattern requires a literal newline in the match")
            out.append(ch)
        elif op is sre_constants.NOT_LITERAL:
            out.append("q" if chr(av) != "q" else "z")
        elif op is sre_constants.ANY:
            out.append(_pick(rng, ANY_CHARS))
        elif op is sre_constants.IN:
            negate = any(iop is sre_constants.NEGATE for iop, _ in av)
            if negate:
                raise Unsupported("negated character class")
            items = rng.choices(av, weights=[_in_item_weight(iop, iav) for iop, iav in av])[0]
            out.append(_char_for_in_item(rng, *items))
        elif op is sre_constants.CATEGORY:
            pool = _category_pool(av)
            if not pool:
                raise Unsupported(f"category escape {av!r}")
            out.append(_pick(rng, pool))
        elif op in (sre_constants.MAX_REPEAT, sre_constants.MIN_REPEAT):
            lo, hi, item = av
            if hi == sre_constants.MAXREPEAT:
                hi = max(lo, MAX_REPEAT_LEN)
            if hi < lo:  # paranoia: unreachable — MAXREPEAT expands to >= lo above, and re.compile rejects {n,m} with m < n
                raise Unsupported(f"repetition {{{lo},{hi}}} has empty range")
            n = rng.randint(lo, min(hi, max(lo, MAX_REPEAT_LEN)))
            # n independent draws — duplicating one draw kills entropy gates
            out.append("".join(_sample(rng, item, depth + 1) for _ in range(n)))
        elif op is sre_constants.SUBPATTERN:
            _group, _add, _del, items = av
            out.append(_sample(rng, items, depth + 1))
        elif op is sre_constants.BRANCH:
            _has_group, branches = av
            out.append(_sample(rng, branches[0], depth + 1))
        elif op is sre_constants.AT:
            continue  # anchors: nothing to synthesize
        elif op in (sre_constants.ASSERT, sre_constants.ASSERT_NOT):
            raise Unsupported("lookaround assertion")
        elif op is sre_constants.GROUPREF:
            raise Unsupported("backreference")
        elif op is sre_constants.GROUPREF_EXISTS:
            raise Unsupported("conditional backreference")
        elif _ATOMIC_GROUP is not None and op is _ATOMIC_GROUP:
            raise Unsupported("atomic group")
        elif _POSSESSIVE_REPEAT is not None and op is _POSSESSIVE_REPEAT:
            raise Unsupported("possessive repeat")
        else:
            raise Unsupported(f"unhandled regex op {op!r}")
    return "".join(out)


def _synthesize(rng: random.Random, rule) -> tuple[str, str, str]:
    """Return (positive_line, negative_line, note) or raise Unsupported."""
    parsed = sre_parse.parse(rule.regex)
    keyword = rule.keywords[0] if rule.keywords else ""
    prefix = keyword.upper() + "_KEY=" if keyword else ""

    for attempt in range(ATTEMPTS):
        sample = _sample(rng, parsed)
        positive = prefix + sample
        if not scan_regex(positive, [rule], Ctx):
            continue  # gate rejected this draw (entropy / shape) — try another
        base_cut = max(1, len(positive) // 7)
        negative = None
        note = ""
        for cut in [base_cut * i for i in range(1, 6)]:
            candidate = positive[:-cut]
            if len(candidate) <= len(prefix):
                break
            if not scan_regex(candidate, [rule], Ctx):
                negative = candidate
                break
        if negative is None:
            # two negative strategies coexist: end-truncation is the canonical
            # negative (negative = partial token), but open-ended repetitions
            # ({n,}) still match after any truncation — for those, mutate the
            # token's last char into one the sample alphabet avoids
            for brk in "!?#%":
                candidate = positive[:-1] + brk
                if candidate != positive and not scan_regex(candidate, [rule], Ctx):
                    negative = candidate
                    note = "negative=last-char mutation (end-truncation still matched)"
                    break
        if negative is None:
            continue
        return positive, negative, note
    raise Unsupported(
        f"no synthesized sample survived the rule's gates after {ATTEMPTS} draws "
        "(entropy threshold / match shape unreachable from its own charset)"
    )


def _chunks(s: str, size: int = 16) -> list[str]:
    return [s[i:i + size] for i in range(0, len(s), size)]


def _emit_tuple(rule_id: str, positive: str, negative: str) -> str:
    def lit_lines(s: str) -> str:
        # implicit concatenation inside parens: keeps every source literal a
        # short chunk (quote characters break contiguous secret-shaped text
        # for literal scanners) while satisfying ruff's ISC rules
        lines = [f"            {c!r}" for c in _chunks(s)]
        return "        (\n" + "\n".join(lines) + "\n        )"

    return (
        "    (\n"
        f'        "{rule_id}",\n'
        f"{lit_lines(positive)},\n"
        f"{lit_lines(negative)},\n"
        "    ),"
    )


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else \
        Path(__file__).resolve().parent.parent / "src" / "token_hunt" / "patterns" / "gitleaks-port.toml"
    rules = load_rules_from_path(path)
    hand_fixtures: list[tuple[str, str]] = []
    emitted: list[str] = []
    fallback_notes: list[str] = []
    for rule in rules:
        rng = random.Random(rule.id)  # deterministic per rule
        try:
            positive, negative, note = _synthesize(rng, rule)
        except Unsupported as e:
            hand_fixtures.append((rule.id, str(e)))
            print(f"NEEDS-HAND-FIXTURE {rule.id}: {e}", file=sys.stderr)
            continue
        if note:
            fallback_notes.append(f"{rule.id}: {note}")
        emitted.append(_emit_tuple(rule.id, positive, negative))

    print("\n".join(emitted))
    for note in fallback_notes:
        print(f"NOTE {note}", file=sys.stderr)
    print(f"\nemitted: {len(emitted)}  needs-hand-fixture: {len(hand_fixtures)}", file=sys.stderr)
    return min(len(hand_fixtures), 125)  # >125 is reserved/undefined as a process exit code


if __name__ == "__main__":
    sys.exit(main())
