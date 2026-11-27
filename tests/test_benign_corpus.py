"""FP tripwire for the gitleaks port: every benign-corpus line must stay
silent under the FULL builtin rule set (48 builtins + all ported batches).
Parametrized per line so a failure names tests/benign_corpus.txt:<line>.
Kept load-bearing on purpose — batches 2-4 must keep this green or tighten
their rules before landing."""
from pathlib import Path

import pytest

from token_hunt.patterns_loader import (
    BUILTIN_PATTERNS_DIR,
    load_builtin_rules,
    load_rules_from_path,
)
from token_hunt.regex_scanner import scan_regex
from token_hunt.types import ScanContext

RULES = load_builtin_rules()
PORTED = load_rules_from_path(BUILTIN_PATTERNS_DIR / "gitleaks-port.toml")
CTX = ScanContext(detection_point="UserPromptSubmit")
CORPUS = Path(__file__).parent / "benign_corpus.txt"


def _corpus_lines() -> list[tuple[int, str]]:
    out = []
    for no, line in enumerate(CORPUS.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            out.append((no, line))
    return out


LINES = _corpus_lines()


@pytest.mark.parametrize("line_no,line", LINES, ids=[str(no) for no, _ in LINES])
def test_benign_line_triggers_no_rule(line_no: int, line: str) -> None:
    hits = scan_regex(line, RULES, CTX)
    assert not hits, (
        f"benign_corpus.txt:{line_no} triggered "
        f"{sorted({h.rule_id for h in hits})}: {line!r}"
    )


def test_benign_corpus_whole_text_triggers_no_ported_rule() -> None:
    # whole-text pass covers the multi-line rules (curl-auth-* may span up to
    # 5 lines via the [\r\n] alternatives), which per-line scans can't see.
    # Scoped to the ported set: the builtin generic-token rules (e.g.
    # cohere-key: any standalone 40-char alnum under a document-level keyword
    # pre-filter) fire across unrelated lines in any multi-line text — a
    # pre-existing builtin design issue, tracked separately.
    text = CORPUS.read_text(encoding="utf-8")
    hits = scan_regex(text, PORTED, CTX)
    assert not hits, f"benign corpus triggered: {sorted({h.rule_id for h in hits})}"
