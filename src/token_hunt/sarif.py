"""SARIF 2.1.0 emission for GitHub code scanning ingestion."""
from __future__ import annotations

import hashlib
import json

from token_hunt.types import Match, Rule

SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"


def _fallback_fingerprint(m: Match) -> str:
    """Deterministic identity for matches that carry no literal-secret hash.

    Escape-hatch expansions and entropy candidates never see the underlying
    secret, so they arrive with an empty fingerprint. We hash kind + NUL +
    value instead. Omitting line/column from the input is deliberate: GitHub
    keys alert identity on this fingerprint, so the same expansion re-appearing
    on any line in any commit folds into ONE alert instead of a fresh one per
    scan. Including kind namespaces `escape:<pattern>` apart from
    `entropy-candidate`, so the same emitted text cannot collide across
    detector paths.
    """
    digest = hashlib.sha256(f"{m.kind}\x00{m.value}".encode()).hexdigest()
    return digest[:16]


def _synthesized_rule_entries(matches: list[Match], known_ids: set[str]) -> list[dict]:
    """Minimal driver rule entries for result kinds not covered by loaded rules."""
    entries: list[dict] = []
    seen: set[str] = set()
    for m in matches:
        rid = m.rule_id or m.kind
        if rid in known_ids or rid in seen:
            continue
        seen.add(rid)
        if rid.startswith("escape:"):
            desc = "Bash escape-hatch secret expansion"
            help_text = ("A shell expansion evaluated a secret variable into emitted text; "
                         "the literal value never passed the scanner. Rotate the underlying "
                         "credential and re-run with the value masked.")
        elif rid == "entropy-candidate":
            desc = "High-entropy candidate string"
            help_text = ("A high-entropy string no known rule matched. Treat it as a potential "
                         "secret: identify where it came from and rotate it if it maps to a "
                         "live credential.")
        else:
            desc = f"Potential secret ({rid})"
            help_text = "Rotate this credential."
        entries.append({
            "id": rid,
            "name": rid,
            "shortDescription": {"text": desc},
            "help": {"text": help_text},
        })
    return entries


def emit_sarif(matches: list[Match], rules: list[Rule], version: str) -> str:
    rule_entries = [
        {
            "id": r.id,
            "name": r.id,
            "shortDescription": {"text": r.description or r.id},
            "help": {"text": f"Rotate at {r.rotate_url}" if r.rotate_url else "Rotate this credential."},
        }
        for r in rules
    ]
    rule_entries.extend(_synthesized_rule_entries(matches, {r.id for r in rules}))
    results = []
    for m in matches:
        fp = m.fingerprint or _fallback_fingerprint(m)
        results.append({
            "ruleId": m.rule_id or m.kind,
            "level": "error",
            "message": {"text": f"Potential {m.kind} secret detected (fingerprint {fp[:8]})."},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "input"},
                        "region": {"startLine": max(m.line, 1), "startColumn": max(m.column, 1)},
                    }
                }
            ],
            "partialFingerprints": {"tokenHuntFingerprint/v1": fp},
        })
    doc = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "token-hunt", "version": version,
                                    "informationUri": "https://tokenhunt.dev",
                                    "rules": rule_entries}},
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)
