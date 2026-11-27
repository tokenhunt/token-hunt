"""SARIF 2.1.0 emission for GitHub code scanning ingestion."""
from __future__ import annotations

import json

from token_hunt.types import Match, Rule

SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"


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
    results = [
        {
            "ruleId": m.rule_id or m.kind,
            "level": "error",
            "message": {"text": f"Potential {m.kind} secret detected (fingerprint {m.fingerprint[:8]})."},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "input"},
                        "region": {"startLine": max(m.line, 1), "startColumn": max(m.column, 1)},
                    }
                }
            ],
            "partialFingerprints": {"tokenHuntFingerprint/v1": m.fingerprint},
        }
        for m in matches
    ]
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
