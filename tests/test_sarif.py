import json

from token_hunt.sarif import emit_sarif
from token_hunt.types import Match, Rule


def _match(rule_id="github-pat"):
    return Match(
        kind=rule_id, value="ghp_" + "A" * 36, fingerprint="abcd1234ef567890",
        rotate_url="https://github.com/settings/tokens",
        detection_point="UserPromptSubmit",
        confidence=0.95, rule_id=rule_id, line=3, column=7,
    )


def test_sarif_shape():
    doc = json.loads(emit_sarif([_match()], rules=[Rule(id="github-pat", regex="x")], version="0.1.2"))
    assert doc["$schema"].endswith("sarif-schema-2.1.0.json")
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "token-hunt"
    assert run["tool"]["driver"]["version"] == "0.1.2"
    assert any(r["id"] == "github-pat" for r in run["tool"]["driver"]["rules"])
    res = run["results"]
    assert len(res) == 1
    assert res[0]["ruleId"] == "github-pat"
    assert res[0]["level"] == "error"
    assert res[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 3
    fp = res[0]["partialFingerprints"]["tokenHuntFingerprint/v1"]
    assert fp == "abcd1234ef567890"


def test_sarif_stable_fingerprint():
    a = json.loads(emit_sarif([_match()], rules=[], version="1"))["runs"][0]["results"][0]
    b = json.loads(emit_sarif([_match()], rules=[], version="1"))["runs"][0]["results"][0]
    assert a["partialFingerprints"] == b["partialFingerprints"]


def test_sarif_empty_results():
    doc = json.loads(emit_sarif([], rules=[], version="1"))
    assert doc["runs"][0]["results"] == []
