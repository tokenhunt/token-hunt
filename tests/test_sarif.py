import json
import re
from dataclasses import replace

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


def test_sarif_fallback_fingerprint_is_16_hex():
    m = replace(_match(), fingerprint="")
    doc = json.loads(emit_sarif([m], rules=[], version="1"))
    fp = doc["runs"][0]["results"][0]["partialFingerprints"]["tokenHuntFingerprint/v1"]
    assert re.fullmatch(r"[0-9a-f]{16}", fp)


def test_sarif_fallback_fingerprint_stable():
    m = replace(_match(), fingerprint="")
    a = json.loads(emit_sarif([m], rules=[], version="1"))["runs"][0]["results"][0]
    b = json.loads(emit_sarif([m], rules=[], version="1"))["runs"][0]["results"][0]
    assert a["partialFingerprints"] == b["partialFingerprints"]


def test_sarif_fallback_fingerprint_namespaced_by_kind():
    value = "eval $AWS_SECRET_ACCESS_KEY"
    escape = Match(
        kind="escape:AWS_SECRET_ACCESS_KEY", value=value, fingerprint="",
        rotate_url="", detection_point="PreToolUse:Bash",
        confidence=0.85, rule_id="escape:curl_eval", line=1, column=1,
    )
    entropy = Match(
        kind="entropy-candidate", value=value, fingerprint="",
        rotate_url="", detection_point="PreToolUse:Bash",
        confidence=0.6, rule_id="", line=1, column=1,
    )
    fp_escape = json.loads(emit_sarif([escape], rules=[], version="1"))["runs"][0]["results"][0]
    fp_entropy = json.loads(emit_sarif([entropy], rules=[], version="1"))["runs"][0]["results"][0]
    assert (fp_escape["partialFingerprints"]["tokenHuntFingerprint/v1"]
            != fp_entropy["partialFingerprints"]["tokenHuntFingerprint/v1"])


def test_sarif_synthesizes_rule_entries_for_uncovered_kinds():
    m = Match(
        kind="escape:AWS_SECRET_ACCESS_KEY", value="eval $AWS_SECRET_ACCESS_KEY", fingerprint="",
        rotate_url="", detection_point="PreToolUse:Bash",
        confidence=0.85, rule_id="escape:curl_eval", line=2, column=5,
    )
    run = json.loads(emit_sarif([m], rules=[], version="1"))["runs"][0]
    entry = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "escape:curl_eval")
    assert entry["shortDescription"]["text"] == "Bash escape-hatch secret expansion"
    assert entry["help"]["text"]


def test_sarif_does_not_duplicate_covered_rule_entries():
    m = _match()
    run = json.loads(emit_sarif([m], rules=[Rule(id="github-pat", regex="x")], version="1"))
    ids = [r["id"] for r in run["runs"][0]["tool"]["driver"]["rules"]]
    assert ids == ["github-pat"]
