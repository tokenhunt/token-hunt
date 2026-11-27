import pytest

from token_hunt.patterns_loader import Rule, load_builtin_rules


def test_load_builtin_rules_returns_list():
    from token_hunt.patterns_loader import BUILTIN_PATTERNS_DIR, load_rules_from_path
    ported = BUILTIN_PATTERNS_DIR / "gitleaks-port.toml"
    rules = load_builtin_rules()
    assert isinstance(rules, list)
    assert len(rules) == 48 + len(load_rules_from_path(ported))


def test_corpus_acceptance_gate():
    # the full gitleaks port (217 rules) + 48 builtins must always load; if
    # this dips below 200, a batch or the port file itself went missing
    rules = load_builtin_rules()
    assert len(rules) >= 200, f"corpus acceptance gate: expected >= 200 rules, got {len(rules)}"


def test_rules_have_required_fields():
    rules = load_builtin_rules()
    for rule in rules:
        assert isinstance(rule, Rule)
        assert rule.id
        assert rule.regex
        # ported gitleaks rules omit rotate_url by policy (unknown provider mapping)
        assert rule.rotate_url.startswith("https://") or rule.id.startswith(
            "generic-"
        ) or rule.id.startswith("gitleaks-")


def test_zai_rule_present():
    rules = load_builtin_rules()
    zai = next(r for r in rules if r.id == "zai-api-key")
    assert "z.ai" in zai.rotate_url.lower() or "zai" in zai.rotate_url.lower()


def test_secret_group_gitleaks_spelling(tmp_path):
    toml = tmp_path / "rules.toml"
    toml.write_text(
        '[[rules]]\n'
        'id = "grp"\n'
        'regex = "token=([a-z0-9]+)"\n'
        'secretGroup = 2\n'
    )
    from token_hunt.patterns_loader import load_rules_from_path
    rules = load_rules_from_path(toml)
    assert rules[0].secret_group == 2


def test_secret_group_defaults_to_zero(tmp_path):
    toml = tmp_path / "rules.toml"
    toml.write_text(
        '[[rules]]\n'
        'id = "plain"\n'
        'regex = "[a-z0-9]+"\n'
    )
    from token_hunt.patterns_loader import load_rules_from_path
    rules = load_rules_from_path(toml)
    assert rules[0].secret_group == 0


def test_entropy_parsed_as_float(tmp_path):
    toml = tmp_path / "rules.toml"
    toml.write_text(
        '[[rules]]\n'
        'id = "ent"\n'
        'regex = "[a-z0-9]{20}"\n'
        'entropy = 3.5\n'
    )
    from token_hunt.patterns_loader import load_rules_from_path
    rules = load_rules_from_path(toml)
    assert rules[0].entropy == 3.5


def test_entropy_defaults_to_zero(tmp_path):
    toml = tmp_path / "rules.toml"
    toml.write_text(
        '[[rules]]\n'
        'id = "plain"\n'
        'regex = "[a-z0-9]+"\n'
    )
    from token_hunt.patterns_loader import load_rules_from_path
    rules = load_rules_from_path(toml)
    assert rules[0].entropy == 0


def test_invalid_toml_raises(tmp_path):
    bad = tmp_path / "bad.toml"
    bad.write_text("not valid toml [[")
    from token_hunt.patterns_loader import load_rules_from_path
    with pytest.raises(ValueError, match="invalid TOML"):
        load_rules_from_path(bad)


def test_gitleaks_port_file_loads_if_present():
    from token_hunt.patterns_loader import BUILTIN_PATTERNS_DIR, load_rules_from_path
    ported = BUILTIN_PATTERNS_DIR / "gitleaks-port.toml"
    if not ported.is_file():
        pytest.skip("gitleaks-port.toml not yet vendored")
    rules = load_rules_from_path(ported)
    assert len(rules) > 0
    assert all(r.id.startswith("gitleaks-") for r in rules)
    assert len({r.id for r in rules}) == len(rules), "duplicate ids in port"


def test_builtin_and_ported_ids_disjoint():
    from token_hunt.patterns_loader import BUILTIN_PATTERNS_DIR, load_rules_from_path
    base = load_rules_from_path(BUILTIN_PATTERNS_DIR / "builtin.toml")
    ported_path = BUILTIN_PATTERNS_DIR / "gitleaks-port.toml"
    if not ported_path.is_file():
        pytest.skip("port not vendored yet")
    ported = load_rules_from_path(ported_path)
    assert not ({r.id for r in base} & {r.id for r in ported})
