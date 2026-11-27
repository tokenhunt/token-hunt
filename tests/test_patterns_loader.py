import pytest

from token_hunt.patterns_loader import Rule, load_builtin_rules


def test_load_builtin_rules_returns_list():
    rules = load_builtin_rules()
    assert isinstance(rules, list)
    assert len(rules) == 48


def test_rules_have_required_fields():
    rules = load_builtin_rules()
    for rule in rules:
        assert isinstance(rule, Rule)
        assert rule.id
        assert rule.regex
        assert rule.rotate_url.startswith("https://") or rule.id.startswith("generic-")


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


def test_invalid_toml_raises(tmp_path):
    bad = tmp_path / "bad.toml"
    bad.write_text("not valid toml [[")
    from token_hunt.patterns_loader import load_rules_from_path
    with pytest.raises(ValueError, match="invalid TOML"):
        load_rules_from_path(bad)
