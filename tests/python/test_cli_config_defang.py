import json

import pytest
from conftest import ROOT, SAMPLES

from phishtriage.cli import main
from phishtriage.config import DEFAULT_CONFIG, ConfigError, load_config
from phishtriage.defang import defang_domain, defang_url, refang

# --- CLI --------------------------------------------------------------------------------------


def test_json_output_for_a_folder(tmp_path):
    out = tmp_path / "result.json"
    assert main(["analyze", str(SAMPLES), "--format", "json", "--output", str(out)]) == 0
    results = json.loads(out.read_text(encoding="utf-8"))
    assert len(results) == 7
    assert {"file", "verdict", "score", "findings", "iocs", "actions"} <= set(results[0])


def test_text_output(capsys):
    assert main(["analyze", str(SAMPLES / "02-password-expiry-lookalike.eml")]) == 0
    out = capsys.readouterr().out
    assert "[PHISHING 100] 02-password-expiry-lookalike.eml" in out
    assert "c0ntoso[.]com" in out


def test_an_unreadable_file_is_reported_and_the_rest_still_triaged(tmp_path):
    out = tmp_path / "result.json"
    missing = tmp_path / "missing.eml"
    empty = tmp_path / "empty.eml"
    empty.write_bytes(b"")
    code = main(["analyze", str(missing), str(empty), str(SAMPLES / "01-internal-newsletter.eml"),
                 "--format", "json", "--output", str(out)])  # fmt: skip
    results = json.loads(out.read_text(encoding="utf-8"))
    assert code == 1
    assert [("error" in r) for r in results] == [True, True, False]


def test_a_folder_without_mail_is_a_usage_error(tmp_path):
    assert main(["analyze", str(tmp_path)]) == 2


def test_a_broken_config_is_a_usage_error(tmp_path, capsys):
    config = tmp_path / "bad.json"
    config.write_text('{"org_domains": ["contoso.com"], "trusted_authserv_id": ["typo"]}', encoding="utf-8")
    assert main(["analyze", str(SAMPLES), "--config", str(config)]) == 2
    assert "unknown config keys: trusted_authserv_id" in capsys.readouterr().err


def test_config_file_changes_the_verdict(tmp_path):
    raw = json.loads((ROOT / "config" / "triage.json").read_text(encoding="utf-8"))
    raw["phishing_threshold"] = 90
    config, out = tmp_path / "strict.json", tmp_path / "out.json"
    config.write_text(json.dumps(raw), encoding="utf-8")
    sample = str(SAMPLES / "07-payroll-spoof-forged-auth.eml")
    main(["analyze", sample, "--config", str(config), "--format", "json", "--output", str(out)])
    assert json.loads(out.read_text(encoding="utf-8"))[0]["verdict"] == "suspicious"


# --- config -----------------------------------------------------------------------------------


def test_shipped_config_matches_the_defaults():
    assert load_config(ROOT / "config" / "triage.json") == DEFAULT_CONFIG


def test_domains_are_lowercased(tmp_path):
    path = tmp_path / "c.json"
    path.write_text('{"org_domains": ["Contoso.COM"], "trusted_authserv_ids": ["MX.contoso.com"]}', encoding="utf-8")
    config = load_config(path)
    assert config.org_domains == frozenset({"contoso.com"})
    assert config.trusted_authserv_ids == frozenset({"mx.contoso.com"})


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("not json", "not valid JSON"),
        ("[]", "JSON object"),
        ('{"org_domains": ["contoso.com"]}', "missing required config keys: trusted_authserv_ids"),
        ('{"org_domains": [], "trusted_authserv_ids": ["mx"]}', "at least one domain"),
        ('{"org_domains": "contoso.com", "trusted_authserv_ids": ["mx"]}', "list of non-empty strings"),
        ('{"org_domains": ["a.com"], "trusted_authserv_ids": ["mx"], "phishing_threshold": "60"}', "whole number"),
        ('{"org_domains": ["a.com"], "trusted_authserv_ids": ["mx"], "phishing_threshold": true}', "whole number"),
        ('{"org_domains": ["a.com"], "trusted_authserv_ids": ["mx"], "suspicious_threshold": 70}', "thresholds"),
    ],
)
def test_invalid_configs_are_rejected_with_a_reason(tmp_path, content, message):
    path = tmp_path / "c.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ConfigError, match=message):
        load_config(path)


def test_missing_config_file(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.json")


# --- defang -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://evil.example/a.php?x=1.2", "hxxps://evil[.]example/a.php?x=1.2"),
        ("HTTP://203.0.113.5/login", "hxxp://203[.]0[.]113[.]5/login"),
        ("evil.example/path", "evil[.]example/path"),
    ],
)
def test_defang_url(url, expected):
    assert defang_url(url) == expected


def test_defang_and_refang_round_trip():
    assert defang_domain("mail.evil.example") == "mail[.]evil[.]example"
    assert refang(defang_url("https://evil.example/x")) == "https://evil.example/x"
