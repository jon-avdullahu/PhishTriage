import hashlib
import importlib.util
from dataclasses import replace

import pytest
from conftest import ROOT, SAMPLES

from phishtriage.checks import Finding
from phishtriage.config import DEFAULT_CONFIG
from phishtriage.mail import parse_mail
from phishtriage.triage import NO_INDICATORS, PHISHING, SIMULATION, SUSPICIOUS, decide, triage_file

# Golden expectations for every sample: the exact verdict and the exact set of indicators.
EXPECTED = {
    "01-internal-newsletter.eml": (NO_INDICATORS, set()),
    "02-password-expiry-lookalike.eml": (
        PHISHING,
        {
            "SENDER_LOOKALIKE_DOMAIN",
            "DISPLAY_NAME_IMPERSONATION",
            "LINK_LOOKALIKE_DOMAIN",
            "LINK_TEXT_MISMATCH",
            "URGENCY_LANGUAGE",
            "CREDENTIAL_LURE",
        },
    ),
    "03-mfa-reregistration-de.eml": (
        PHISHING,
        {"AUTH_SPF_SOFTFAIL", "LINK_IP_ADDRESS", "LINK_TEXT_MISMATCH", "URGENCY_LANGUAGE", "CREDENTIAL_LURE"},
    ),
    "04-invoice-attachments.eml": (
        PHISHING,
        {"REPLY_TO_MISMATCH", "ATTACHMENT_DOUBLE_EXTENSION", "ATTACHMENT_MACRO", "URGENCY_LANGUAGE"},
    ),
    "05-ceo-gift-cards.eml": (SUSPICIOUS, {"DISPLAY_NAME_IMPERSONATION", "REPLY_TO_MISMATCH", "URGENCY_LANGUAGE"}),
    "06-phishing-simulation.eml": (SIMULATION, {"SENDER_LOOKALIKE_DOMAIN", "LINK_LOOKALIKE_DOMAIN"}),
    "07-payroll-spoof-forged-auth.eml": (
        PHISHING,
        {"AUTH_DMARC_FAIL", "AUTH_SPF_FAIL", "LINK_SHORTENER", "CREDENTIAL_LURE"},
    ),
}


def test_every_sample_has_an_expectation():
    assert sorted(p.name for p in SAMPLES.glob("*.eml")) == sorted(EXPECTED)


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_sample_verdicts_and_indicators(name):
    result = triage_file(SAMPLES / name)
    verdict, expected_codes = EXPECTED[name]
    assert result.verdict == verdict
    assert {f.code for f in result.findings} == expected_codes


def test_forged_authentication_header_from_the_sender_is_ignored():
    # Sample 07 contains a second, attacker-written "dmarc=pass" header below our gateway's "dmarc=fail".
    codes = {f.code for f in triage_file(SAMPLES / "07-payroll-spoof-forged-auth.eml").findings}
    assert "AUTH_DMARC_FAIL" in codes


def _findings(total: int) -> list[Finding]:
    return [Finding("X", total, "test")]


@pytest.mark.parametrize(
    ("score", "verdict"),
    [(0, NO_INDICATORS), (24, NO_INDICATORS), (25, SUSPICIOUS), (59, SUSPICIOUS), (60, PHISHING), (100, PHISHING)],
)
def test_verdict_thresholds(score, verdict):
    assert decide(_findings(score), simulation=False, config=DEFAULT_CONFIG) == (verdict, score)


def test_score_is_capped_at_100():
    assert decide(_findings(70) + _findings(70), simulation=False, config=DEFAULT_CONFIG) == (PHISHING, 100)


def test_simulation_wins_over_score():
    assert decide(_findings(100), simulation=True, config=DEFAULT_CONFIG)[0] == SIMULATION


def test_thresholds_come_from_config():
    strict = replace(DEFAULT_CONFIG, suspicious_threshold=10, phishing_threshold=20)
    assert decide(_findings(15), simulation=False, config=strict)[0] == SUSPICIOUS


def test_iocs_are_defanged_and_exclude_our_own_domains():
    iocs = triage_file(SAMPLES / "02-password-expiry-lookalike.eml").iocs
    assert iocs["domains"] == ["c0ntoso[.]com", "contoso-sso[.]example"]
    assert iocs["urls"] == ["hxxps://contoso-sso[.]example/owa/login"]
    assert iocs["ips"] == []


def test_ip_indicators_are_listed_separately():
    iocs = triage_file(SAMPLES / "03-mfa-reregistration-de.eml").iocs
    assert iocs["ips"] == ["203[.]0[.]113[.]45"]
    assert "203[.]0[.]113[.]45" not in iocs["domains"]


def test_attachment_hashes_match_the_attachment_bytes():
    mail = parse_mail((SAMPLES / "04-invoice-attachments.eml").read_bytes())
    iocs = triage_file(SAMPLES / "04-invoice-attachments.eml").iocs
    assert [a["sha256"] for a in iocs["attachments"]] == [a.sha256 for a in mail.attachments]
    assert all(len(h) == 64 and h != hashlib.sha256(b"").hexdigest() for h in (a.sha256 for a in mail.attachments))


def test_no_indicators_never_claims_the_mail_is_safe():
    actions = triage_file(SAMPLES / "01-internal-newsletter.eml").to_dict()["actions"]
    assert any("does not prove" in a for a in actions)


def test_committed_samples_match_the_generator(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("make_samples", ROOT / "tools" / "make_samples.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "OUT", tmp_path)
    module.main()
    for generated in tmp_path.iterdir():
        assert generated.read_bytes() == (SAMPLES / generated.name).read_bytes(), generated.name
