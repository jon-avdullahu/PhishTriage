import pytest
from conftest import parsed, zip_of

from phishtriage.checks import is_approved_simulation, run_checks
from phishtriage.config import DEFAULT_CONFIG


def codes(**kwargs) -> set[str]:
    return {f.code for f in run_checks(parsed(**kwargs), DEFAULT_CONFIG)}


# --- authentication ---------------------------------------------------------------------------


def test_clean_mail_has_no_findings():
    assert codes(text="Lunch on Friday?") == set()


@pytest.mark.parametrize(
    ("auth", "expected"),
    [
        ("mx.contoso.com; spf=pass; dkim=pass; dmarc=fail", {"AUTH_DMARC_FAIL"}),
        ("mx.contoso.com; spf=fail; dkim=pass; dmarc=pass", {"AUTH_SPF_FAIL"}),
        ("mx.contoso.com; spf=softfail; dkim=pass; dmarc=pass", {"AUTH_SPF_SOFTFAIL"}),
        ("mx.contoso.com; spf=pass; dkim=fail; dmarc=pass", {"AUTH_DKIM_FAIL"}),
        ("mx.contoso.com; spf=none; dkim=none; dmarc=none", set()),
    ],
)
def test_authentication_results(auth, expected):
    assert codes(auth=auth) == expected


@pytest.mark.parametrize("auth", [None, "mail.attacker.example; spf=pass; dkim=pass; dmarc=pass"])
def test_results_not_from_our_gateway_are_not_believed(auth):
    assert codes(auth=auth) == {"AUTH_RESULTS_UNTRUSTED"}


# --- sender -----------------------------------------------------------------------------------


def test_lookalike_sender_domain():
    assert "SENDER_LOOKALIKE_DOMAIN" in codes(from_="it@c0ntoso.com")


def test_internal_sender_is_not_checked_for_impersonation():
    assert codes(from_='"Contoso IT, Anna Becker" <it@contoso.com>') == set()


@pytest.mark.parametrize(
    "from_",
    [
        '"Contoso Service Desk" <desk@helpdesk.example>',
        '"Anna Becker" <anna@freemail.example>',
        '"it@contoso.com" <it@freemail.example>',
    ],
)
def test_display_name_impersonation(from_):
    assert "DISPLAY_NAME_IMPERSONATION" in codes(from_=from_)


def test_display_name_showing_the_real_address_is_fine():
    assert codes(from_='"news@shop.example" <news@shop.example>') == set()


def test_reply_to_on_another_domain():
    assert codes(headers=[("Reply-To", "pay@other.example")]) == {"REPLY_TO_MISMATCH"}


def test_reply_to_on_a_subdomain_of_the_sender_is_fine():
    assert codes(headers=[("Reply-To", "support@help.sender.example")]) == set()


# --- links ------------------------------------------------------------------------------------


def test_link_text_that_shows_a_different_domain():
    assert codes(html='<a href="https://evil.example/x">https://portal.fabrikam.example</a>') == {"LINK_TEXT_MISMATCH"}


@pytest.mark.parametrize("text", ["www.shop.example", "Click here", "shop.example/offers"])
def test_link_text_that_is_not_a_different_domain_is_fine(text):
    assert codes(html=f'<a href="https://shop.example/offers">{text}</a>') == set()


@pytest.mark.parametrize(
    ("href", "code"),
    [
        ("https://contoso.com@evil.example/", "LINK_USERINFO"),
        ("http://203.0.113.9/login", "LINK_IP_ADDRESS"),
        ("https://bit.ly/abc", "LINK_SHORTENER"),
        ("https://contoso-portal.example/", "LINK_LOOKALIKE_DOMAIN"),
    ],
)
def test_suspicious_link_destinations(href, code):
    assert code in codes(html=f'<a href="{href}">Open</a>')


def test_each_indicator_counts_once():
    findings = run_checks(
        parsed(html='<a href="http://203.0.113.9/a">a</a><a href="http://203.0.113.10/b">b</a>'), DEFAULT_CONFIG
    )
    assert [f.code for f in findings] == ["LINK_IP_ADDRESS"]


# --- attachments ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("invoice.pdf.exe", {"ATTACHMENT_DOUBLE_EXTENSION"}),
        ("Scan.PDF.html", {"ATTACHMENT_DOUBLE_EXTENSION"}),
        ("setup.exe", {"ATTACHMENT_EXECUTABLE"}),
        ("shortcut.lnk", {"ATTACHMENT_EXECUTABLE"}),
        ("disk.iso", {"ATTACHMENT_EXECUTABLE"}),
        ("budget.xlsm", {"ATTACHMENT_MACRO"}),
        ("login.htm", {"ATTACHMENT_HTML"}),
        ("logo.svg", {"ATTACHMENT_HTML"}),
        ("photo.jpg", set()),
        ("report.final.pdf", set()),
        ("README", set()),
    ],
)
def test_attachment_types(filename, expected):
    assert codes(attachments=[(filename, b"placeholder")]) == expected


def _zip(name: str, encrypted: bool = False) -> bytes:
    return zip_of({name: b"x"}, encrypted=encrypted)


def test_risky_file_inside_an_archive():
    assert codes(attachments=[("docs.zip", _zip("folder/Rechnung.lnk"))]) == {"ATTACHMENT_EXECUTABLE"}


def test_password_protected_archive():
    assert codes(attachments=[("docs.zip", _zip("notes.txt", encrypted=True))]) == {"ATTACHMENT_ENCRYPTED_ARCHIVE"}


def test_unreadable_archive():
    assert codes(attachments=[("docs.zip", b"PK\x03\x04garbage")]) == {"ATTACHMENT_BAD_ARCHIVE"}


# --- language ---------------------------------------------------------------------------------


def test_one_pressure_phrase_is_not_enough():
    assert codes(text="This is urgent, see you at 3.") == set()


@pytest.mark.parametrize(
    "text",
    [
        "Urgent: pay the overdue invoice.",
        "Dringend! Bitte sofort erledigen.",
        "Are you at your desk? Gift card needed.",
    ],
)
def test_two_pressure_phrases_in_english_or_german(text):
    assert "URGENCY_LANGUAGE" in codes(text=text)


def test_phrases_match_whole_words_only():
    assert codes(text="Our mfabric team is unconfidentially sofortig urgentish.") == set()


def test_credential_lure_needs_an_external_link():
    assert codes(text="Change your password at https://portal.contoso.com/") == set()
    assert "CREDENTIAL_LURE" in codes(text="Change your password at https://portal.example/")


# --- simulations ------------------------------------------------------------------------------

SIM_HEADER = [("X-Contoso-PhishSim", "campaign=2026-Q4-01")]


def test_approved_simulation_needs_header_and_platform_domain():
    approved = parsed(from_="desk@contoso-training.example", headers=SIM_HEADER)
    assert is_approved_simulation(approved, DEFAULT_CONFIG)
    assert "SIMULATION_HEADER_UNTRUSTED" not in {f.code for f in run_checks(approved, DEFAULT_CONFIG)}


def test_simulation_header_from_anyone_else_is_suspicious():
    forged = parsed(from_="desk@attacker.example", headers=SIM_HEADER)
    assert not is_approved_simulation(forged, DEFAULT_CONFIG)
    assert "SIMULATION_HEADER_UNTRUSTED" in {f.code for f in run_checks(forged, DEFAULT_CONFIG)}


def test_platform_domain_without_header_is_not_a_simulation():
    assert not is_approved_simulation(parsed(from_="desk@contoso-training.example"), DEFAULT_CONFIG)
