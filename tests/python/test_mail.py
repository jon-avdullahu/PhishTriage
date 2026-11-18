import hashlib

import pytest
from conftest import build_mail, parsed, zip_of

import phishtriage.mail as mail_module
from phishtriage.mail import MailError, parse_mail


def test_reads_sender_and_lowercases_the_address():
    mail = parsed(from_='"Max Mustermann" <Max.Mustermann@Sender.Example>')
    assert mail.sender.display_name == "Max Mustermann"
    assert mail.sender.address == "max.mustermann@sender.example"
    assert mail.sender.domain == "sender.example"


def test_decodes_encoded_subjects(sample):
    assert parse_mail(sample("03-mfa-reregistration-de.eml")).subject == "Ihr Authenticator muss neu registriert werden"


def test_uses_the_topmost_authentication_results_header(sample):
    auth = parse_mail(sample("07-payroll-spoof-forged-auth.eml")).auth
    assert (auth.authserv_id, auth.spf, auth.dmarc) == ("mx.contoso.com", "fail", "fail")


def test_parses_authserv_id_with_version_number():
    auth = parsed(auth="mx.contoso.com 1; spf=softfail smtp.mailfrom=x.example; dmarc=none").auth
    assert (auth.authserv_id, auth.spf, auth.dkim, auth.dmarc) == ("mx.contoso.com", "softfail", None, "none")


def test_missing_authentication_results_is_none():
    assert parsed(auth=None).auth is None


def test_html_links_keep_their_visible_text_and_hidden_text_is_ignored():
    mail = parsed(
        html='<style>.x{}</style><script>var s = "urgent";</script>'
        '<p>Hello <a href="https://portal.example/a">Open   the portal</a></p>'
        '<a href="mailto:x@y.example">mail</a><a href="#top">top</a>'
    )
    assert [(link.url, link.text) for link in mail.links] == [("https://portal.example/a", "Open the portal")]
    assert "urgent" not in mail.text
    assert "Hello" in mail.text


def test_plain_text_urls_lose_trailing_punctuation():
    mail = parsed(text="See https://portal.example/path. Or (https://other.example/x)!")
    assert [link.url for link in mail.links] == ["https://portal.example/path", "https://other.example/x"]
    assert all(link.text is None for link in mail.links)


def test_detects_userinfo_trick_and_reads_the_real_host():
    (link,) = parsed(html='<a href="https://contoso.com@evil.example/login">x</a>').links
    assert link.has_userinfo
    assert link.host == "evil.example"


def test_a_malformed_url_is_skipped_instead_of_crashing():
    mail = parsed(html='<a href="http://[not-an-ip/">x</a><a href="https://ok.example/">y</a>')
    assert [link.host for link in mail.links] == ["ok.example"]


def test_a_url_with_an_impossible_port_is_still_shown_to_the_analyst():
    (link,) = parsed(html='<a href="http://host.example:99999999/">x</a>').links
    assert link.host == "host.example"


def test_attachments_get_a_sha256_and_zip_members_are_listed():
    data = zip_of({"invoice.pdf.js": b"x", "readme.txt": b"y"})
    (attachment,) = parsed(text="see attached", attachments=[("files.zip", data)]).attachments
    assert attachment.sha256 == hashlib.sha256(data).hexdigest()
    assert [m.name for m in attachment.archive_members] == ["invoice.pdf.js", "readme.txt"]
    assert attachment.archive_error is None


def test_encrypted_zip_members_are_flagged():
    (attachment,) = parsed(attachments=[("secret.zip", zip_of({"a.exe": b"x"}, encrypted=True))]).attachments
    assert attachment.archive_members[0].encrypted


def test_a_corrupt_zip_is_reported_not_raised():
    (attachment,) = parsed(attachments=[("broken.zip", b"PK\x03\x04 this is not really a zip")]).attachments
    assert attachment.archive_members is None
    assert "could not be read" in attachment.archive_error


def test_unknown_charset_does_not_stop_triage():
    raw = (
        b"From: a@sender.example\r\nSubject: x\r\nContent-Type: text/plain; charset=x-made-up\r\n\r\n"
        b"Please verify your password\r\n"
    )
    assert "verify your password" in parse_mail(raw).text


@pytest.mark.parametrize("raw", [b"", b"   \r\n", b"just some text, no headers at all"])
def test_rejects_files_that_are_not_mail(raw):
    with pytest.raises(MailError):
        parse_mail(raw)


def test_rejects_oversized_files(monkeypatch):
    monkeypatch.setattr(mail_module, "MAX_MESSAGE_BYTES", 100)
    with pytest.raises(MailError, match="larger than"):
        parse_mail(build_mail(text="x" * 500))
