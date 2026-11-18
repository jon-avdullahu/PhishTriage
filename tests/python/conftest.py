from __future__ import annotations

import io
import zipfile
from email.message import EmailMessage
from pathlib import Path

import pytest

from phishtriage.mail import ParsedMail, parse_mail

ROOT = Path(__file__).resolve().parents[2]
SAMPLES = ROOT / "samples" / "mail"
TRUSTED_PASS = "mx.contoso.com; spf=pass smtp.mailfrom=sender.example; dkim=pass; dmarc=pass"


def build_mail(
    *,
    from_: str = '"Sender" <someone@sender.example>',
    subject: str = "Hello",
    text: str | None = None,
    html: str | None = None,
    auth: str | None = TRUSTED_PASS,
    headers: list[tuple[str, str]] | None = None,
    attachments: list[tuple[str, bytes]] | None = None,
) -> bytes:
    msg = EmailMessage()
    if auth is not None:
        msg["Authentication-Results"] = auth
    msg["From"] = from_
    msg["To"] = "max.mustermann@contoso.com"
    msg["Subject"] = subject
    msg["Date"] = "Mon, 16 Nov 2026 08:12:00 +0100"
    msg["Message-ID"] = "<test@sender.example>"
    for name, value in headers or []:
        msg[name] = value
    if text is not None:
        msg.set_content(text)
        if html is not None:
            msg.add_alternative(html, subtype="html")
    elif html is not None:
        msg.set_content(html, subtype="html")
    else:
        msg.set_content("")
    for filename, data in attachments or []:
        msg.add_attachment(data, maintype="application", subtype="octet-stream", filename=filename)
    return msg.as_bytes()


def parsed(**kwargs) -> ParsedMail:
    return parse_mail(build_mail(**kwargs))


@pytest.fixture
def sample():
    return lambda name: (SAMPLES / name).read_bytes()


def zip_of(members: dict[str, bytes], encrypted: bool = False) -> bytes:
    """Build a zip in memory. With encrypted=True the 'encrypted' flag is set on every entry.

    zipfile cannot write encrypted archives (and clears the flag on write), so the flag bit is
    patched into the local and central directory headers afterwards. Only the flag matters here.
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    raw = bytearray(buffer.getvalue())
    if encrypted:
        for signature, flag_offset in ((b"PK", 6), (b"PK", 8)):
            start = raw.find(signature)
            while start != -1:
                raw[start + flag_offset] |= 0x1
                start = raw.find(signature, start + 4)
    return bytes(raw)
