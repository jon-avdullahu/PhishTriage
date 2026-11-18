"""Generate the sample reported e-mails in samples/mail/.

All samples are synthetic. They use the fictional company Contoso, reserved .example domains and
documentation IP ranges (RFC 5737), so no link in them leads anywhere real. Attachments are short
text placeholders, not malware. Output is deterministic: running this twice gives identical files.

    python tools/make_samples.py
"""

from __future__ import annotations

import base64
import io
import zipfile
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "samples" / "mail"
DATE = "Mon, 16 Nov 2026 08:12:00 +0100"
RECEIVED = "Received: from {host} ({host} [{ip}]) by mx.contoso.com with ESMTPS; " + DATE


def auth(spf: str, dkim: str, dmarc: str, domain: str, server: str = "mx.contoso.com") -> str:
    return (
        f"Authentication-Results: {server}; spf={spf} smtp.mailfrom={domain}; "
        f"dkim={dkim} header.d={domain}; dmarc={dmarc} header.from={domain}"
    )


def headers(*lines: str) -> str:
    return "\r\n".join(lines)


def alternative(plain: str, html: str, boundary: str = "alt-0001") -> str:
    return (
        f'Content-Type: multipart/alternative; boundary="{boundary}"\r\n\r\n'
        f"--{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n"
        f"{plain}\r\n"
        f"--{boundary}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n"
        f"{html}\r\n"
        f"--{boundary}--\r\n"
    )


def b64(data: bytes) -> str:
    return base64.encodebytes(data).decode("ascii").replace("\n", "\r\n")


def zip_bytes(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            info = zipfile.ZipInfo(name, date_time=(2026, 11, 16, 8, 0, 0))
            # zipfile records the OS it runs on (0 = Windows, 3 = Unix) in the "made by" field.
            # Pin it so the generated sample is byte-identical on every platform.
            info.create_system = 0
            archive.writestr(info, data)
    return buffer.getvalue()


SAMPLES: dict[str, str] = {}

SAMPLES["01-internal-newsletter.eml"] = headers(
    auth("pass", "pass", "pass", "contoso.com"),
    RECEIVED.format(host="mail.contoso.com", ip="198.51.100.10"),
    'From: "Contoso Communications" <comms@contoso.com>',
    "To: max.mustermann@contoso.com",
    "Subject: Weekly update: canteen hours and new coffee machines",
    f"Date: {DATE}",
    "Message-ID: <newsletter-2026-47@contoso.com>",
    "MIME-Version: 1.0",
    alternative(
        "This week: new coffee machines on floor 3, and the canteen closes early on Friday.\r\n"
        "Read the full update: https://intranet.contoso.com/news/2026-47",
        "<p>This week: new coffee machines on floor 3, and the canteen closes early on Friday.</p>"
        '<p><a href="https://intranet.contoso.com/news/2026-47">Read the full update</a> on '
        '<a href="https://intranet.contoso.com/">intranet.contoso.com</a>.</p>',
    ),
)

SAMPLES["02-password-expiry-lookalike.eml"] = headers(
    "Authentication-Results: mx.contoso.com; spf=pass smtp.mailfrom=c0ntoso.com; dkim=none; dmarc=none",
    RECEIVED.format(host="smtp.c0ntoso.com", ip="203.0.113.21"),
    'From: "Contoso IT Service Desk" <it-support@c0ntoso.com>',
    "To: max.mustermann@contoso.com",
    "Subject: Action required: your password expires today",
    f"Date: {DATE}",
    "Message-ID: <a81f3c@c0ntoso.com>",
    "MIME-Version: 1.0",
    alternative(
        "Your Contoso password expires today. Verify your account immediately at https://login.contoso.com.",
        "<p>Your Contoso password expires today. To keep access to e-mail, verify your account "
        'immediately: <a href="https://contoso-sso.example/owa/login">https://login.contoso.com</a></p>'
        "<p>If you do not act within 24 hours your account will be suspended.</p>",
        boundary="alt-0002",
    ),
)

SAMPLES["03-mfa-reregistration-de.eml"] = headers(
    "Authentication-Results: mx.contoso.com; spf=softfail smtp.mailfrom=secure-mfa-alerts.example; dkim=none; "
    "dmarc=none",
    RECEIVED.format(host="vps-4471.example", ip="203.0.113.45"),
    'From: "M365 Sicherheitsteam" <no-reply@secure-mfa-alerts.example>',
    "To: max.mustermann@contoso.com",
    "Subject: =?utf-8?q?Ihr_Authenticator_muss_neu_registriert_werden?=",
    f"Date: {DATE}",
    "Message-ID: <mfa-77120@secure-mfa-alerts.example>",
    "MIME-Version: 1.0",
    "Content-Type: text/html; charset=utf-8",
    "Content-Transfer-Encoding: 8bit",
    "",
    "<p>Hallo,</p><p>Ihr Authenticator muss <b>dringend</b> neu registriert werden. Andernfalls wird Ihr "
    "Konto gesperrt.</p><p>Bitte melden Sie sich sofort hier an: "
    '<a href="http://203.0.113.45/mfa/register">https://aka.contoso.com/mfa</a></p><p>Ihr IT-Team</p>',
)

_zip = zip_bytes({"Rechnung_2026-11.pdf.js": b"// Placeholder for tests. Not malware; never executed.\n"})
SAMPLES["04-invoice-attachments.eml"] = headers(
    auth("pass", "pass", "pass", "fabrikam-billing.example"),
    RECEIVED.format(host="out.fabrikam-billing.example", ip="198.51.100.77"),
    'From: "Fabrikam Accounts" <accounts@fabrikam-billing.example>',
    "Reply-To: payments@transfer-desk.example",
    "To: max.mustermann@contoso.com",
    "Subject: Rechnung November 2026 / Invoice 4471",
    f"Date: {DATE}",
    "Message-ID: <inv-4471@fabrikam-billing.example>",
    "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="mix-0004"',
    "",
    "--mix-0004",
    "Content-Type: text/plain; charset=utf-8",
    "Content-Transfer-Encoding: 8bit",
    "",
    "Please find invoice 4471 attached. Payment is overdue, please pay immediately.",
    "Bitte begleichen Sie die Rechnung sofort.",
    "--mix-0004",
    'Content-Type: application/zip; name="Rechnung_2026-11.zip"',
    'Content-Disposition: attachment; filename="Rechnung_2026-11.zip"',
    "Content-Transfer-Encoding: base64",
    "",
    b64(_zip),
    "--mix-0004",
    'Content-Type: application/vnd.ms-excel.sheet.macroEnabled.12; name="Invoice_4471.xlsm"',
    'Content-Disposition: attachment; filename="Invoice_4471.xlsm"',
    "Content-Transfer-Encoding: base64",
    "",
    b64(b"Placeholder for tests, not a real workbook.\n"),
    "--mix-0004--",
    "",
)

SAMPLES["05-ceo-gift-cards.eml"] = headers(
    auth("pass", "pass", "pass", "mailbox-direct.example"),
    RECEIVED.format(host="mx.mailbox-direct.example", ip="198.51.100.140"),
    'From: "Anna Becker" <anna.becker.office@mailbox-direct.example>',
    "Reply-To: anna.becker.private@other-mail.example",
    "To: max.mustermann@contoso.com",
    "Subject: Quick favour",
    f"Date: {DATE}",
    "Message-ID: <q-9921@mailbox-direct.example>",
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
    "",
    "Hi, are you at your desk? I need you to buy gift cards for a client today.",
    "Please keep this confidential, I am in meetings all day.",
    "Anna",
    "",
)

SAMPLES["06-phishing-simulation.eml"] = headers(
    auth("pass", "pass", "pass", "contoso-training.example"),
    RECEIVED.format(host="send.contoso-training.example", ip="198.51.100.200"),
    'From: "IT Service Desk" <servicedesk@contoso-training.example>',
    "To: max.mustermann@contoso.com",
    "Subject: Your mailbox is almost full",
    f"Date: {DATE}",
    "Message-ID: <sim-2026-q4-01-0042@contoso-training.example>",
    "X-Contoso-PhishSim: campaign=2026-Q4-01",
    "MIME-Version: 1.0",
    "Content-Type: text/html; charset=utf-8",
    "",
    '<p>Your mailbox is almost full. <a href="https://contoso-training.example/c/8f2a">Review your mailbox '
    "settings</a> to keep receiving mail.</p>",
)

SAMPLES["07-payroll-spoof-forged-auth.eml"] = headers(
    auth("fail", "none", "fail", "contoso.com"),
    "Received: from unknown (HELO bulk-sender.example) (192.0.2.80) by mx.contoso.com with SMTP; " + DATE,
    # The next header was written by the attacker, below our gateway's own header. It must be ignored.
    auth("pass", "pass", "pass", "contoso.com"),
    'From: "Contoso Payroll" <payroll@contoso.com>',
    "To: max.mustermann@contoso.com",
    "Subject: =?utf-8?q?Gehaltsabrechnung_November_=E2=80=93_bitte_best=C3=A4tigen?=",
    f"Date: {DATE}",
    "Message-ID: <p-11@bulk-sender.example>",
    "MIME-Version: 1.0",
    "Content-Type: text/html; charset=utf-8",
    "Content-Transfer-Encoding: 8bit",
    "",
    "<p>Ihre Gehaltsabrechnung für November liegt bereit. Bitte bestätigen Sie Ihre Bankverbindung "
    "innerhalb von 24 Stunden, sonst verzögert sich die Zahlung.</p>"
    '<p><a href="https://bit.ly/example-sample">Gehaltsabrechnung öffnen</a></p>',
)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, content in SAMPLES.items():
        (OUT / name).write_bytes(content.encode("utf-8"))
    print(f"wrote {len(SAMPLES)} samples to {OUT}")


if __name__ == "__main__":
    main()
