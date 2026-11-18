"""Phishing indicators. Each check looks at one thing and explains what it found.

Weights are deliberately simple and documented in the README. Every indicator code counts once,
so ten bad links do not outweigh one failed DMARC check.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from .config import TriageConfig
from .domains import is_ip_address, lookalike_reason, registrable_domain
from .mail import Attachment, ParsedMail

WEIGHTS: dict[str, int] = {
    "AUTH_DMARC_FAIL": 40,
    "AUTH_SPF_FAIL": 15,
    "AUTH_SPF_SOFTFAIL": 10,
    "AUTH_DKIM_FAIL": 10,
    "AUTH_RESULTS_UNTRUSTED": 10,
    "SENDER_LOOKALIKE_DOMAIN": 35,
    "DISPLAY_NAME_IMPERSONATION": 25,
    "REPLY_TO_MISMATCH": 15,
    "LINK_TEXT_MISMATCH": 30,
    "LINK_LOOKALIKE_DOMAIN": 35,
    "LINK_USERINFO": 30,
    "LINK_IP_ADDRESS": 20,
    "LINK_SHORTENER": 10,
    "ATTACHMENT_EXECUTABLE": 45,
    "ATTACHMENT_DOUBLE_EXTENSION": 45,
    "ATTACHMENT_MACRO": 30,
    "ATTACHMENT_HTML": 30,
    "ATTACHMENT_ENCRYPTED_ARCHIVE": 20,
    "ATTACHMENT_BAD_ARCHIVE": 15,
    "URGENCY_LANGUAGE": 10,
    "CREDENTIAL_LURE": 15,
    "SIMULATION_HEADER_UNTRUSTED": 30,
}

EXECUTABLE_EXTENSIONS = frozenset(
    "exe scr com pif bat cmd js jse vbs vbe wsf wsh hta lnk msi ps1 jar iso img vhd vhdx one cpl reg".split()
)
MACRO_EXTENSIONS = frozenset("docm dotm xlsm xltm xlam pptm potm ppam".split())
HTML_EXTENSIONS = frozenset("html htm shtml xhtml svg".split())
DECOY_EXTENSIONS = frozenset("pdf doc docx xls xlsx ppt pptx txt jpg jpeg png gif csv rtf".split())

# English and German, because reported mail at a German company arrives in both.
URGENCY_PHRASES = (
    "urgent",
    "immediately",
    "within 24 hours",
    "account will be suspended",
    "overdue",
    "final notice",
    "are you at your desk",
    "gift card",
    "confidential",
    "wire transfer",
    "dringend",
    "sofort",
    "innerhalb von 24 stunden",
    "konto gesperrt",
    "letzte mahnung",
    "überfällig",
    "vertraulich",
    "gutschein",
    "überweisung",
)
CREDENTIAL_PHRASES = (
    "password",
    "verify your account",
    "sign in",
    "log in",
    "login",
    "authenticator",
    "multi-factor",
    "mfa",
    "bank details",
    "passwort",
    "kennwort",
    "anmelden",
    "konto bestätigen",
    "bankverbindung",
    "zugangsdaten",
)
_EMAIL_IN_TEXT = re.compile(r"[\w.+-]+@((?:[\w-]+\.)+[\w-]+)")
_DOMAIN_LIKE = re.compile(r"^(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]\S*)?$", re.IGNORECASE)


@dataclass(frozen=True)
class Finding:
    code: str
    weight: int
    message: str


def _finding(code: str, message: str) -> Finding:
    return Finding(code, WEIGHTS[code], message)


def _is_ours(domain: str, config: TriageConfig) -> bool:
    return registrable_domain(domain) in {registrable_domain(d) for d in config.org_domains}


def _phrases_in(text: str, phrases: Iterable[str]) -> list[str]:
    lowered = text.lower()
    return [p for p in phrases if re.search(rf"(?<!\w){re.escape(p)}(?!\w)", lowered)]


def is_approved_simulation(mail: ParsedMail, config: TriageConfig) -> bool:
    """An approved simulation needs the platform's header *and* its sending domain.

    Checking the header alone would let any attacker add it to skip triage.
    """
    has_header = any(h.lower() in mail.headers for h in config.simulation_headers)
    return has_header and registrable_domain(mail.sender.domain) in {
        registrable_domain(d) for d in config.simulation_sender_domains
    }


def check_authentication(mail: ParsedMail, config: TriageConfig) -> Iterator[Finding]:
    auth = mail.auth
    if auth is None or auth.authserv_id not in config.trusted_authserv_ids:
        seen = f"from '{auth.authserv_id}'" if auth else "at all"
        yield _finding(
            "AUTH_RESULTS_UNTRUSTED",
            f"no Authentication-Results header from our own gateway (found {seen}); SPF/DKIM/DMARC unknown",
        )
        return
    if auth.dmarc == "fail":
        yield _finding("AUTH_DMARC_FAIL", f"DMARC failed: the sender is not allowed to send as {mail.sender.domain}")
    if auth.spf == "fail":
        yield _finding("AUTH_SPF_FAIL", "SPF failed: the sending server is not authorised for this domain")
    elif auth.spf == "softfail":
        yield _finding("AUTH_SPF_SOFTFAIL", "SPF soft-failed: the sending server is probably not authorised")
    if auth.dkim == "fail":
        yield _finding("AUTH_DKIM_FAIL", "DKIM failed: the signature does not match, the message may be altered")


def check_sender(mail: ParsedMail, config: TriageConfig) -> Iterator[Finding]:
    domain = mail.sender.domain
    if domain and not _is_ours(domain, config):
        reason = lookalike_reason(domain, config.org_domains)
        if reason:
            yield _finding("SENDER_LOOKALIKE_DOMAIN", f"sender domain {domain} {reason}")

        name = mail.sender.display_name
        vips = [n for n in config.vip_names if n.lower() in name.lower()]
        orgs = [n for n in config.org_names if n.lower() in name.lower()]
        shown = _EMAIL_IN_TEXT.search(name)
        if vips:
            yield _finding(
                "DISPLAY_NAME_IMPERSONATION",
                f"display name '{name}' matches the protected person '{vips[0]}' but the mail comes from outside "
                f"({domain})",
            )
        elif orgs:
            yield _finding(
                "DISPLAY_NAME_IMPERSONATION",
                f"display name '{name}' uses our name '{orgs[0]}' but the mail comes from outside ({domain})",
            )
        elif shown and registrable_domain(shown.group(1)) != registrable_domain(domain):
            yield _finding(
                "DISPLAY_NAME_IMPERSONATION",
                f"display name shows the address {shown.group(0)} but the mail comes from {domain}",
            )

    for reply in mail.reply_to:
        if domain and reply.domain and registrable_domain(reply.domain) != registrable_domain(domain):
            yield _finding("REPLY_TO_MISMATCH", f"replies go to {reply.address}, not to the sender's domain {domain}")
            break


def check_links(mail: ParsedMail, config: TriageConfig) -> Iterator[Finding]:
    for link in mail.links:
        host = link.host
        if link.has_userinfo:
            yield _finding("LINK_USERINFO", f"link {link.url} hides its real destination {host} behind an @")
        if is_ip_address(host):
            yield _finding("LINK_IP_ADDRESS", f"link points to a bare IP address: {link.url}")
        elif registrable_domain(host) in config.shortener_domains:
            yield _finding("LINK_SHORTENER", f"link uses a URL shortener that hides the destination: {link.url}")
        else:
            reason = lookalike_reason(host, config.org_domains)
            if reason:
                yield _finding("LINK_LOOKALIKE_DOMAIN", f"link domain {host} {reason}")
        if link.text:
            shown = _DOMAIN_LIKE.match(link.text.strip())
            if shown and registrable_domain(shown.group(1)) != registrable_domain(host):
                yield _finding(
                    "LINK_TEXT_MISMATCH",
                    f"link text shows {link.text.strip()} but the link goes to {host}",
                )


def _extension_findings(name: str, where: str) -> Iterator[Finding]:
    parts = name.lower().rsplit("/", 1)[-1].split(".")
    if len(parts) < 2:
        return
    ext = parts[-1]
    if (
        len(parts) >= 3
        and parts[-2] in DECOY_EXTENSIONS
        and (ext in EXECUTABLE_EXTENSIONS or ext in MACRO_EXTENSIONS or ext in HTML_EXTENSIONS)
    ):
        yield _finding("ATTACHMENT_DOUBLE_EXTENSION", f"{where}{name} pretends to be a .{parts[-2]} but is a .{ext}")
    elif ext in EXECUTABLE_EXTENSIONS:
        yield _finding("ATTACHMENT_EXECUTABLE", f"{where}{name} is a file type that runs code (.{ext})")
    elif ext in MACRO_EXTENSIONS:
        yield _finding("ATTACHMENT_MACRO", f"{where}{name} is an Office file that can contain macros (.{ext})")
    elif ext in HTML_EXTENSIONS:
        yield _finding(
            "ATTACHMENT_HTML", f"{where}{name} is an HTML/SVG file, often used for fake login pages (.{ext})"
        )


def _check_attachment(attachment: Attachment) -> Iterator[Finding]:
    yield from _extension_findings(attachment.filename, "")
    if attachment.archive_error:
        yield _finding("ATTACHMENT_BAD_ARCHIVE", f"{attachment.filename}: {attachment.archive_error}")
    for member in attachment.archive_members or ():
        if member.encrypted:
            yield _finding(
                "ATTACHMENT_ENCRYPTED_ARCHIVE",
                f"{attachment.filename} is password-protected, so mail scanners cannot look inside",
            )
        yield from _extension_findings(member.name, f"inside {attachment.filename}: ")


def check_attachments(mail: ParsedMail, config: TriageConfig) -> Iterator[Finding]:
    for attachment in mail.attachments:
        yield from _check_attachment(attachment)


def check_language(mail: ParsedMail, config: TriageConfig) -> Iterator[Finding]:
    urgency = _phrases_in(mail.text, URGENCY_PHRASES)
    if len(urgency) >= 2:
        yield _finding("URGENCY_LANGUAGE", f"pressure wording: {', '.join(urgency)}")
    external_links = [lnk for lnk in mail.links if not _is_ours(lnk.host, config)]
    lures = _phrases_in(mail.text, CREDENTIAL_PHRASES)
    if lures and external_links:
        yield _finding(
            "CREDENTIAL_LURE",
            f"asks about {', '.join(lures[:3])} and links outside the company ({external_links[0].host})",
        )


def check_simulation_header(mail: ParsedMail, config: TriageConfig) -> Iterator[Finding]:
    present = [h for h in config.simulation_headers if h.lower() in mail.headers]
    if present and not is_approved_simulation(mail, config):
        yield _finding(
            "SIMULATION_HEADER_UNTRUSTED",
            f"carries the simulation header {present[0]} but was not sent by the simulation platform",
        )


CHECKS = (
    check_authentication,
    check_sender,
    check_links,
    check_attachments,
    check_language,
    check_simulation_header,
)


def run_checks(mail: ParsedMail, config: TriageConfig) -> list[Finding]:
    """Run every check and keep the first finding per code, in check order."""
    findings: dict[str, Finding] = {}
    for check in CHECKS:
        for finding in check(mail, config):
            findings.setdefault(finding.code, finding)
    return list(findings.values())
