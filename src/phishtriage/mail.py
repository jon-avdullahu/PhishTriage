"""Parse a reported e-mail (.eml) into the facts the checks need.

Nothing here opens a link, runs an attachment or extracts an archive. Archives are only listed.
"""

from __future__ import annotations

import hashlib
import io
import re
import zipfile
from dataclasses import dataclass
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from urllib.parse import urlsplit

MAX_MESSAGE_BYTES = 25 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 500

_URL_IN_TEXT = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
_AUTH_METHOD = re.compile(r"(?:^|;)\s*(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)


class MailError(ValueError):
    """The file cannot be triaged (empty, too large, not an e-mail)."""


@dataclass(frozen=True)
class Address:
    display_name: str
    address: str

    @property
    def domain(self) -> str:
        return self.address.rpartition("@")[2].lower() if "@" in self.address else ""

    def __str__(self) -> str:
        return f'"{self.display_name}" <{self.address}>' if self.display_name else f"<{self.address}>"


@dataclass(frozen=True)
class AuthResults:
    authserv_id: str
    spf: str | None
    dkim: str | None
    dmarc: str | None


@dataclass(frozen=True)
class Link:
    url: str
    text: str | None
    """Visible anchor text for HTML links; None for URLs written out in plain text."""
    host: str
    has_userinfo: bool
    """True for URLs like https://contoso.com@evil.example/, where the real host is after the @."""


@dataclass(frozen=True)
class ArchiveMember:
    name: str
    encrypted: bool


@dataclass(frozen=True)
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    archive_members: tuple[ArchiveMember, ...] | None = None
    archive_error: str | None = None


@dataclass(frozen=True)
class ParsedMail:
    subject: str
    message_id: str
    sender: Address
    reply_to: tuple[Address, ...]
    auth: AuthResults | None
    """The top-most Authentication-Results header, i.e. the one our own gateway added last."""
    headers: dict[str, str]
    """First value of every header, keyed by lower-case name."""
    text: str
    """Visible text of all text parts, HTML tags removed."""
    links: tuple[Link, ...]
    attachments: tuple[Attachment, ...]


class _HtmlScanner(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: list[tuple[str, str]] = []
        self.text: list[str] = []
        self._href: str | None = None
        self._anchor_text: list[str] = []
        self._hidden_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("script", "style", "head"):
            self._hidden_depth += 1
        elif tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._anchor_text = []
        elif tag in ("br", "p", "div", "tr", "li"):
            self.text.append(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style", "head"):
            self._hidden_depth = max(0, self._hidden_depth - 1)
        elif tag == "a" and self._href is not None:
            self.anchors.append((self._href, " ".join("".join(self._anchor_text).split())))
            self._href = None

    def handle_data(self, data: str) -> None:
        if self._hidden_depth:
            return
        self.text.append(data)
        if self._href is not None:
            self._anchor_text.append(data)


def _header(msg: Message, name: str) -> str:
    try:
        value = msg.get(name)
    except Exception:  # malformed headers must not stop the triage of the rest
        return ""
    return " ".join(str(value).split()) if value is not None else ""


def _parse_auth(value: str) -> AuthResults:
    authserv_id, _, rest = value.partition(";")
    tokens = authserv_id.split()
    results: dict[str, str] = {}
    for method, result in _AUTH_METHOD.findall(";" + rest):
        results.setdefault(method.lower(), result.lower())
    return AuthResults(
        authserv_id=tokens[0].lower() if tokens else "",
        spf=results.get("spf"),
        dkim=results.get("dkim"),
        dmarc=results.get("dmarc"),
    )


def _make_link(url: str, text: str | None) -> Link | None:
    url = url.strip()
    try:
        parts = urlsplit(url)
        if parts.scheme.lower() not in ("http", "https"):
            return None
        host = parts.hostname or ""
    except ValueError:
        return None
    return Link(url=url, text=text, host=host.lower(), has_userinfo="@" in parts.netloc)


def _part_text(part: Message) -> str:
    try:
        content = part.get_content()  # type: ignore[attr-defined]
    except (LookupError, UnicodeError, AttributeError):
        payload = part.get_payload(decode=True) or b""
        content = payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else str(payload)
    return content if isinstance(content, str) else ""


def _list_archive(data: bytes) -> tuple[tuple[ArchiveMember, ...] | None, str | None]:
    """List a zip's member names without extracting anything."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()[:MAX_ARCHIVE_MEMBERS]
            return tuple(ArchiveMember(i.filename, bool(i.flag_bits & 0x1)) for i in infos), None
    except (zipfile.BadZipFile, EOFError, ValueError) as exc:
        return None, f"archive could not be read: {exc}"


def _attachment(part: Message) -> Attachment:
    payload = part.get_payload(decode=True)
    data = payload if isinstance(payload, bytes) else b""
    filename = part.get_filename() or "(no name)"
    members = error = None
    if filename.lower().endswith(".zip") or data[:4] == b"PK\x03\x04":
        members, error = _list_archive(data)
    return Attachment(
        filename=filename,
        content_type=part.get_content_type(),
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        archive_members=members,
        archive_error=error,
    )


def parse_mail(data: bytes) -> ParsedMail:
    if not data.strip():
        raise MailError("the file is empty")
    if len(data) > MAX_MESSAGE_BYTES:
        raise MailError(f"the file is larger than {MAX_MESSAGE_BYTES // (1024 * 1024)} MB")

    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(data)  # type: ignore[assignment]
    if not any(msg.get(h) for h in ("From", "Subject", "Message-ID", "Date")):
        raise MailError("the file does not look like an e-mail (no From, Subject, Message-ID or Date header)")

    name, address = parseaddr(_header(msg, "From"))
    sender = Address(name.strip(), address.strip().lower())
    reply_to = tuple(Address(n.strip(), a.strip().lower()) for n, a in getaddresses([_header(msg, "Reply-To")]) if a)

    auth_headers = msg.get_all("Authentication-Results") or []
    auth = _parse_auth(" ".join(str(auth_headers[0]).split())) if auth_headers else None

    headers: dict[str, str] = {}
    for key in msg:
        headers.setdefault(key.lower(), _header(msg, key))

    texts: list[str] = []
    links: list[Link] = []
    attachments: list[Attachment] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        if part.get_content_disposition() == "attachment" or (
            part.get_filename() and part.get_content_maintype() != "text"
        ):
            attachments.append(_attachment(part))
            continue
        ctype = part.get_content_type()
        if ctype == "text/html":
            scanner = _HtmlScanner()
            scanner.feed(_part_text(part))
            scanner.close()
            texts.append("".join(scanner.text))
            links.extend(filter(None, (_make_link(href, text) for href, text in scanner.anchors)))
        elif ctype == "text/plain":
            body = _part_text(part)
            texts.append(body)
            links.extend(filter(None, (_make_link(u.rstrip(".,;:!?"), None) for u in _URL_IN_TEXT.findall(body))))

    unique_links = tuple(dict.fromkeys(links))
    return ParsedMail(
        subject=_header(msg, "Subject"),
        message_id=_header(msg, "Message-ID"),
        sender=sender,
        reply_to=reply_to,
        auth=auth,
        headers=headers,
        text=" ".join(" ".join(texts).split()),
        links=unique_links,
        attachments=tuple(attachments),
    )
