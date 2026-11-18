"""Defang indicators so they can be pasted into tickets and chats without becoming clickable."""

from __future__ import annotations

import re

_SCHEME = re.compile(r"^(http)(s?)://", re.IGNORECASE)


def defang_domain(domain: str) -> str:
    return domain.replace(".", "[.]")


def defang_url(url: str) -> str:
    match = _SCHEME.match(url)
    if not match:
        return url.replace(".", "[.]")
    rest = url[match.end() :]
    authority, sep, path = rest.partition("/")
    return f"hxxp{match.group(2).lower()}://{authority.replace('.', '[.]')}{sep}{path}"


def refang(text: str) -> str:
    """Undo defanging, e.g. to feed indicators into a block list."""
    return re.sub(r"^hxxp", "http", text.replace("[.]", "."), flags=re.IGNORECASE)
