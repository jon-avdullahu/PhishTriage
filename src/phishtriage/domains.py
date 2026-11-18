"""Domain helpers: registrable domain, IP literals and look-alike detection.

There is no network access and no public-suffix download, so the registrable domain is an
approximation: the last two labels, or three for common two-part suffixes such as co.uk.
"""

from __future__ import annotations

import contextlib
import ipaddress

_TWO_PART_SUFFIXES = frozenset(
    {
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "com.au",
        "net.au",
        "org.au",
        "co.jp",
        "co.nz",
        "co.za",
        "com.br",
        "com.cn",
        "com.tr",
        "com.mx",
        "co.in",
        "co.kr",
        "com.sg",
    }
)

# Characters attackers swap in for letters that look the same. Cyrillic letters are the classic
# homograph attack; digits are the classic typo-squat.
_CONFUSABLES = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "х": "x",
        "у": "y",
        "і": "i",
        "ј": "j",
        "ѕ": "s",
        "ԁ": "d",
        "ɡ": "g",
        "0": "o",
        "1": "l",
        "3": "e",
        "5": "s",
        "7": "t",
    }
)


def normalise_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def registrable_domain(host: str) -> str:
    host = normalise_host(host)
    if not host or is_ip_address(host):
        return host
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _TWO_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _first_label(domain: str) -> str:
    return registrable_domain(domain).split(".")[0]


def decode_idna(host: str) -> str:
    """Turn xn-- labels into Unicode so homoglyphs become visible. Undecodable labels stay as they are."""
    labels = []
    for label in normalise_host(host).split("."):
        if label.startswith("xn--"):
            with contextlib.suppress(UnicodeError):
                label = label.encode("ascii").decode("idna")
        labels.append(label)
    return ".".join(labels)


def skeleton(label: str) -> str:
    """A rough 'what a human sees' form of a label: homoglyphs and rn/vv collapsed."""
    return label.lower().translate(_CONFUSABLES).replace("rn", "m").replace("vv", "w")


def edit_distance(a: str, b: str) -> int:
    """Optimal string alignment distance: insert, delete, substitute, or swap two neighbours."""
    rows = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        rows[i][0] = i
    for j in range(len(b) + 1):
        rows[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            rows[i][j] = min(rows[i - 1][j] + 1, rows[i][j - 1] + 1, rows[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                rows[i][j] = min(rows[i][j], rows[i - 2][j - 2] + 1)
    return rows[len(a)][len(b)]


def lookalike_reason(host: str, protected_domains: frozenset[str]) -> str | None:
    """Explain why `host` imitates one of our domains, or return None.

    Domains we own (including their subdomains) are never look-alikes.
    """
    host = normalise_host(host)
    if not host or is_ip_address(host):
        return None
    own = {registrable_domain(d) for d in protected_domains}
    if registrable_domain(host) in own:
        return None

    unicode_host = decode_idna(host)
    candidate = _first_label(unicode_host)
    for protected in sorted(own):
        target = _first_label(protected)
        if host.startswith(protected + "."):
            return f"starts with our domain {protected} but belongs to {registrable_domain(host)}"
        if unicode_host != host and skeleton(candidate) == skeleton(target):
            return f"uses look-alike Unicode characters to imitate {protected}"
        if candidate != target and skeleton(candidate) == skeleton(target):
            return f"swaps similar-looking characters to imitate {protected}"
        allowed = 1 if len(target) <= 5 else 2
        if 0 < edit_distance(candidate, target) <= allowed:
            return f"is a misspelling of {protected}"
        if target in candidate:
            return f"contains our name '{target}' but is not our domain"
    return None
