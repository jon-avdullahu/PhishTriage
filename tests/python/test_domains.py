import pytest

from phishtriage.domains import edit_distance, is_ip_address, lookalike_reason, registrable_domain

OURS = frozenset({"contoso.com"})


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("contoso.com", "contoso.com"),
        ("mail.eu.contoso.com", "contoso.com"),
        ("Login.Contoso.COM.", "contoso.com"),
        ("shop.example.co.uk", "example.co.uk"),
        ("203.0.113.5", "203.0.113.5"),
        ("localhost", "localhost"),
    ],
)
def test_registrable_domain(host, expected):
    assert registrable_domain(host) == expected


@pytest.mark.parametrize(("host", "expected"), [("203.0.113.5", True), ("[2001:db8::1]", True), ("contoso.com", False)])
def test_is_ip_address(host, expected):
    assert is_ip_address(host) is expected


@pytest.mark.parametrize(
    ("a", "b", "distance"),
    [("contoso", "contoso", 0), ("contoso", "contosso", 1), ("contoso", "cnotoso", 1), ("", "abc", 3), ("abc", "", 3)],
)
def test_edit_distance(a, b, distance):
    assert edit_distance(a, b) == distance


@pytest.mark.parametrize(
    ("host", "reason_contains"),
    [
        ("c0ntoso.com", "similar-looking characters"),
        ("contosso.com", "misspelling"),
        ("cnotoso.net", "misspelling"),
        ("contoso-login.example", "contains our name"),
        ("contoso.com.secure-login.example", "starts with our domain"),
        ("cоntoso.com".encode("idna").decode("ascii"), "Unicode"),  # Cyrillic 'о'
    ],
)
def test_lookalikes_are_explained(host, reason_contains):
    reason = lookalike_reason(host, OURS)
    assert reason is not None
    assert reason_contains in reason


@pytest.mark.parametrize(
    "host", ["contoso.com", "mail.contoso.com", "fabrikam.com", "coffee.example", "203.0.113.5", ""]
)
def test_our_domains_and_unrelated_domains_are_not_lookalikes(host):
    assert lookalike_reason(host, OURS) is None


def test_short_names_allow_only_one_typo():
    ours = frozenset({"abcd.com"})
    assert lookalike_reason("abce.com", ours) is not None
    assert lookalike_reason("abxy.com", ours) is None
