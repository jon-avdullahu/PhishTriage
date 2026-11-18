"""Triage configuration: which domains are ours, which mail servers we trust, and so on.

The defaults describe the fictional company Contoso so the samples and tests work out of the box.
A real deployment passes its own JSON file (see config/triage.json).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

DEFAULT_SHORTENERS = (
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at",
)


class ConfigError(ValueError):
    """The configuration file is missing a value or contains a value that cannot work."""


@dataclass(frozen=True)
class TriageConfig:
    org_domains: frozenset[str]
    """Domains the organisation owns. Mail from these is internal; look-alikes of these are suspicious."""
    org_names: tuple[str, ...]
    """Company names that attackers put into display names ("Contoso IT Service Desk")."""
    vip_names: tuple[str, ...]
    """People who are impersonated often (executives, finance). Matched against display names."""
    trusted_authserv_ids: frozenset[str]
    """Our own mail gateways. Only their Authentication-Results header is believed."""
    shortener_domains: frozenset[str]
    simulation_headers: tuple[str, ...]
    """Headers our phishing-simulation platform adds to its test mails."""
    simulation_sender_domains: frozenset[str]
    """Sending domains of the approved simulation platform. Header and domain must both match."""
    phishing_threshold: int = 60
    suspicious_threshold: int = 25


DEFAULT_CONFIG = TriageConfig(
    org_domains=frozenset({"contoso.com"}),
    org_names=("Contoso",),
    vip_names=("Anna Becker",),
    trusted_authserv_ids=frozenset({"mx.contoso.com"}),
    shortener_domains=frozenset(DEFAULT_SHORTENERS),
    simulation_headers=("X-Contoso-PhishSim",),
    simulation_sender_domains=frozenset({"contoso-training.example"}),
)

_LIST_KEYS = {
    "org_domains",
    "org_names",
    "vip_names",
    "trusted_authserv_ids",
    "shortener_domains",
    "simulation_headers",
    "simulation_sender_domains",
}
_INT_KEYS = {"phishing_threshold", "suspicious_threshold"}
_LOWERCASE_KEYS = {"org_domains", "trusted_authserv_ids", "shortener_domains", "simulation_sender_domains"}


def load_config(path: str | Path) -> TriageConfig:
    """Read a JSON config. Unknown keys are an error, so a typo cannot silently disable a check."""
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"config file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"config file is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError("config file must contain a JSON object")

    unknown = set(raw) - _LIST_KEYS - _INT_KEYS
    if unknown:
        raise ConfigError(f"unknown config keys: {', '.join(sorted(unknown))}")
    missing = {"org_domains", "trusted_authserv_ids"} - set(raw)
    if missing:
        raise ConfigError(f"missing required config keys: {', '.join(sorted(missing))}")

    values: dict[str, object] = {}
    for key in _LIST_KEYS & set(raw):
        items = raw[key]
        if not isinstance(items, list) or not all(isinstance(i, str) and i.strip() for i in items):
            raise ConfigError(f"'{key}' must be a list of non-empty strings")
        cleaned = [i.strip().lower() if key in _LOWERCASE_KEYS else i.strip() for i in items]
        values[key] = frozenset(cleaned) if key in _LOWERCASE_KEYS else tuple(cleaned)
    for key in _INT_KEYS & set(raw):
        if not isinstance(raw[key], int) or isinstance(raw[key], bool):
            raise ConfigError(f"'{key}' must be a whole number")
        values[key] = raw[key]

    if not values["org_domains"]:
        raise ConfigError("'org_domains' must list at least one domain")

    defaults = {
        "org_names": (),
        "vip_names": (),
        "shortener_domains": frozenset(DEFAULT_SHORTENERS),
        "simulation_headers": (),
        "simulation_sender_domains": frozenset(),
    }
    config = TriageConfig(**{**defaults, **values})  # type: ignore[arg-type]
    if not 0 < config.suspicious_threshold < config.phishing_threshold <= 100:
        raise ConfigError("thresholds must satisfy 0 < suspicious_threshold < phishing_threshold <= 100")
    return config
