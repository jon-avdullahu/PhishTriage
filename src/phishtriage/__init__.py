"""PhishTriage: offline triage of user-reported phishing e-mails."""

from .config import DEFAULT_CONFIG, TriageConfig, load_config
from .mail import MailError, parse_mail
from .triage import TriageResult, triage_file, triage_mail

__all__ = [
    "DEFAULT_CONFIG",
    "MailError",
    "TriageConfig",
    "TriageResult",
    "load_config",
    "parse_mail",
    "triage_file",
    "triage_mail",
]
__version__ = "0.1.0"
