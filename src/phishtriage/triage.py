"""Turn findings into a verdict, a list of indicators (IOCs) and the next steps for the analyst."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .checks import Finding, is_approved_simulation, run_checks
from .config import DEFAULT_CONFIG, TriageConfig
from .defang import defang_domain, defang_url
from .domains import is_ip_address, registrable_domain
from .mail import ParsedMail, parse_mail

PHISHING = "phishing"
SUSPICIOUS = "suspicious"
NO_INDICATORS = "no_indicators"
SIMULATION = "simulation"

ACTIONS: dict[str, tuple[str, ...]] = {
    PHISHING: (
        "Block the sender and the listed domains and URLs.",
        "Find and remove other copies of this message (kql/similar-messages.kql).",
        "Check who clicked (kql/clicks-on-reported-urls.kql); reset their password and revoke sessions.",
        "Thank the reporter.",
    ),
    SUSPICIOUS: (
        "Analyst review needed before blocking anything.",
        "Thank the reporter and ask them not to reply, click or open attachments until reviewed.",
    ),
    NO_INDICATORS: (
        "No automatic indicators found. This does not prove the mail is safe; an analyst should still look.",
        "Thank the reporter.",
    ),
    SIMULATION: (
        "This is an approved phishing simulation: count the report, no further action.",
        "Thank the reporter: reporting it was the right thing to do.",
    ),
}


@dataclass(frozen=True)
class TriageResult:
    file: str
    verdict: str
    score: int
    subject: str
    message_id: str
    sender: str
    sender_domain: str
    findings: tuple[Finding, ...]
    iocs: dict[str, list] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "verdict": self.verdict,
            "score": self.score,
            "subject": self.subject,
            "message_id": self.message_id,
            "sender": self.sender,
            "sender_domain": self.sender_domain,
            "findings": [{"code": f.code, "weight": f.weight, "message": f.message} for f in self.findings],
            "iocs": self.iocs,
            "actions": list(ACTIONS[self.verdict]),
        }


def decide(findings: list[Finding], simulation: bool, config: TriageConfig) -> tuple[str, int]:
    score = min(100, sum(f.weight for f in findings))
    if simulation:
        return SIMULATION, score
    if score >= config.phishing_threshold:
        return PHISHING, score
    if score >= config.suspicious_threshold:
        return SUSPICIOUS, score
    return NO_INDICATORS, score


def collect_iocs(mail: ParsedMail, config: TriageConfig) -> dict[str, list]:
    ours = {registrable_domain(d) for d in config.org_domains}
    domains: list[str] = []
    ips: list[str] = []
    for host in [mail.sender.domain, *(r.domain for r in mail.reply_to), *(lnk.host for lnk in mail.links)]:
        if not host or registrable_domain(host) in ours:
            continue
        bucket = ips if is_ip_address(host) else domains
        if defang_domain(host) not in bucket:
            bucket.append(defang_domain(host))
    urls = list(dict.fromkeys(defang_url(lnk.url) for lnk in mail.links if registrable_domain(lnk.host) not in ours))
    files = [{"filename": a.filename, "sha256": a.sha256} for a in mail.attachments]
    return {"domains": domains, "ips": ips, "urls": urls, "attachments": files}


def triage_mail(mail: ParsedMail, config: TriageConfig = DEFAULT_CONFIG, file: str = "") -> TriageResult:
    findings = run_checks(mail, config)
    verdict, score = decide(findings, is_approved_simulation(mail, config), config)
    return TriageResult(
        file=file,
        verdict=verdict,
        score=score,
        subject=mail.subject,
        message_id=mail.message_id,
        sender=str(mail.sender),
        sender_domain=mail.sender.domain,
        findings=tuple(findings),
        iocs=collect_iocs(mail, config),
    )


def triage_file(path: str | Path, config: TriageConfig = DEFAULT_CONFIG) -> TriageResult:
    path = Path(path)
    return triage_mail(parse_mail(path.read_bytes()), config, file=path.name)
