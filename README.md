# PhishTriage

[![CI](https://github.com/jon-avdullahu/phishtriage/actions/workflows/ci.yml/badge.svg)](https://github.com/jon-avdullahu/phishtriage/actions/workflows/ci.yml)

Tooling for the daily work of a small security operations team: **triage e-mails that users report as
phishing**, find the other copies and the people who clicked (**KQL** for Microsoft Defender XDR and Sentinel),
and turn simulation and vulnerability data into **KPI reports** (**PowerShell**).

| Part | Language | What it does |
|---|---|---|
| `src/phishtriage` | Python | Reads a reported `.eml` and explains why it looks like phishing: SPF/DKIM/DMARC, look-alike domains, display-name and reply-to tricks, link text that lies, risky attachments (also inside zips), pressure wording in English and German. Returns a verdict, defanged indicators and next steps. |
| `powershell/PhishTriage` | PowerShell 5.1 / 7 | `Invoke-PhishTriage`, `Get-TriageSummary`, `Get-AwarenessKpi` (phishing-simulation click and report rates), `Get-VulnerabilityKpi` (open and overdue findings against SLA, per severity and site), `Export-SecurityReport` (HTML). |
| `kql/` | KQL | Six hunting queries: other copies of a reported mail, who clicked, look-alike sender domains, risky attachments that were delivered, MFA fatigue, vulnerability status. |
| `docs/runbook-reported-phishing.md` | | The process around it: collect, triage, scope, contain, close, with reply templates in English and German. |

Everything works **offline**. The triage never opens a link, runs an attachment or unpacks an archive.

## Example

```text
$ python -m phishtriage analyze samples/mail/02-password-expiry-lookalike.eml

[PHISHING 100] 02-password-expiry-lookalike.eml
  Subject: Action required: your password expires today
  From:    "Contoso IT Service Desk" <it-support@c0ntoso.com>
  - SENDER_LOOKALIKE_DOMAIN (+35): sender domain c0ntoso.com swaps similar-looking characters to imitate contoso.com
  - DISPLAY_NAME_IMPERSONATION (+25): display name 'Contoso IT Service Desk' uses our name 'Contoso' but the mail comes from outside (c0ntoso.com)
  - LINK_LOOKALIKE_DOMAIN (+35): link domain contoso-sso.example contains our name 'contoso' but is not our domain
  - LINK_TEXT_MISMATCH (+30): link text shows https://login.contoso.com but the link goes to contoso-sso.example
  - URGENCY_LANGUAGE (+10): pressure wording: immediately, within 24 hours, account will be suspended
  - CREDENTIAL_LURE (+15): asks about password, verify your account, login and links outside the company (contoso-sso.example)
  Domains: c0ntoso[.]com, contoso-sso[.]example
  > Block the sender and the listed domains and URLs.
  > Find and remove other copies of this message (kql/similar-messages.kql).
  > Check who clicked (kql/clicks-on-reported-urls.kql); reset their password and revoke sessions.
  > Thank the reporter.
```

```powershell
Import-Module .\powershell\PhishTriage\PhishTriage.psd1
$triage = Invoke-PhishTriage -Path .\samples\mail
$triage | Get-TriageSummary
Get-AwarenessKpi -Path .\samples\awareness-campaign-2026-q4.csv | Format-Table
$vuln = Get-VulnerabilityKpi -Path .\samples\vulnerabilities.csv -AsOf 2026-11-18
Export-SecurityReport -Path .\report.html -Triage $triage -Vulnerability $vuln `
    -Awareness (Get-AwarenessKpi -Path .\samples\awareness-campaign-2026-q4.csv)
```

## Design decisions

- **Only our own gateway's Authentication-Results header is believed**, and only the top-most one. Attackers can
  write their own `dmarc=pass` header into a mail; sample 07 does exactly that and is still caught.
- **A phishing simulation needs the platform's header *and* its sending domain.** Trusting the header alone
  would let any attacker add it to skip triage.
- **"No indicators" is not "safe".** There is no URL reputation or sandbox here, and the output says so.
- **Each indicator counts once**, so ten bad links do not outweigh one failed DMARC check. Weights and thresholds
  are in `checks.py` and `config/triage.json`.
- **KPIs refuse bad input.** A duplicate recipient, a "maybe" in a yes/no column or a closing date before the
  opening date stops the calculation with the line number, because a wrong KPI is worse than none.
- **Culture-independent.** Dates are `yyyy-MM-dd`, numbers use a decimal point, and tests run the KPIs on a
  German (`de-DE`) system to prove the results do not change.
- **Reports are HTML-encoded.** Subjects and sender names come from attackers; a test puts `<script>` into a
  subject and checks it cannot run.

## Tests

| Suite | Count | What it covers |
|---|---|---|
| pytest | 137 | Domain logic (homoglyphs, typos, punycode), parsing, every indicator, verdict thresholds, golden results for all 7 samples, CLI, config validation, defanging, samples match their generator |
| Pester | 33 | The PowerShell module end to end with the real Python engine, KPI maths on known data, German locale, bad-input errors, HTML encoding |
| KqlCheck | 6 + 4 | Every query is parsed and analysed with Microsoft's `Kusto.Language` against the table schemas (unknown tables, misspelt columns, type errors); 4 deliberately broken queries must be rejected |

CI (GitHub Actions) runs ruff, pytest on Python 3.11 and 3.13, PSScriptAnalyzer, Pester on PowerShell 7 **and**
Windows PowerShell 5.1, and the KQL check.

The KQL check proves the queries are valid against the documented schemas; it cannot prove they return the
right rows, which needs a Microsoft tenant with real data.

## Run it

```bash
python -m pip install pytest ruff
python -m pytest                                   # Python tests
python -m phishtriage analyze samples/mail          # (with src on PYTHONPATH, or pip install -e .)
dotnet run --project tools/KqlCheck -- kql          # KQL check, needs the .NET 10 SDK
```

```powershell
Install-Module Pester -MinimumVersion 5.5.0 -Scope CurrentUser
Invoke-Pester -Path .\powershell\tests -Output Detailed
```

## Samples

`samples/mail` holds seven synthetic reported mails for the fictional company Contoso, generated by
`tools/make_samples.py`: an internal newsletter, a password-expiry look-alike, a German MFA re-registration lure,
an invoice with a macro file and a `.pdf.js` inside a zip, CEO gift-card fraud, an approved phishing simulation,
and a payroll spoof with a forged authentication header. They use reserved `.example` domains and documentation IP
ranges; attachments are short text placeholders, not malware.

## Limits

- The registrable domain is approximated (no public suffix list, to stay offline).
- No URL reputation, no attachment sandbox, no Microsoft Graph integration: the tool prepares the analyst's
  decision and the KQL scoping, it does not replace them.
- KPI inputs are CSV exports; column names are documented in each function's help.

Personal learning project, not affiliated with any company. Built with AI-assisted development (Claude Code);
I reviewed and can explain every part of the code and tests.
