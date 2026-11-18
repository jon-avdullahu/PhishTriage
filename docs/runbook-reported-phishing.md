# Runbook: user-reported phishing

**Goal:** every reported e-mail gets a verdict within one working hour, every real phishing mail is removed from
all mailboxes, everyone who clicked is protected, and the reporter hears back.

**Never** click links or open attachments from a reported mail on a normal workstation. PhishTriage reads the
`.eml` file as data only: it opens no links, runs no attachments and does not unpack archives.

## 1. Collect

1. Save the reported message as `.eml` (with all headers) into the case folder, e.g. `cases\2026-11-18\`.
2. Open a ticket. Note the reporter, the time of the report, and whether they clicked, replied or opened anything.

## 2. Triage

```powershell
Import-Module .\powershell\PhishTriage\PhishTriage.psd1
$results = Invoke-PhishTriage -Path .\cases\2026-11-18 -ConfigPath .\config\triage.json
$results | Format-Table file, verdict, score, subject -AutoSize
$results | Where-Object verdict -ne 'no_indicators' | Select-Object -ExpandProperty findings
```

| Verdict | Meaning | Next step |
|---|---|---|
| `phishing` | Score 60 or more | Steps 3 to 5 now |
| `suspicious` | Score 25 to 59 | Analyst review: read the findings, check the sender history, then decide |
| `no_indicators` | Score below 25 | Still look at it. The tool has no URL reputation or sandbox, so "no indicators" is not "safe" |
| `simulation` | Approved phishing simulation (header **and** sending domain match) | Count the report, thank the reporter, close |

A mail that carries the simulation header but comes from another domain gets `SIMULATION_HEADER_UNTRUSTED`:
treat it as an attempt to look like a test.

## 3. Scope

Copy the sender, subject, domains and IPs from the result. Indicators are defanged (`hxxps`, `[.]`) so they cannot
be clicked; refang them before pasting them into a query or block list.

1. **Who else received it?** `kql/similar-messages.kql` in Defender advanced hunting.
2. **Who clicked?** `kql/clicks-on-reported-urls.kql`.
3. If the lure was about MFA or the authenticator app, also run `kql/mfa-fatigue.kql` in Sentinel.

## 4. Contain

1. Remove all copies found in step 3 (soft delete) and record how many.
2. Block the sender address or domain and the URLs/domains (tenant allow/block list).
3. For every user who clicked through or entered credentials: reset the password, revoke sessions, check MFA
   methods for newly added devices, and review sign-ins for the last 24 hours.
4. Attachments: search the SHA256 hashes in Defender and block them if they were opened anywhere.

## 5. Close

1. Reply to the reporter (templates below). People keep reporting when they hear back.
2. Record verdict, number of recipients, number of clicks and time to contain in the ticket.
3. Weekly: `Get-TriageSummary` for the KPI report, `Export-SecurityReport` for the HTML version.

### Reply templates

> **EN:** Thank you for reporting this e-mail. It was a phishing attempt and we have removed it from all
> mailboxes. You do not need to do anything else. If you clicked the link or entered your password, please call
> the IT service desk now.

> **DE:** Vielen Dank für Ihre Meldung. Es handelte sich um eine Phishing-Mail, die wir aus allen Postfächern
> entfernt haben. Sie müssen nichts weiter tun. Falls Sie auf den Link geklickt oder Ihr Passwort eingegeben
> haben, rufen Sie bitte sofort den IT-Service-Desk an.

## Escalate immediately (do not wait for the weekly report)

- Credentials were entered, or an MFA prompt was approved by mistake.
- An attachment was opened on a device.
- The mail targets finance with a payment or bank-detail change (possible CEO fraud): confirm by phone using a
  known number, never the one in the mail.
- More than 20 recipients, or the sender is a real partner whose mailbox appears compromised.
