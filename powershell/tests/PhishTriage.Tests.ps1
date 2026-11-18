#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }
# Run: Invoke-Pester -Path .\powershell\tests -Output Detailed
# Works in Windows PowerShell 5.1 and PowerShell 7.

BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).ProviderPath
    $script:Samples = Join-Path $script:Root 'samples'
    $script:Mail = Join-Path $script:Samples 'mail'
    Import-Module (Join-Path $script:Root 'powershell\PhishTriage\PhishTriage.psd1') -Force

    function Write-TestCsv {
        param([string] $Name, [string[]] $Lines)
        $path = Join-Path $TestDrive $Name
        [IO.File]::WriteAllLines($path, $Lines, [Text.UTF8Encoding]::new($false))
        $path
    }

    function Use-Culture {
        param([string] $Name, [scriptblock] $Script)
        $previous = [Threading.Thread]::CurrentThread.CurrentCulture
        try {
            [Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]::GetCultureInfo($Name)
            & $Script
        }
        finally { [Threading.Thread]::CurrentThread.CurrentCulture = $previous }
    }
}

Describe 'Invoke-PhishTriage' {
    BeforeAll {
        $script:Results = @(Invoke-PhishTriage -Path $script:Mail)
    }

    It 'triages every sample with the expected verdict' {
        $verdicts = @{}
        foreach ($r in $script:Results) { $verdicts[$r.file] = $r.verdict }
        $verdicts['01-internal-newsletter.eml'] | Should -Be 'no_indicators'
        $verdicts['02-password-expiry-lookalike.eml'] | Should -Be 'phishing'
        $verdicts['03-mfa-reregistration-de.eml'] | Should -Be 'phishing'
        $verdicts['04-invoice-attachments.eml'] | Should -Be 'phishing'
        $verdicts['05-ceo-gift-cards.eml'] | Should -Be 'suspicious'
        $verdicts['06-phishing-simulation.eml'] | Should -Be 'simulation'
        $verdicts['07-payroll-spoof-forged-auth.eml'] | Should -Be 'phishing'
        $script:Results.Count | Should -Be 7
    }

    It 'accepts files from the pipeline' {
        $piped = @(Get-ChildItem -Path $script:Mail -Filter '*.eml' | Where-Object Name -match '^0[12]-' | Invoke-PhishTriage)
        $piped.file | Should -Be @('01-internal-newsletter.eml', '02-password-expiry-lookalike.eml')
    }

    It 'keeps German umlauts and dashes intact' {
        ($script:Results | Where-Object file -like '07-*').subject | Should -Be 'Gehaltsabrechnung November – bitte bestätigen'
    }

    It 'returns defanged indicators' {
        ($script:Results | Where-Object file -like '02-*').iocs.domains | Should -Contain 'c0ntoso[.]com'
    }

    It 'passes the config file through' {
        $raw = Get-Content (Join-Path $script:Root 'config\triage.json') -Raw | ConvertFrom-Json
        $raw.phishing_threshold = 90
        $config = Join-Path $TestDrive 'strict.json'
        $raw | ConvertTo-Json | Set-Content -Path $config -Encoding ASCII
        (Invoke-PhishTriage -Path (Join-Path $script:Mail '07-payroll-spoof-forged-auth.eml') -ConfigPath $config).verdict |
            Should -Be 'suspicious'
    }

    It 'reports an unreadable file as an error and still returns the others' {
        $empty = Join-Path $TestDrive 'empty.eml'
        Set-Content -Path $empty -Value '' -NoNewline
        $ok = @(Invoke-PhishTriage -Path $empty, (Join-Path $script:Mail '01-internal-newsletter.eml') -ErrorVariable problems -ErrorAction SilentlyContinue)
        $ok.Count | Should -Be 1
        "$problems" | Should -Match 'empty\.eml: the file is empty'
    }

    It 'fails clearly for a path that does not exist' {
        { Invoke-PhishTriage -Path (Join-Path $TestDrive 'nope.eml') } | Should -Throw
    }

    It 'fails clearly when Python is not where it was pointed to' {
        { Invoke-PhishTriage -Path $script:Mail -PythonPath 'C:\does-not-exist\python.exe' } | Should -Throw '*Python not found*'
    }
}

Describe 'Get-TriageSummary' {
    BeforeAll { $script:Summary = Invoke-PhishTriage -Path $script:Mail | Get-TriageSummary }

    It 'counts reports per verdict' {
        $script:Summary.Total | Should -Be 7
        $script:Summary.Phishing | Should -Be 4
        $script:Summary.Suspicious | Should -Be 1
        $script:Summary.NoIndicators | Should -Be 1
        $script:Summary.Simulation | Should -Be 1
    }

    It 'leaves simulations out of the phishing share' {
        # 4 phishing out of 6 real reports
        $script:Summary.PhishingShare | Should -Be 66.7
    }

    It 'ranks indicators without counting simulations' {
        $script:Summary.TopIndicators[0].Indicator | Should -Be 'URGENCY_LANGUAGE'
        $script:Summary.TopIndicators[0].Reports | Should -Be 4
        $all = Invoke-PhishTriage -Path $script:Mail | Get-TriageSummary -Top 50
        ($all.TopIndicators | Where-Object Indicator -eq 'LINK_LOOKALIKE_DOMAIN').Reports | Should -Be 1
    }

    It 'handles an empty batch' {
        $empty = @() | Get-TriageSummary
        $empty.Total | Should -Be 0
        $empty.PhishingShare | Should -Be 0
    }
}

Describe 'Get-AwarenessKpi' {
    It 'calculates rates per department and overall for the sample campaign' {
        $kpi = Get-AwarenessKpi -Path (Join-Path $script:Samples 'awareness-campaign-2026-q4.csv')
        $kpi.Department | Should -Be @('Engineering', 'Finance', 'HR', 'Sales', 'All')
        $all = $kpi | Where-Object Department -eq 'All'
        $all.Recipients | Should -Be 20
        $all.ClickRate | Should -Be 35
        $all.CredentialRate | Should -Be 15
        $all.ReportRate | Should -Be 60
        $all.MedianMinutesToReport | Should -Be 10.5
        $engineering = $kpi | Where-Object Department -eq 'Engineering'
        $engineering.ClickRate | Should -Be 16.7
        $engineering.ReportRate | Should -Be 83.3
        $engineering.MedianMinutesToReport | Should -Be 4.5
    }

    It 'reads semicolon-separated German exports on a German system' {
        $path = Write-TestCsv 'de.csv' @(
            'Email;Department;Clicked;CredentialsSubmitted;Reported;MinutesToReport'
            'a@contoso.com;Einkauf;ja;nein;ja;7.5'
            'b@contoso.com;Einkauf;nein;nein;nein;'
        )
        Use-Culture 'de-DE' {
            $all = Get-AwarenessKpi -Path $path -Delimiter ';' | Where-Object Department -eq 'All'
            $all.ClickRate | Should -Be 50
            $all.MedianMinutesToReport | Should -Be 7.5
        }
    }

    It 'stops on an unclear yes/no value and names the line' {
        $path = Write-TestCsv 'bad.csv' @(
            'Email,Department,Clicked,CredentialsSubmitted,Reported,MinutesToReport'
            'a@contoso.com,HR,no,no,no,'
            'b@contoso.com,HR,maybe,no,no,'
        )
        { Get-AwarenessKpi -Path $path } | Should -Throw "*Line 3: column 'Clicked' is 'maybe'*"
    }

    It 'stops on a recipient that appears twice' {
        $path = Write-TestCsv 'dupe.csv' @(
            'Email,Department,Clicked,CredentialsSubmitted,Reported,MinutesToReport'
            'a@contoso.com,HR,no,no,no,'
            'A@Contoso.com,HR,yes,no,no,'
        )
        { Get-AwarenessKpi -Path $path } | Should -Throw '*already appears on line 2*'
    }

    It 'stops on credentials submitted without a click' {
        $path = Write-TestCsv 'odd.csv' @(
            'Email,Department,Clicked,CredentialsSubmitted,Reported,MinutesToReport'
            'a@contoso.com,HR,no,yes,no,'
        )
        { Get-AwarenessKpi -Path $path } | Should -Throw '*without a click*'
    }

    It 'stops on a reported row without a time' {
        $path = Write-TestCsv 'notime.csv' @(
            'Email,Department,Clicked,CredentialsSubmitted,Reported,MinutesToReport'
            'a@contoso.com,HR,no,no,yes,'
        )
        { Get-AwarenessKpi -Path $path } | Should -Throw '*MinutesToReport*'
    }

    It 'names missing columns and hints at the delimiter' {
        $path = Write-TestCsv 'semi.csv' @('Email;Department;Clicked;CredentialsSubmitted;Reported;MinutesToReport', 'a@contoso.com;HR;no;no;no;')
        { Get-AwarenessKpi -Path $path } | Should -Throw '*missing column*Wrong -Delimiter*'
    }
}

Describe 'Get-VulnerabilityKpi' {
    BeforeAll {
        $script:Vuln = Get-VulnerabilityKpi -Path (Join-Path $script:Samples 'vulnerabilities.csv') -AsOf ([datetime]'2026-11-18')
    }

    It 'counts open and overdue findings' {
        $script:Vuln.Total | Should -Be 12
        $script:Vuln.Open | Should -Be 7
        $script:Vuln.Overdue | Should -Be 4
    }

    It 'lists overdue findings, most overdue first, with days past the deadline' {
        $script:Vuln.OverdueFindings.Id | Should -Be @('VULN-110', 'VULN-106', 'VULN-103', 'VULN-101')
        $script:Vuln.OverdueFindings.DaysOverdue | Should -Be @(82, 50, 29, 9)
    }

    It 'reports per severity, including closures within the SLA' {
        $medium = $script:Vuln.BySeverity | Where-Object Severity -eq 'Medium'
        $medium.Open | Should -Be 2
        $medium.Closed | Should -Be 2
        $medium.ClosedWithinSla | Should -Be 50
        $medium.MeanDaysToClose | Should -Be 91
        $script:Vuln.BySeverity.Severity | Should -Be @('Critical', 'High', 'Medium', 'Low')
    }

    It 'ranks sites by overdue findings' {
        $script:Vuln.BySite.Site | Should -Be @('Berlin HQ', 'Plant B', 'Erlangen', 'Plant A')
    }

    It 'gives the same result on a German system' {
        Use-Culture 'de-DE' {
            (Get-VulnerabilityKpi -Path (Join-Path $script:Samples 'vulnerabilities.csv') -AsOf ([datetime]'2026-11-18')).Overdue |
                Should -Be 4
        }
    }

    It 'uses custom SLA deadlines' {
        $loose = Get-VulnerabilityKpi -Path (Join-Path $script:Samples 'vulnerabilities.csv') -AsOf ([datetime]'2026-11-18') `
            -SlaDays ([ordered]@{ Critical = 30; High = 60; Medium = 365; Low = 365 })
        $loose.Overdue | Should -Be 0
    }

    It 'rejects bad rows with the line number' -TestCases @(
        @{ Row = 'V-1,t,Critical,HQ,01.11.2026,'; Message = "*Line 2: column 'Opened' is '01.11.2026'*" }
        @{ Row = 'V-1,t,Severe,HQ,2026-11-01,'; Message = "*severity 'Severe'*" }
        @{ Row = 'V-1,t,Low,HQ,2026-11-10,2026-11-01'; Message = '*closed (2026-11-01) before it was opened*' }
        @{ Row = 'V-1,t,Low,HQ,2026-12-01,'; Message = '*after the report date*' }
    ) {
        param($Row, $Message)
        $path = Write-TestCsv 'v.csv' @('Id,Title,Severity,Site,Opened,Closed', $Row)
        { Get-VulnerabilityKpi -Path $path -AsOf ([datetime]'2026-11-18') } | Should -Throw $Message
    }
}

Describe 'Export-SecurityReport' {
    It 'writes one HTML report with all sections' {
        $path = Join-Path $TestDrive 'report.html'
        $null = Export-SecurityReport -Path $path -GeneratedAt ([datetime]'2026-11-18T09:00:00') `
            -Triage (Invoke-PhishTriage -Path $script:Mail) `
            -Awareness (Get-AwarenessKpi -Path (Join-Path $script:Samples 'awareness-campaign-2026-q4.csv')) `
            -Vulnerability (Get-VulnerabilityKpi -Path (Join-Path $script:Samples 'vulnerabilities.csv') -AsOf ([datetime]'2026-11-18'))
        $html = [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8)
        $html | Should -Match '<h2>Reported e-mails</h2>'
        $html | Should -Match '<h2>Phishing simulation</h2>'
        $html | Should -Match '<h2>Vulnerability status \(as of 2026-11-18\)</h2>'
        $html | Should -Match 'Generated 2026-11-18 09:00'
        $html | Should -Match 'bestätigen'
    }

    It 'encodes attacker-controlled text so it cannot run as script' {
        $evil = [pscustomobject]@{
            file = 'x.eml'; verdict = 'phishing'; score = 90; sender = '"<img src=x onerror=alert(1)>" <a@evil.example>'
            sender_domain = 'evil.example'; subject = '<script>alert(1)</script>'; findings = @()
        }
        $path = Join-Path $TestDrive 'evil.html'
        $null = Export-SecurityReport -Path $path -Triage $evil
        $html = [IO.File]::ReadAllText($path)
        $html | Should -Not -Match '<script>alert'
        $html | Should -Not -Match '<img src=x'
        $html | Should -Match '&lt;script&gt;alert\(1\)&lt;/script&gt;'
    }

    It 'writes numbers the same way on a German system' {
        $path = Join-Path $TestDrive 'de.html'
        Use-Culture 'de-DE' {
            $null = Export-SecurityReport -Path $path -Awareness (Get-AwarenessKpi -Path (Join-Path $script:Samples 'awareness-campaign-2026-q4.csv'))
        }
        [IO.File]::ReadAllText($path) | Should -Match '<td>16\.7</td>'
    }

    It 'refuses to write an empty report' {
        { Export-SecurityReport -Path (Join-Path $TestDrive 'none.html') } | Should -Throw '*Nothing to report*'
    }
}
