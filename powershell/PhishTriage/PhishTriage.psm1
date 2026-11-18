#Requires -Version 5.1
<#
    PhishTriage PowerShell module: runs the triage engine and turns triage results, phishing-simulation
    exports and vulnerability lists into the KPIs a security team reports on.
    Works in Windows PowerShell 5.1 and PowerShell 7. All parsing is culture-independent, so a German
    Windows (decimal comma, dd.MM.yyyy) gives the same numbers as an English one.
#>
Set-StrictMode -Version Latest

$script:RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$script:Invariant = [Globalization.CultureInfo]::InvariantCulture
$script:Verdicts = @('phishing', 'suspicious', 'no_indicators', 'simulation')
$script:DefaultSla = [ordered]@{ Critical = 7; High = 30; Medium = 90; Low = 180 }

#region helpers

function Get-PythonCommand {
    param([string] $PythonPath)
    if ($PythonPath) {
        if (-not (Get-Command $PythonPath -ErrorAction SilentlyContinue)) { throw "Python not found at '$PythonPath'." }
        return $PythonPath
    }
    if ($env:PHISHTRIAGE_PYTHON) { return $env:PHISHTRIAGE_PYTHON }
    # On Windows 'python' may be the Microsoft Store placeholder, so prefer the 'py' launcher there.
    $names = if ($env:OS -eq 'Windows_NT') { @('py', 'python', 'python3') } else { @('python3', 'python') }
    foreach ($name in $names) {
        $command = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($command) { return $command.Source }
    }
    throw 'Python 3.11 or newer is required. Install it or pass -PythonPath.'
}

function Get-Percent {
    param([double] $Part, [double] $Whole)
    if ($Whole -eq 0) { return 0.0 }
    return [math]::Round(100.0 * $Part / $Whole, 1, [MidpointRounding]::AwayFromZero)
}

function Get-Median {
    param([double[]] $Values)
    if (-not $Values -or $Values.Count -eq 0) { return $null }
    $sorted = @($Values | Sort-Object)
    $middle = [int][math]::Floor($sorted.Count / 2)
    if ($sorted.Count % 2) { return [double]$sorted[$middle] }
    return ([double]$sorted[$middle - 1] + [double]$sorted[$middle]) / 2
}

function Import-KpiCsv {
    param([string] $Path, [string] $Delimiter, [string[]] $Required)
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
    $rows = @(Import-Csv -LiteralPath $resolved -Delimiter $Delimiter -Encoding UTF8)
    if ($rows.Count -eq 0) { throw "'$Path' contains no data rows." }
    $columns = @($rows[0].PSObject.Properties.Name)
    $missing = @($Required | Where-Object { $columns -notcontains $_ })
    if ($missing.Count) {
        throw "'$Path' is missing column(s): $($missing -join ', '). Found: $($columns -join ', '). Wrong -Delimiter?"
    }
    return $rows
}

function ConvertTo-KpiBool {
    param([string] $Value, [string] $Column, [int] $Line)
    switch -Regex ($Value.Trim().ToLowerInvariant()) {
        '^(true|yes|y|1|ja|j|x)$' { return $true }
        '^(false|no|n|0|nein|)$' { return $false }
    }
    throw "Line ${Line}: column '$Column' is '$Value'; expected yes/no, true/false, ja/nein or 1/0."
}

function ConvertTo-KpiDate {
    param([string] $Value, [string] $Column, [int] $Line)
    $date = [datetime]::MinValue
    if (-not [datetime]::TryParseExact($Value.Trim(), 'yyyy-MM-dd', $script:Invariant,
            [Globalization.DateTimeStyles]::None, [ref] $date)) {
        throw "Line ${Line}: column '$Column' is '$Value'; expected a date as yyyy-MM-dd."
    }
    return $date
}

function ConvertTo-HtmlEncoded {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [double] -or $Value -is [decimal] -or $Value -is [single]) {
        return $Value.ToString('0.#', $script:Invariant)
    }
    if ($Value -is [datetime]) { return $Value.ToString('yyyy-MM-dd', $script:Invariant) }
    # Escape only what HTML needs; the page is UTF-8, so umlauts stay readable.
    return ([string]$Value).Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;').Replace("'", '&#39;')
}

function ConvertTo-HtmlTableFragment {
    param([object[]] $Rows, [string[]] $Columns, [string] $Empty = 'Nothing to report.')
    if (-not $Rows -or $Rows.Count -eq 0) { return "<p class=`"empty`">$(ConvertTo-HtmlEncoded $Empty)</p>" }
    $builder = [Text.StringBuilder]::new()
    [void]$builder.Append('<table><thead><tr>')
    foreach ($column in $Columns) { [void]$builder.Append("<th>$(ConvertTo-HtmlEncoded $column)</th>") }
    [void]$builder.Append('</tr></thead><tbody>')
    foreach ($row in $Rows) {
        [void]$builder.Append('<tr>')
        foreach ($column in $Columns) { [void]$builder.Append("<td>$(ConvertTo-HtmlEncoded $row.$column)</td>") }
        [void]$builder.Append('</tr>')
    }
    [void]$builder.Append('</tbody></table>')
    return $builder.ToString()
}

#endregion

function Invoke-PhishTriage {
    <#
    .SYNOPSIS
        Triage reported e-mails (.eml files or folders) and return one result object per mail.
    .EXAMPLE
        Get-ChildItem .\reported -Filter *.eml | Invoke-PhishTriage | Where-Object verdict -eq 'phishing'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('FullName')]
        [string[]] $Path,
        [string] $ConfigPath,
        [string] $PythonPath
    )
    begin { $files = [Collections.Generic.List[string]]::new() }
    process {
        foreach ($item in $Path) { $files.Add((Resolve-Path -LiteralPath $item -ErrorAction Stop).ProviderPath) }
    }
    end {
        if ($files.Count -eq 0) { return }
        $python = Get-PythonCommand -PythonPath $PythonPath
        $output = [IO.Path]::GetTempFileName()
        $previousPythonPath = $env:PYTHONPATH
        try {
            $env:PYTHONPATH = Join-Path $script:RepoRoot 'src'
            $arguments = @('-m', 'phishtriage', 'analyze') + $files.ToArray() + @('--format', 'json', '--output', $output)
            if ($ConfigPath) {
                $arguments += @('--config', (Resolve-Path -LiteralPath $ConfigPath -ErrorAction Stop).ProviderPath)
            }
            & $python @arguments
            if ($LASTEXITCODE -ge 2) { throw "phishtriage stopped with exit code $LASTEXITCODE (see the message above)." }

            $json = [IO.File]::ReadAllText($output, [Text.Encoding]::UTF8)
            foreach ($result in ($json | ConvertFrom-Json)) {
                if ($result.PSObject.Properties.Name -contains 'error') {
                    Write-Error -Message "$($result.file): $($result.error)" -Category InvalidData
                    continue
                }
                $result.PSObject.TypeNames.Insert(0, 'PhishTriage.Result')
                $result
            }
        }
        finally {
            $env:PYTHONPATH = $previousPythonPath
            Remove-Item -LiteralPath $output -ErrorAction SilentlyContinue
        }
    }
}

function Get-TriageSummary {
    <#
    .SYNOPSIS
        KPIs for a batch of triaged reports: counts per verdict, confirmed-phishing share, top senders and indicators.
    .DESCRIPTION
        PhishingShare is the share of real reports (simulations excluded) that were rated phishing.
        Top senders and top indicators ignore simulations, so the company's own tests do not dominate the report.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)] [AllowEmptyCollection()] [psobject[]] $InputObject,
        [ValidateRange(1, 100)] [int] $Top = 5
    )
    begin { $items = [Collections.Generic.List[object]]::new() }
    process { foreach ($item in $InputObject) { $items.Add($item) } }
    end {
        $counts = @{}
        foreach ($verdict in $script:Verdicts) { $counts[$verdict] = @($items | Where-Object { $_.verdict -eq $verdict }).Count }
        $real = @($items | Where-Object { $_.verdict -ne 'simulation' })
        $flagged = @($real | Where-Object { $_.verdict -in 'phishing', 'suspicious' })

        $topSenders = @($flagged | Group-Object -Property sender_domain |
                Sort-Object -Property @{ Expression = 'Count'; Descending = $true }, @{ Expression = 'Name' } |
                Select-Object -First $Top |
                ForEach-Object { [pscustomobject]@{ Domain = $_.Name; Reports = $_.Count } })
        $topFindings = @($real | ForEach-Object { $_.findings } | Where-Object { $_ } | Group-Object -Property code |
                Sort-Object -Property @{ Expression = 'Count'; Descending = $true }, @{ Expression = 'Name' } |
                Select-Object -First $Top |
                ForEach-Object { [pscustomobject]@{ Indicator = $_.Name; Reports = $_.Count } })

        [pscustomobject]@{
            PSTypeName       = 'PhishTriage.Summary'
            Total            = $items.Count
            Phishing         = $counts['phishing']
            Suspicious       = $counts['suspicious']
            NoIndicators     = $counts['no_indicators']
            Simulation       = $counts['simulation']
            PhishingShare    = Get-Percent $counts['phishing'] $real.Count
            TopSenderDomains = $topSenders
            TopIndicators    = $topFindings
        }
    }
}

function Get-AwarenessKpi {
    <#
    .SYNOPSIS
        Click, credential and report rates per department from a phishing-simulation export.
    .DESCRIPTION
        Expected columns: Email, Department, Clicked, CredentialsSubmitted, Reported, MinutesToReport.
        Yes/no columns accept yes/no, true/false, ja/nein, 1/0. MinutesToReport is only read for reported rows.
        Bad rows stop the calculation with the line number, because a KPI built on wrong rows is worse than none.
    .EXAMPLE
        Get-AwarenessKpi -Path .\campaign.csv -Delimiter ';' | Format-Table
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [string] $Delimiter = ','
    )
    $required = 'Email', 'Department', 'Clicked', 'CredentialsSubmitted', 'Reported', 'MinutesToReport'
    $rows = Import-KpiCsv -Path $Path -Delimiter $Delimiter -Required $required

    $records = [Collections.Generic.List[object]]::new()
    $seen = @{}
    $line = 1
    foreach ($row in $rows) {
        $line++
        $email = $row.Email.Trim().ToLowerInvariant()
        if (-not $email) { throw "Line ${line}: Email is empty." }
        if ($seen.ContainsKey($email)) { throw "Line ${line}: $email already appears on line $($seen[$email]); each recipient must appear once." }
        $seen[$email] = $line
        $clicked = ConvertTo-KpiBool $row.Clicked 'Clicked' $line
        $submitted = ConvertTo-KpiBool $row.CredentialsSubmitted 'CredentialsSubmitted' $line
        $reported = ConvertTo-KpiBool $row.Reported 'Reported' $line
        if ($submitted -and -not $clicked) { throw "Line ${line}: credentials were submitted without a click; check the export." }
        $minutes = $null
        if ($reported) {
            $parsed = 0.0
            if (-not [double]::TryParse($row.MinutesToReport, [Globalization.NumberStyles]::Float, $script:Invariant, [ref] $parsed) -or $parsed -lt 0) {
                throw "Line ${line}: MinutesToReport is '$($row.MinutesToReport)'; expected a number like 12 or 7.5."
            }
            $minutes = $parsed
        }
        $department = if ($row.Department.Trim()) { $row.Department.Trim() } else { '(none)' }
        $records.Add([pscustomobject]@{ Department = $department; Clicked = $clicked; Submitted = $submitted; Reported = $reported; Minutes = $minutes })
    }

    $groups = @($records | Group-Object -Property Department | Sort-Object -Property Name)
    $groups += [pscustomobject]@{ Name = 'All'; Group = $records.ToArray() }
    foreach ($group in $groups) {
        $members = @($group.Group)
        $clicks = @($members | Where-Object Clicked).Count
        $submits = @($members | Where-Object Submitted).Count
        $reports = @($members | Where-Object Reported)
        [pscustomobject]@{
            PSTypeName            = 'PhishTriage.AwarenessKpi'
            Department            = $group.Name
            Recipients            = $members.Count
            Clicked               = $clicks
            ClickRate             = Get-Percent $clicks $members.Count
            CredentialsSubmitted  = $submits
            CredentialRate        = Get-Percent $submits $members.Count
            Reported              = $reports.Count
            ReportRate            = Get-Percent $reports.Count $members.Count
            MedianMinutesToReport = Get-Median @($reports | ForEach-Object { $_.Minutes })
        }
    }
}

function Get-VulnerabilityKpi {
    <#
    .SYNOPSIS
        Remediation status of vulnerability findings against SLA deadlines, per severity and per site.
    .DESCRIPTION
        Expected columns: Id, Title, Severity, Site, Opened, Closed (empty while open); Owner is optional.
        Dates are yyyy-MM-dd. A finding is overdue when it is still open after Opened + SLA days.
    .EXAMPLE
        Get-VulnerabilityKpi -Path .\findings.csv -AsOf (Get-Date) | Select-Object -ExpandProperty OverdueFindings
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [datetime] $AsOf = (Get-Date).Date,
        [Collections.IDictionary] $SlaDays = $script:DefaultSla,
        [string] $Delimiter = ','
    )
    $rows = Import-KpiCsv -Path $Path -Delimiter $Delimiter -Required 'Id', 'Title', 'Severity', 'Site', 'Opened', 'Closed'
    $asOfDate = $AsOf.Date
    $severities = @($SlaDays.Keys)
    $findings = [Collections.Generic.List[object]]::new()
    $line = 1
    foreach ($row in $rows) {
        $line++
        $severity = $severities | Where-Object { $_ -eq $row.Severity.Trim() } | Select-Object -First 1
        if (-not $severity) { throw "Line ${line}: severity '$($row.Severity)' is not one of: $($severities -join ', ')." }
        $opened = ConvertTo-KpiDate $row.Opened 'Opened' $line
        if ($opened -gt $asOfDate) { throw "Line ${line}: opened on $($row.Opened), after the report date." }
        $closed = $null
        if ($row.Closed.Trim()) {
            $closed = ConvertTo-KpiDate $row.Closed 'Closed' $line
            if ($closed -lt $opened) { throw "Line ${line}: closed ($($row.Closed)) before it was opened ($($row.Opened))." }
        }
        $due = $opened.AddDays([int]$SlaDays[$severity])
        $owner = if ($row.PSObject.Properties.Name -contains 'Owner') { $row.Owner } else { '' }
        $findings.Add([pscustomobject]@{
                Id = $row.Id; Title = $row.Title; Severity = $severity; Site = $row.Site.Trim(); Owner = $owner
                Opened = $opened; Closed = $closed; Due = $due
                IsOpen = ($null -eq $closed)
                DaysOverdue = if ($null -eq $closed -and $asOfDate -gt $due) { [int]($asOfDate - $due).TotalDays } else { 0 }
                ClosedInSla = ($null -ne $closed -and $closed -le $due)
                DaysToClose = if ($null -ne $closed) { [int]($closed - $opened).TotalDays } else { $null }
            })
    }

    $bySeverity = foreach ($severity in $severities) {
        $set = @($findings | Where-Object Severity -eq $severity)
        $closedSet = @($set | Where-Object { -not $_.IsOpen })
        $days = @($closedSet | ForEach-Object { $_.DaysToClose })
        [pscustomobject]@{
            Severity        = $severity
            SlaDays         = [int]$SlaDays[$severity]
            Open            = @($set | Where-Object IsOpen).Count
            Overdue         = @($set | Where-Object { $_.DaysOverdue -gt 0 }).Count
            Closed          = $closedSet.Count
            ClosedWithinSla = Get-Percent @($closedSet | Where-Object ClosedInSla).Count $closedSet.Count
            MeanDaysToClose = if ($days.Count) { [math]::Round(($days | Measure-Object -Average).Average, 1, [MidpointRounding]::AwayFromZero) } else { $null }
        }
    }
    $bySite = @($findings | Group-Object -Property Site | ForEach-Object {
            [pscustomobject]@{
                Site    = $_.Name
                Open    = @($_.Group | Where-Object IsOpen).Count
                Overdue = @($_.Group | Where-Object { $_.DaysOverdue -gt 0 }).Count
            }
        } | Sort-Object -Property @{ Expression = 'Overdue'; Descending = $true }, @{ Expression = 'Open'; Descending = $true }, Site)
    $overdue = @($findings | Where-Object { $_.DaysOverdue -gt 0 } |
            Sort-Object -Property @{ Expression = 'DaysOverdue'; Descending = $true }, Id |
            Select-Object Id, Title, Severity, Site, Owner, Due, DaysOverdue)

    [pscustomobject]@{
        PSTypeName      = 'PhishTriage.VulnerabilityKpi'
        AsOf            = $asOfDate
        Total           = $findings.Count
        Open            = @($findings | Where-Object IsOpen).Count
        Overdue         = $overdue.Count
        BySeverity      = @($bySeverity)
        BySite          = $bySite
        OverdueFindings = $overdue
    }
}

function Export-SecurityReport {
    <#
    .SYNOPSIS
        Write a self-contained HTML report from triage results, awareness KPIs and vulnerability KPIs.
    .DESCRIPTION
        Every value is HTML-encoded: subjects and sender names come from attackers and must not run as script
        when the report is opened.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [psobject[]] $Triage = @(),
        [psobject[]] $Awareness = @(),
        [psobject] $Vulnerability,
        [string] $Title = 'Security operations report',
        [datetime] $GeneratedAt = (Get-Date)
    )
    $sections = [Collections.Generic.List[string]]::new()
    if ($Triage.Count) {
        $summary = $Triage | Get-TriageSummary
        $counts = [pscustomobject]@{
            Reports = $summary.Total; Phishing = $summary.Phishing; Suspicious = $summary.Suspicious
            'No indicators' = $summary.NoIndicators; Simulation = $summary.Simulation; 'Phishing share %' = $summary.PhishingShare
        }
        $sections.Add('<h2>Reported e-mails</h2>' +
            (ConvertTo-HtmlTableFragment @($counts) @('Reports', 'Phishing', 'Suspicious', 'No indicators', 'Simulation', 'Phishing share %')) +
            '<h3>Reports</h3>' +
            (ConvertTo-HtmlTableFragment @($Triage | Sort-Object -Property @{ Expression = 'score'; Descending = $true }, file) @('verdict', 'score', 'subject', 'sender', 'file')) +
            '<h3>Most common indicators</h3>' +
            (ConvertTo-HtmlTableFragment $summary.TopIndicators @('Indicator', 'Reports')))
    }
    if ($Awareness.Count) {
        $sections.Add('<h2>Phishing simulation</h2>' + (ConvertTo-HtmlTableFragment $Awareness @(
                    'Department', 'Recipients', 'ClickRate', 'CredentialRate', 'ReportRate', 'MedianMinutesToReport')))
    }
    if ($Vulnerability) {
        $sections.Add("<h2>Vulnerability status (as of $(ConvertTo-HtmlEncoded $Vulnerability.AsOf))</h2>" +
            (ConvertTo-HtmlTableFragment $Vulnerability.BySeverity @('Severity', 'SlaDays', 'Open', 'Overdue', 'Closed', 'ClosedWithinSla', 'MeanDaysToClose')) +
            '<h3>By site</h3>' + (ConvertTo-HtmlTableFragment $Vulnerability.BySite @('Site', 'Open', 'Overdue')) +
            '<h3>Overdue findings</h3>' +
            (ConvertTo-HtmlTableFragment $Vulnerability.OverdueFindings @('Id', 'Title', 'Severity', 'Site', 'Owner', 'Due', 'DaysOverdue') 'No overdue findings.'))
    }
    if ($sections.Count -eq 0) { throw 'Nothing to report: pass -Triage, -Awareness and/or -Vulnerability.' }

    $style = 'body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1b1b1b}h1{font-size:22px}' +
    'h2{font-size:18px;border-bottom:2px solid #0b5394;padding-bottom:4px;margin-top:28px}h3{font-size:15px}' +
    'table{border-collapse:collapse;margin:8px 0}th,td{border:1px solid #c8c8c8;padding:4px 8px;text-align:left}' +
    'th{background:#eef3f8}.meta,.empty{color:#555}'
    $html = "<!doctype html><html lang=`"en`"><head><meta charset=`"utf-8`"><title>$(ConvertTo-HtmlEncoded $Title)</title>" +
    "<style>$style</style></head><body><h1>$(ConvertTo-HtmlEncoded $Title)</h1>" +
    "<p class=`"meta`">Generated $($GeneratedAt.ToString('yyyy-MM-dd HH:mm', $script:Invariant))</p>" +
    ($sections -join '') + '</body></html>'

    $target = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    [IO.File]::WriteAllText($target, $html, [Text.UTF8Encoding]::new($false))
    Get-Item -LiteralPath $target
}

Export-ModuleMember -Function Invoke-PhishTriage, Get-TriageSummary, Get-AwarenessKpi, Get-VulnerabilityKpi, Export-SecurityReport
