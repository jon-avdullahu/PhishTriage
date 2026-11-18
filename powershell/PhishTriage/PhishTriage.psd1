@{
    RootModule           = 'PhishTriage.psm1'
    ModuleVersion        = '0.1.0'
    GUID                 = '6f0d4f5e-2a8c-4c1e-9a77-3d2f1b6e8c41'
    Author               = 'Jon Avdullahu'
    Description          = 'Triage reported phishing e-mails and report security KPIs (awareness campaigns, vulnerability remediation).'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport    = @('Invoke-PhishTriage', 'Get-TriageSummary', 'Get-AwarenessKpi', 'Get-VulnerabilityKpi', 'Export-SecurityReport')
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
}
