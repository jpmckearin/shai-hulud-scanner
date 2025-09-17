param(
    [string]$ConfigPath = "$PSScriptRoot/pester.psd1",
    [string[]]$Tags,
    [switch]$PassThru
)

if (-not (Get-Module -ListAvailable -Name Pester)) {
    Write-Host 'Pester is not installed. Installing to CurrentUser...' -ForegroundColor Yellow
    Install-Module Pester -Scope CurrentUser -Force -ErrorAction Stop
}

Import-Module Pester -Force

$cfgData = Import-PowerShellDataFile -Path $ConfigPath
$config = [PesterConfiguration]::Default

if ($cfgData.Run) {
    if ($cfgData.Run.Path) { $config.Run.Path = $cfgData.Run.Path }
    if ($cfgData.Run.ExcludeTag) { $config.Run.ExcludeTag = $cfgData.Run.ExcludeTag }
}
if ($cfgData.Output) {
    if ($cfgData.Output.Verbosity) { $config.Output.Verbosity = $cfgData.Output.Verbosity }
}
if ($cfgData.TestResult) {
    $config.TestResult.Enabled = $true
    if ($cfgData.TestResult.OutputPath) { $config.TestResult.OutputPath = $cfgData.TestResult.OutputPath }
    if ($cfgData.TestResult.OutputFormat) { $config.TestResult.OutputFormat = $cfgData.TestResult.OutputFormat }
}

if ($Tags) { $config.Filter.Tag = $Tags }

$invokeParams = @{ Configuration = $config }
if ($PassThru) { $invokeParams.PassThru = $true }

Invoke-Pester @invokeParams