param(
    [Parameter(Mandatory=$true)][string]$LabRoot,
    [Parameter(Mandatory=$true)][string]$SourcePath
)
$ErrorActionPreference = 'Stop'
$editorRoot = Join-Path $LabRoot 'Hex editor'
$policy = Get-Content -LiteralPath (Join-Path $editorRoot 'config\live_gemma_e2e_monitor_policy.json') -Raw | ConvertFrom-Json
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$outputRoot = Join-Path $LabRoot $policy.runtime_output_root
$runRoot = Join-Path $outputRoot $stamp
New-Item -ItemType Directory -Force -Path $runRoot | Out-Null
$logPath = Join-Path $runRoot 'rolling.log'
$statusPath = Join-Path $runRoot 'latest.json'
$counter = 0
Write-Host "Gemma live E2E monitor" -ForegroundColor Cyan
Write-Host "Source: $SourcePath"
Write-Host "Output: $runRoot"
Write-Host "Ctrl+C stops the monitor." -ForegroundColor Yellow
while ($true) {
    $counter += 1
    $fullEvery = [int]$policy.full_e2e_every_health_checks
    $mode = if (($counter % $fullEvery) -eq 0) { 'full' } else { 'health' }
    $timestamp = (Get-Date).ToString('o')
    Write-Host "[$timestamp] check=$counter mode=$mode" -ForegroundColor Green
    $result = & python (Join-Path $editorRoot 'scripts\live_gemma_e2e_once.py') --lab-root $LabRoot --source $SourcePath --mode $mode 2>&1
    $line = "[$timestamp] $result"
    $line | Tee-Object -FilePath $logPath -Append
    $result | Set-Content -LiteralPath $statusPath -Encoding UTF8
    Start-Sleep -Seconds ([int]$policy.health_interval_seconds)
}
