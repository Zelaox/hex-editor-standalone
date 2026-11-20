param(
    [string]$PythonCommand = 'python',
    [switch]$WithMcp,
    [switch]$WithTests
)
$ErrorActionPreference = 'Stop'
$environmentRoot = Join-Path $PSScriptRoot '.venv'
$environmentPython = Join-Path $environmentRoot 'Scripts/python.exe'
if (-not (Test-Path -LiteralPath $environmentPython)) {
    & $PythonCommand -m venv $environmentRoot
    if ($LASTEXITCODE -ne 0) { throw 'Virtual environment creation failed.' }
}
$requirementsName = 'requirements.txt'
if ($WithMcp) { $requirementsName = 'requirements-mcp.txt' }
if ($WithTests) { $requirementsName = 'requirements-dev.txt' }
& $environmentPython -m pip install -r (Join-Path $PSScriptRoot $requirementsName)
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
Write-Output "Installed Hex Editor dependencies in $environmentRoot"
Write-Output "GUI: `"$environmentPython`" `"$(Join-Path $PSScriptRoot 'main.py')`""
