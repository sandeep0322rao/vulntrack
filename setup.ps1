param([switch]$Demo)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
if (-not (Test-Path -LiteralPath '.venv/Scripts/python.exe')) {
    python -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw 'Virtual environment creation failed.' }
}
& '.venv/Scripts/python.exe' -m pip install -r requirements.lock.txt
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
& '.venv/Scripts/python.exe' -m flask --app app init-db
if ($LASTEXITCODE -ne 0) { throw 'Database initialization failed.' }
if ($Demo) {
    & '.venv/Scripts/python.exe' -m flask --app app setup-demo
} else {
    & '.venv/Scripts/python.exe' -m flask --app app create-admin
}
if ($LASTEXITCODE -ne 0) { throw 'Account setup did not complete. See the message above.' }
Write-Host 'Ready. Run .\start.ps1 to start the app and passive check worker.'
