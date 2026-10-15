param([int]$Port = 5000)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$taskPython = Join-Path $PSScriptRoot '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $taskPython)) { throw 'Run .\setup.ps1 first.' }
if ($Port -lt 1024 -or $Port -gt 65535) { throw 'Choose a port between 1024 and 65535.' }
New-Item -ItemType Directory -Force -Path 'instance' | Out-Null
& $taskPython -m flask --app app init-db
if ($LASTEXITCODE -ne 0) { throw 'Database initialization failed.' }
$taskWorker = Start-Process -FilePath $taskPython -ArgumentList '-m','flask','--app','app','worker' -WorkingDirectory $PSScriptRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $PSScriptRoot 'instance/worker-out.log') -RedirectStandardError (Join-Path $PSScriptRoot 'instance/worker-error.log')
try {
    Write-Host "VulnTrack is starting at http://127.0.0.1:$Port"
    Write-Host 'Keep this terminal open. Press Ctrl+C to stop the application and its worker.'
    & $taskPython -m waitress "--listen=127.0.0.1:$Port" '--threads=4' 'app:app'
} finally {
    if (-not $taskWorker.HasExited) { Stop-Process -InputObject $taskWorker -ErrorAction SilentlyContinue }
}
