$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$taskVersion = '2.17.0'
$taskExpectedHash = '94c8f767b1c2e94f0db66b3ae56514d5e3f5a728ee1b6c798e0c8fe2d61fbff0'
New-Item -ItemType Directory -Force -Path '.tools' | Out-Null
$taskArchive = Join-Path $PSScriptRoot '.tools/ZAP_2.17.0_Crossplatform.zip'
if (-not (Test-Path -LiteralPath $taskArchive)) {
    Invoke-WebRequest -Uri "https://github.com/zaproxy/zaproxy/releases/download/v$taskVersion/ZAP_${taskVersion}_Crossplatform.zip" -OutFile $taskArchive -UseBasicParsing
}
if ((Get-FileHash -LiteralPath $taskArchive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $taskExpectedHash) { throw 'The scanner checksum does not match the official release. Nothing was installed.' }
Expand-Archive -LiteralPath $taskArchive -DestinationPath (Join-Path $PSScriptRoot '.tools') -Force
Write-Host 'Official ZAP 2.17.0 is ready. Java 17+ must be on PATH. Restart the app and worker.'
