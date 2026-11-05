$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Set-Location -LiteralPath $root
$log = Join-Path $root '.test-results\windows-admin.txt'
$result = Join-Path $root '.test-results\windows-admin.exit'
try {
    & (Join-Path $PSScriptRoot 'aidns_windows_integration.ps1') -Assembly (Join-Path $root 'src\ZapretHub\bin\Release\net8.0-windows10.0.17763.0\win-x64\ZapretHub.dll') -OutputDirectory (Join-Path $root '.test-results\windows') *>&1 | Out-File -LiteralPath $log -Encoding utf8
    [IO.File]::WriteAllText($result, '0')
} catch {
    $_ | Out-String | Out-File -LiteralPath $log -Encoding utf8 -Append
    [IO.File]::WriteAllText($result, '1')
    exit 1
}
