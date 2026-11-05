param([Parameter(Mandatory=$true)][string]$Assembly)
$ErrorActionPreference = 'Stop'
[Reflection.Assembly]::LoadFrom((Resolve-Path $Assembly)) | Out-Null
$type = [Reflection.Assembly]::LoadFrom((Resolve-Path $Assembly)).GetType('ZapretHub.AiDnsPolicy')
$flags = [Reflection.BindingFlags]'NonPublic, Static'
$token = $type.GetMethod('NewToken', $flags).Invoke($null, @())
$install = $type.GetMethod('InstallScript', $flags).Invoke($null, @($token))
$cleanup = $type.GetMethod('Script', $flags).Invoke($null, @($token)) + "`nCleanup"
$staleCleanup = $type.GetMethod('Script', $flags).Invoke($null, @($null)) + "`nCleanup"
$script:rules = @()
$script:override = $false
$script:removed = @()
$script:flushes = 0
function Get-DnsClientNrptRule { [CmdletBinding()]param() return $script:rules }
function Get-DnsClientNrptPolicy {
    [CmdletBinding()]
    param([switch]$Effective)
    if ($script:override) { return @() }
    return $script:rules
}
function Add-DnsClientNrptRule {
    [CmdletBinding()]
    param([string[]]$Namespace, [string]$NameServers, [string]$DisplayName, [string]$Comment)
    $script:rules += [pscustomobject]@{ Name = [guid]::NewGuid().ToString(); Namespace = $Namespace; NameServers = $NameServers; DisplayName = $DisplayName; Comment = $Comment }
}
function Remove-DnsClientNrptRule {
    [CmdletBinding()]
    param([string]$Name, [switch]$Force, [switch]$Confirm)
    $script:removed += $Name
    $script:rules = @($script:rules | Where-Object { $_.Name -ne $Name })
}
function Clear-DnsClientCache { [CmdletBinding()]param() $script:flushes++ }
function Check([string]$name, [bool]$condition) {
    if (-not $condition) { throw "FAIL $name" }
    Write-Output "PASS $name"
}
foreach ($code in @($install, $cleanup, $staleCleanup)) {
    $tokens = $null; $errors = $null
    [Management.Automation.Language.Parser]::ParseInput($code, [ref]$tokens, [ref]$errors) | Out-Null
    Check 'Policy script parses' ($errors.Count -eq 0)
}
$corp = [pscustomobject]@{ Name = 'corporate-rule'; Namespace = @('.nau-ra.local'); NameServers = '192.0.2.53'; DisplayName = 'Corporate'; Comment = 'Do not touch' }
$root = [pscustomobject]@{ Name = 'vpn-rule'; Namespace = @('.'); NameServers = '198.18.0.2'; DisplayName = 'VPN'; Comment = 'Do not touch' }
$script:rules = @($corp, $root)
& ([scriptblock]::Create($install))
Check 'Install adds only one AI rule' ($script:rules.Count -eq 3)
Check 'Corporate and VPN rules preserved' ($script:rules[0] -eq $corp -and $script:rules[1] -eq $root -and $script:removed.Count -eq 0)
& ([scriptblock]::Create($staleCleanup))
Check 'Stale cleanup preserves a live owner' ($script:rules.Count -eq 3)
& ([scriptblock]::Create($cleanup))
Check 'Disable removes only its own rule' ($script:rules.Count -eq 2 -and $script:rules[0] -eq $corp -and $script:rules[1] -eq $root)
& ([scriptblock]::Create($cleanup))
Check 'Cleanup is idempotent' ($script:removed.Count -eq 1)
$script:override = $true
$threw = $false
try { & ([scriptblock]::Create($install)) } catch { $threw = $true }
Check 'Overridden rule fails and rolls back' ($threw -and $script:rules.Count -eq 2)
$script:override = $false
$conflict = [pscustomobject]@{ Name = 'existing-ai-rule'; Namespace = @('.Google.COM'); NameServers = '192.0.2.1'; DisplayName = 'Other'; Comment = '' }
$script:rules += $conflict
$threw = $false
try { & ([scriptblock]::Create($install)) } catch { $threw = $true }
Check 'Existing overlapping policy is preserved' ($threw -and $script:rules.Count -eq 3 -and $script:rules[2] -eq $conflict)
$script:rules = @($corp, $root)
& ([scriptblock]::Create($install))
$own = $script:rules[2]
$own.Comment = 'ZapretHub.AiDns.Split.v1:2147483646:1:' + [guid]::NewGuid().ToString('N')
& ([scriptblock]::Create($staleCleanup))
Check 'Abandoned rule is removed after owner exits' ($script:rules.Count -eq 2)
& ([scriptblock]::Create($install))
$script:rules[2].Namespace += '.unrelated.example'
$threw = $false
try { & ([scriptblock]::Create($cleanup)) } catch { $threw = $true }
Check 'Externally modified rule is preserved and cleanup reports failure' ($threw -and $script:rules.Count -eq 3)
Write-Output 'All policy mock checks passed; no Windows DNS settings were changed.'
