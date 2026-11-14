# SafeBox V6 hardening P0.1 (issue #14): same-user signing probe for the fingerprint-gate key.
#
# Question answered on the REAL laptop: can an ordinary process running as the current Windows user (no helper, no
# fingerprint sensor, no Windows Hello prompt) open the SafeBox gate key and produce a valid signature with it?
#
# Safety properties of this probe:
#  * It only OPENS an existing key by name; it never creates, deletes, exports or modifies a key.
#  * It signs ONE fixed hash: SHA-256("safebox-p0.1-same-user-probe: not a SafeBox statement"). Every SafeBox gate
#    statement is signed as SHA-256(domain || canonical JSON), so this hash can never be a valid gate attestation.
#  * It prints NO signature and no key material: only the key's properties and booleans. It does not touch WinBio,
#    Windows Hello, the network, or any SafeBox file.
#
# Usage (PowerShell, as the same Windows user that enrolled the gate, NOT elevated):
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\winbio-gate\same-user-sign-probe.ps1 [-KeyName SafeBoxGate-k2-laptop]
param([string]$KeyName = 'SafeBoxGate-k2-laptop')
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Core

$msg = [Text.Encoding]::ASCII.GetBytes('safebox-p0.1-same-user-probe: not a SafeBox statement')
$hash = [Security.Cryptography.SHA256]::Create().ComputeHash($msg)
$out = [ordered]@{ probe = 'safebox.v6.p0.1.same-user-sign'; keyName = $KeyName; user = $env:USERNAME
  elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  opened = $false; provider = $null; exportPolicy = $null; uiProtectionLevel = $null; isMachineKey = $null
  signedWithoutFingerprint = $false; signatureVerified = $false; elapsedMs = $null; error = $null }

foreach ($p in @('Microsoft Platform Crypto Provider', 'Microsoft Software Key Storage Provider')) {
  $prov = New-Object Security.Cryptography.CngProvider($p)
  try { if (-not [Security.Cryptography.CngKey]::Exists($KeyName, $prov)) { continue } } catch { continue }
  try {
    $k = [Security.Cryptography.CngKey]::Open($KeyName, $prov)
    $out.opened = $true; $out.provider = $p
    $out.exportPolicy = [string]$k.ExportPolicy
    $out.uiProtectionLevel = [string]$k.UIPolicy.ProtectionLevel
    $out.isMachineKey = $k.IsMachineKey
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $e = New-Object Security.Cryptography.ECDsaCng($k)
    $sig = $e.SignHash($hash)               # no helper, no sensor: just the same-user key handle
    $sw.Stop(); $out.elapsedMs = $sw.ElapsedMilliseconds
    $out.signedWithoutFingerprint = ($sig.Length -gt 0)
    $out.signatureVerified = $e.VerifyHash($hash, $sig)
    [Array]::Clear($sig, 0, $sig.Length)    # never printed
  } catch { $out.error = $_.Exception.GetType().Name + ': ' + $_.Exception.Message }
  break
}
if (-not $out.opened -and -not $out.error) { $out.error = 'KEY_NOT_FOUND (run the gate enrollment first, as this user)' }
$out | ConvertTo-Json -Compress
