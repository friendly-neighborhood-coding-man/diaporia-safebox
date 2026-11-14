# SafeBox V6 hardening P0.1: real-sensor checks R1-R4 (docs/v6/hardening/P0-1-SAME-USER-SIGNING.md).
# Uses `winbio-gate.exe identify` only: the helper runs the full gate (Start click, quiet window, capture, Yes/No) and
# SIGNS NOTHING. Each step's instruction is shown on screen first; the helper's JSON result is appended to the log.
# Whether the owner touched the sensor is owner-attested (optionally screen-recorded).
param([string]$Exe = "$PSScriptRoot\winbio-gate.exe", [string]$Log = "$PSScriptRoot\sensor-checks.jsonl")
Add-Type -AssemblyName System.Windows.Forms
$steps = @(
  @{ id = 'R1'; expect = 'TIMEOUT with quietDiscards >= 1'; text = "R1 (stale sample).`n`nClick OK. When the SafeBox gate window appears: TOUCH the sensor and LIFT your finger, then click Start IMMEDIATELY (within 2 s).`nAfter that, keep your hands OFF the sensor until the window closes (about 60 s)." },
  @{ id = 'R2'; expect = 'TIMEOUT with discarded = 0'; text = "R2 (spontaneous match).`n`nClick OK. When the gate window appears, click Start, then keep your hands OFF the sensor and the power button until the window closes (about 60 s)." },
  @{ id = 'R3'; expect = 'BIOMETRIC_TOUCH_DISOWNED'; text = "R3 (the No button).`n`nClick OK. When the gate window appears, click Start, then touch the sensor deliberately.`nWhen asked whether you touched it, answer NO." },
  @{ id = 'R4'; expect = 'MATCH with ownerConfirmed = true'; text = "R4 (honest path).`n`nClick OK. When the gate window appears, click Start, then touch the sensor deliberately.`nWhen asked whether you touched it, answer YES." }
)
foreach ($s in $steps) {
  [void][System.Windows.Forms.MessageBox]::Show($s.text, "SafeBox sensor check $($s.id)", 'OK', 'Information')
  $t0 = Get-Date
  $json = & $Exe identify --timeout 60 --prompt "SafeBox sensor check $($s.id) (nothing is signed)" 2>$null | Select-Object -Last 1
  $rec = [ordered]@{ step = $s.id; expected = $s.expect; startedAt = $t0.ToUniversalTime().ToString('o'); helper = ($json | ConvertFrom-Json) }
  ($rec | ConvertTo-Json -Compress -Depth 5) | Add-Content -Path $Log -Encoding UTF8
  Write-Output "$($s.id): $json"
}
[void][System.Windows.Forms.MessageBox]::Show("Sensor checks done. Results: $Log", 'SafeBox sensor checks', 'OK', 'Information')
