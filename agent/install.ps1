#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
$AgentDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $AgentDir

if (-not (Test-Path -LiteralPath ".venv\Scripts\python.exe")) {
    py -3 -m venv .venv
}
$Python = Join-Path $AgentDir ".venv\Scripts\python.exe"
& $Python -m pip install --upgrade pip
& $Python -m pip install -r requirements.txt

if (-not (Test-Path -LiteralPath "agent_state\device_token.json")) {
    Write-Host "No enrollment state found. Enter a pairing code now."
    & $Python enroll.py --server (Read-Host "IP server") --ca-cert "certs\ogk-ca.crt"
    if ($LASTEXITCODE -ne 0) { throw "Enrollment failed." }
}

& $Python agentctl.py set-password
& $Python windows_service.py --startup auto install
sc.exe failure ChildGuardAgent reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
sc.exe start ChildGuardAgent | Out-Null

$TrayScript = Join-Path $AgentDir "tray\tray_app.py"
$Pythonw = Join-Path $AgentDir ".venv\Scripts\pythonw.exe"
$Action = New-ScheduledTaskAction -Execute $Pythonw -Argument ('"' + $TrayScript + '"') -WorkingDirectory $AgentDir
$Trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "ChildGuard Tray UI" -Action $Action -Trigger $Trigger -Description "Transparent ChildGuard status for the signed-in child" -Force | Out-Null
Start-ScheduledTask -TaskName "ChildGuard Tray UI"

Write-Host "ChildGuard is installed and running. Use agentctl.py to stop or remove it."

