#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
$AgentDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Python = Join-Path $AgentDir ".venv\Scripts\python.exe"
& $Python (Join-Path $AgentDir "agentctl.py") uninstall
Unregister-ScheduledTask -TaskName "ChildGuard Tray UI" -Confirm:$false -ErrorAction SilentlyContinue
Write-Host "Service and TrayUI removed. agent_state was preserved for recovery; a parent may delete it manually."

