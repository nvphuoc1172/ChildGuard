"""Windows Service wrapper for ChildGuard Agent Core."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import servicemanager
import win32event
import win32service
import win32serviceutil


class ChildGuardService(win32serviceutil.ServiceFramework):
    _svc_name_ = "ChildGuardAgent"
    _svc_display_name_ = "ChildGuard Agent Protection"
    _svc_description_ = "ChildGuard background policy, screen-time and sync service"

    def __init__(self, args):
        super().__init__(args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.child = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
        if self.child and self.child.poll() is None:
            self.child.terminate()

    def SvcDoRun(self):
        agent_dir = Path(__file__).resolve().parent
        log_path = agent_dir / "agent_state" / "service.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        python_exe = agent_dir / ".venv" / "Scripts" / "python.exe"
        command = [
            str(python_exe),
            str(agent_dir / "run_agent.py"),
            "--no-elevate",
            "--no-tray",
            "--state", str(agent_dir / "agent_state" / "device_token.json"),
            "--ca-cert", str(agent_dir / "certs" / "ogk-ca.crt"),
        ]
        with log_path.open("a", encoding="utf-8") as log:
            self.child = subprocess.Popen(
                command, cwd=str(agent_dir), stdin=subprocess.DEVNULL,
                stdout=log, stderr=subprocess.STDOUT,
            )
            servicemanager.LogInfoMsg("ChildGuard Agent Core started")
            while win32event.WaitForSingleObject(self.stop_event, 2000) == win32event.WAIT_TIMEOUT:
                if self.child.poll() is not None:
                    raise RuntimeError(f"Agent Core exited with code {self.child.returncode}")


if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(ChildGuardService)

