from __future__ import annotations

import getpass
import os
import platform
import socket
import sqlite3
import winreg
from pathlib import Path
from typing import Any

from .utils import EXECUTABLE_EXTENSIONS, file_metadata, ps_json, run_powershell, safe_glob

try:
    import psutil
except Exception:  # pragma: no cover - optional dependency
    psutil = None


class WindowsCollector:
    def collect_all(self) -> dict[str, Any]:
        return {
            "system": self.system_info(),
            "installed_software": self.installed_software(),
            "processes": self.processes(),
            "services": self.services(),
            "startup_entries": self.startup_entries(),
            "scheduled_tasks": self.scheduled_tasks(),
            "user_accounts": self.user_accounts(),
            "usb_history": self.usb_history(),
            "browser_artifacts": self.browser_artifacts(),
            "event_logs": self.event_logs(),
            "network_connections": self.network_connections(),
            "recent_files": self.recent_files(),
            "downloads": self.downloads(),
        }

    def system_info(self) -> dict[str, Any]:
        return {
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "user": getpass.getuser(),
            "cwd": os.getcwd(),
        }

    def installed_software(self) -> list[dict[str, Any]]:
        roots = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]
        software: list[dict[str, Any]] = []
        for hive, key_path in roots:
            try:
                with winreg.OpenKey(hive, key_path) as key:
                    for index in range(winreg.QueryInfoKey(key)[0]):
                        try:
                            sub_name = winreg.EnumKey(key, index)
                            with winreg.OpenKey(key, sub_name) as sub:
                                item = {"registry_key": key_path + "\\" + sub_name}
                                for value in ["DisplayName", "DisplayVersion", "Publisher", "InstallDate", "InstallLocation"]:
                                    try:
                                        item[value] = winreg.QueryValueEx(sub, value)[0]
                                    except OSError:
                                        pass
                                if item.get("DisplayName"):
                                    software.append(item)
                        except OSError:
                            continue
            except OSError:
                continue
        return software

    def processes(self) -> list[dict[str, Any]]:
        if psutil:
            items = []
            for proc in psutil.process_iter(["pid", "ppid", "name", "username", "exe", "cmdline", "create_time"]):
                try:
                    row = proc.info
                    exe = row.get("exe")
                    if exe:
                        row["file"] = file_metadata(exe, hash_content=False)
                    items.append(row)
                except Exception:
                    continue
            return items
        return ps_json("Get-Process | Select-Object Id,ProcessName,Path,StartTime", timeout=30)

    def services(self) -> list[dict[str, Any]]:
        return ps_json("Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName,StartName", timeout=45)

    def startup_entries(self) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]
        for hive, key_path in keys:
            try:
                with winreg.OpenKey(hive, key_path) as key:
                    for index in range(winreg.QueryInfoKey(key)[1]):
                        try:
                            name, value, _ = winreg.EnumValue(key, index)
                            entries.append({"source": "registry", "key": key_path, "name": name, "command": value})
                        except OSError:
                            continue
            except OSError:
                continue
        startup_dirs = [
            Path(os.environ.get("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup",
            Path(os.environ.get("PROGRAMDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup",
        ]
        for item in safe_glob(startup_dirs, ["*"], limit=1000):
            entries.append({"source": "startup_folder", "name": item.get("name"), "path": item.get("path"), "file": item})
        return entries

    def scheduled_tasks(self) -> list[dict[str, Any]]:
        return ps_json("Get-ScheduledTask | Select-Object TaskName,TaskPath,State,Author,Description", timeout=60)

    def user_accounts(self) -> list[dict[str, Any]]:
        data = ps_json("Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordLastSet,PasswordRequired,UserMayChangePassword", timeout=30)
        if data:
            return data
        ok, output = run_powershell("net user", timeout=20)
        return [{"raw": output}] if ok else []

    def usb_history(self) -> list[dict[str, Any]]:
        devices: list[dict[str, Any]] = []
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\USBSTOR") as key:
                for index in range(winreg.QueryInfoKey(key)[0]):
                    family = winreg.EnumKey(key, index)
                    with winreg.OpenKey(key, family) as family_key:
                        for child_index in range(winreg.QueryInfoKey(family_key)[0]):
                            instance = winreg.EnumKey(family_key, child_index)
                            devices.append({"device": family, "instance": instance})
        except OSError:
            pass
        return devices

    def browser_artifacts(self) -> dict[str, Any]:
        local = Path(os.environ.get("LOCALAPPDATA", ""))
        roaming = Path(os.environ.get("APPDATA", ""))
        paths = {
            "chrome": local / r"Google\Chrome\User Data\Default",
            "edge": local / r"Microsoft\Edge\User Data\Default",
            "firefox": roaming / r"Mozilla\Firefox\Profiles",
        }
        artifacts: dict[str, Any] = {}
        for name, base in paths.items():
            artifacts[name] = []
            candidates = [base] if name != "firefox" else list(base.glob("*")) if base.exists() else []
            for profile in candidates:
                for artifact in ["History", "Cookies", "Login Data", "Downloads.sqlite", "places.sqlite"]:
                    p = profile / artifact
                    if p.exists():
                        meta = file_metadata(p, hash_content=False)
                        meta["profile"] = str(profile)
                        artifacts[name].append(meta)
        return artifacts

    def event_logs(self) -> list[dict[str, Any]]:
        script = (
            "Get-WinEvent -FilterHashtable @{LogName='System','Application','Security'; StartTime=(Get-Date).AddDays(-7)} "
            "-MaxEvents 300 | Select-Object TimeCreated,LogName,Id,ProviderName,LevelDisplayName,Message"
        )
        return ps_json(script, timeout=90)

    def network_connections(self) -> list[dict[str, Any]]:
        if psutil:
            rows = []
            for conn in psutil.net_connections(kind="inet"):
                rows.append(
                    {
                        "fd": conn.fd,
                        "family": str(conn.family),
                        "type": str(conn.type),
                        "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                        "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                        "status": conn.status,
                        "pid": conn.pid,
                    }
                )
            return rows
        return ps_json("Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess", timeout=30)

    def recent_files(self) -> list[dict[str, Any]]:
        recent = Path(os.environ.get("APPDATA", "")) / r"Microsoft\Windows\Recent"
        return safe_glob([recent], ["*"], limit=2000)

    def downloads(self) -> list[dict[str, Any]]:
        downloads = Path.home() / "Downloads"
        patterns = ["*"]
        return safe_glob([downloads], patterns, limit=3000)


class EmailCollector:
    def collect_all(self) -> dict[str, Any]:
        return {
            "outlook_data_files": self.outlook_data_files(),
            "mail_client_configs": self.mail_client_configs(),
            "suspicious_attachments": self.suspicious_attachments(),
            "phishing_indicators": self.phishing_indicators(),
        }

    def outlook_data_files(self) -> list[dict[str, Any]]:
        bases = [Path.home() / "Documents" / "Outlook Files", Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "Outlook"]
        return safe_glob(bases, ["*.pst", "*.ost"], limit=1000)

    def mail_client_configs(self) -> list[dict[str, Any]]:
        bases = [
            Path(os.environ.get("APPDATA", "")) / "Thunderbird" / "Profiles",
            Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Outlook",
            Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "Outlook",
        ]
        return safe_glob(bases, ["*.ini", "*.xml", "*.json", "*.dat"], limit=1000)

    def suspicious_attachments(self) -> list[dict[str, Any]]:
        bases = [
            Path.home() / "Downloads",
            Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "Windows" / "INetCache" / "Content.Outlook",
        ]
        patterns = [f"*{ext}" for ext in EXECUTABLE_EXTENSIONS | {".zip", ".rar", ".7z", ".iso", ".img", ".docm", ".xlsm"}]
        return safe_glob(bases, patterns, limit=2000)

    def phishing_indicators(self) -> list[dict[str, Any]]:
        indicators = []
        for item in self.suspicious_attachments():
            name = str(item.get("name", "")).lower()
            if any(token in name for token in ["invoice", "payment", "urgent", "password", "verify", "statement"]):
                indicators.append({"indicator": "social-engineering filename token", "artifact": item})
        return indicators
