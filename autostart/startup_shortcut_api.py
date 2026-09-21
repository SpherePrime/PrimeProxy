from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

from .model import StartEntry

log = logging.getLogger("swift-autostart")

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def get_user_startup_dir() -> str:
    if os.name != "nt":
        return ""
    appdata = os.environ.get("APPDATA", "").strip()
    root = appdata or str(Path.home())
    return str(Path(root) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")


def get_startup_shortcut_path(*, shortcut_name: str = "SwiftProxy") -> str:
    name = str(shortcut_name or "").strip() + ".lnk"
    startup = get_user_startup_dir()
    return str(Path(startup) / name)


def _run_powershell(script: str) -> int:
    powershell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    exe = str(powershell) if powershell.exists() else (shutil.which("powershell.exe") or "powershell.exe")
    run = subprocess.run(
        [exe, "-NoProfile", "-NonInteractive", "-Command", script],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        creationflags=_NO_WINDOW,
    )
    return run.returncode


def _ps_script(entry: StartEntry, shortcut_path: str) -> str:
    import json
    lines = [
        "$shell = New-Object -ComObject WScript.Shell",
        f"$shortcut = $shell.CreateShortcut({json.dumps(shortcut_path)})",
        f"$shortcut.TargetPath = {json.dumps(str(entry.command).strip())}",
    ]
    if entry.working_dir:
        lines.append(f"$shortcut.WorkingDirectory = {json.dumps(str(entry.working_dir).strip())}")
    if entry.args:
        args = " ".join(_powershell_quote(str(a)) for a in entry.args)
        lines.append(f"$shortcut.Arguments = {json.dumps(args)}")
    icon = str(entry.command).strip()
    lines.append(f"$shortcut.IconLocation = {json.dumps(icon)}")
    lines.append("$shortcut.Save()")
    return "\n".join(lines)


def _powershell_quote(value: str) -> str:
    escaped = value.replace("`", "``").replace('"', '`"')
    return '"' + escaped + '"'


def startup_shortcut_exists(*, shortcut_path: Optional[str] = None) -> bool:
    path = Path(shortcut_path or get_startup_shortcut_path()).resolve()
    return path.exists()


def create_startup_shortcut(entry: StartEntry, *, shortcut_path: Optional[str] = None) -> Dict[str, Any]:
    if os.name != "nt":
        return {"ok": False, "error": "not_windows"}
    path = Path(shortcut_path or get_startup_shortcut_path()).resolve()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return {"ok": False, "error": str(exc)}
    try:
        import win32com.client
    except ImportError:
        pass
    else:
        try:
            shell = win32com.client.Dispatch("WScript.Shell")
            shortcut = shell.CreateShortcut(str(path))
            shortcut.TargetPath = str(entry.command).strip()
            shortcut.WorkingDirectory = (entry.working_dir or "").strip()
            shortcut.Arguments = subprocess.list2cmdline([str(a) for a in (entry.args or [])])
            shortcut.save()
            return {"ok": True, "path": str(path)}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
    return_code = _run_powershell(_ps_script(entry, str(path)))
    if return_code == 0:
        return {"ok": True, "path": str(path)}
    return {"ok": False, "error": f"powershell завершился с кодом {return_code}"}


def get_startup_shortcut_info(*, shortcut_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    path = Path(shortcut_path or get_startup_shortcut_path())
    if not path.exists():
        return None
    return {"exists": True, "path": str(path.resolve()), "target": None}


def delete_startup_shortcut(*, shortcut_path: Optional[str] = None) -> bool:
    path = Path(shortcut_path or get_startup_shortcut_path())
    if not path.exists():
        return True
    try:
        path.unlink(missing_ok=True)
        return True
    except OSError:
        return False


task_exists = startup_shortcut_exists
create_task = create_startup_shortcut
delete_task = delete_startup_shortcut
get_task_info = get_startup_shortcut_info