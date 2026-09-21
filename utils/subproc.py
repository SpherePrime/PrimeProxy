from __future__ import annotations

import os
import shlex
import subprocess
import sys
import time
from typing import List, Optional, Sequence, Union

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _prepare_cmd(command, shell: bool = False) -> Union[List[str], str]:
    if command is None:
        return ""
    if isinstance(command, str):
        if shell:
            return command
        return shlex.split(command) if command.strip() else ""
    return list(command)


def run_hidden(
    command,
    *,
    shell: bool = False,
    cwd: Optional[str] = None,
    timeout: float = 60.0,
    capture_output: bool = False,
    check: bool = False,
    encoding: str = "utf-8",
    errors: str = "replace",
) -> subprocess.CompletedProcess:
    cmd = _prepare_cmd(command, shell=shell)
    kwargs: dict = {
        "cwd": cwd,
        "timeout": timeout,
        "creationflags": _NO_WINDOW,
    }
    kwargs["shell"] = shell
    if capture_output:
        kwargs["capture_output"] = True
    kwargs["text"] = True
    kwargs["encoding"] = encoding
    kwargs["errors"] = errors
    try:
        return subprocess.run(cmd, **kwargs)
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"Команда не найдена: {exc}") from exc


def run_hidden_checked(command, **kwargs) -> subprocess.CompletedProcess:
    kwargs.setdefault("check", True)
    return run_hidden(command, **kwargs)


def run_with_timeout(command, timeout: float = 60.0, **kwargs) -> subprocess.CompletedProcess:
    kwargs.setdefault("timeout", timeout)
    return run_hidden(command, **kwargs)


def get_system32_path() -> str:
    system_root = os.environ.get("SystemRoot")
    if system_root:
        return os.path.join(system_root, "System32")
    return os.path.join("C:", "Windows", "System32")


def get_syswow64_path() -> str:
    system_root = os.environ.get("SystemRoot")
    if system_root:
        return os.path.join(system_root, "SysWOW64")
    return os.path.join("C:", "Windows", "SysWOW64")


def is_process_alive(pid: int) -> bool:
    try:
        proc = subprocess.run(
            ["tasklist", "/FI", f"PID eq {int(pid)}", "/NH"],
            capture_output=True, text=True, timeout=15, creationflags=_NO_WINDOW,
        )
        return str(pid) in (proc.stdout or "")
    except Exception:
        return False


def wait_process_exit(pid: int, timeout_s: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if not is_process_alive(pid):
            return True
        time.sleep(0.1)
    return not is_process_alive(pid)