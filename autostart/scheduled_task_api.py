from __future__ import annotations

import ctypes
import locale
import logging
import ntpath
import os
import re
import subprocess
import tempfile
from ctypes import wintypes
from html import escape as escape_xml_text, unescape as unescape_xml_text
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .model import StartEntry

log = logging.getLogger("swift-autostart")

AUTOSTART_TASK_NAME = "PrimeProxy Autostart"
_TASK_XML_NAMESPACE = "http://schemas.microsoft.com/windows/2004/02/mit/task"
_NAME_SAM_COMPATIBLE = 2
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _current_user_id() -> str:
    if os.name != "nt":
        return (os.environ.get("USERDOMAIN", "") + "\\" if os.environ.get("USERDOMAIN") else "") + os.environ.get("USERNAME", "")
    try:
        size = wintypes.ULONG(256)
        buffer = ctypes.create_unicode_buffer(size.value)
        get_user_name = ctypes.windll.secur32.GetUserNameExW
        if get_user_name(_NAME_SAM_COMPATIBLE, buffer, ctypes.byref(size)):
            value = buffer.value.strip()
            if value:
                return value
        if size.value > len(buffer):
            buffer = ctypes.create_unicode_buffer(size.value)
            if get_user_name(_NAME_SAM_COMPATIBLE, buffer, ctypes.byref(size)):
                value = buffer.value.strip()
                if value:
                    return value
    except Exception:
        pass
    user = os.environ.get("USERNAME", "").strip()
    domain = os.environ.get("USERDOMAIN", "").strip()
    if not user:
        raise OSError("Windows не вернул имя текущего пользователя")
    return f"{domain}\\{user}" if domain else user


def _schtasks_executable() -> str:
    windows_root = os.environ.get("SystemRoot", r"C:\Windows").strip()
    return ntpath.join(windows_root, "System32", "schtasks.exe")


def _run_schtasks(arguments: list) -> "subprocess.CompletedProcess[bytes]":
    return subprocess.run(
        [_schtasks_executable(), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        creationflags=_NO_WINDOW,
    )


def _decode_process_output(data: Optional[bytes]) -> str:
    if not data:
        return ""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        candidates = ("utf-16",)
    elif data.startswith(b"<\x00") or data.count(b"\x00") > len(data) // 4:
        candidates = ("utf-16-le", "utf-16")
    else:
        candidates = (
            "utf-8-sig",
            locale.getpreferredencoding(False),
            "mbcs",
            "cp866",
        )
    for encoding in candidates:
        try:
            return data.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return data.decode("utf-8", errors="replace")


def _build_autostart_task_xml(entry: StartEntry, user_id: str) -> bytes:
    command = str(entry.command or "").strip()
    if not command:
        raise ValueError("Для задачи автозапуска не указан исполняемый файл")
    user_id = str(user_id or "").strip()
    if not user_id:
        raise ValueError("Для задачи автозапуска не определён текущий пользователь")
    working_directory = (entry.working_dir or os.path.dirname(command) or "").strip()
    arguments = subprocess.list2cmdline([str(a) for a in (entry.args or [])])
    run_level = "HighestAvailable" if str(entry.run_level or "highest").lower() in (
        "highest", "high", "admin", "elevated") else "LeastPrivilege"
    description = entry.description or f"Автозапуск {entry.name} при входе в Windows"

    escaped_user = escape_xml_text(user_id, quote=False)
    escaped_exe = escape_xml_text(command, quote=False)
    escaped_working_directory = escape_xml_text(working_directory, quote=False)
    escaped_arguments = escape_xml_text(arguments, quote=False)
    escaped_description = escape_xml_text(description, quote=False)

    task_xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="{_TASK_XML_NAMESPACE}">
  <RegistrationInfo>
    <Author>PrimeProxy</Author>
    <Description>{escaped_description}</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{escaped_user}</UserId>
      <Delay>PT3S</Delay>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{escaped_user}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>{run_level}</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <Enabled>true</Enabled>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>5</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{escaped_exe}</Command>
      <Arguments>{escaped_arguments}</Arguments>
      <WorkingDirectory>{escaped_working_directory}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"""
    return task_xml.encode("utf-16")


def _format_schtasks_error(result: "subprocess.CompletedProcess[bytes]") -> str:
    detail = _decode_process_output(result.stderr).strip()
    if not detail:
        detail = _decode_process_output(result.stdout).strip()
    return detail or f"schtasks.exe завершился с кодом {result.returncode}"


def create_or_update_autostart_task(
    entry: StartEntry,
    *,
    task_name: Optional[str] = None,
) -> bool:
    task_name = (task_name or entry.name) if entry else task_name
    name = str(task_name or "").strip()
    if not entry or os.name != "nt":
        return False
    temporary_path: Optional[Path] = None
    try:
        task_xml = _build_autostart_task_xml(entry, _current_user_id())
        with tempfile.NamedTemporaryFile(
            mode="wb",
            suffix=".xml",
            prefix="primeproxy-autostart-",
            delete=False,
        ) as temporary:
            temporary.write(task_xml)
            temporary_path = Path(temporary.name)

        result = _run_schtasks(["/Create", "/TN", name, "/XML", str(temporary_path), "/F"])
        if result.returncode == 0:
            return True
        log.warning("Autostart task create failed: %s", _format_schtasks_error(result))
        return False
    except Exception as exc:
        log.warning("Autostart task create failed: %s", exc)
        return False
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass


def _first_task_action(xml_text: str) -> Optional[Tuple[str, str]]:
    prefix = r"(?:[A-Za-z_][\w.-]*:)?"
    execute = re.search(
        rf"<{prefix}Exec\b[^>]*>(.*?)</{prefix}Exec\s*>",
        xml_text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if execute is None:
        return None

    def _value(name: str) -> str:
        match = re.search(
            rf"<{prefix}{name}\b[^>]*>(.*?)</{prefix}{name}\s*>",
            execute.group(1),
            flags=re.IGNORECASE | re.DOTALL,
        )
        return unescape_xml_text(match.group(1)).strip() if match else ""

    command = _value("Command")
    return (command, _value("Arguments")) if command else None


def get_autostart_task_action(*, task_name: str = AUTOSTART_TASK_NAME) -> Optional[Tuple[str, str]]:
    if os.name != "nt":
        return None
    try:
        result = _run_schtasks(["/Query", "/TN", task_name, "/XML", "ONE"])
        if result.returncode != 0:
            return None
        return _first_task_action(_decode_process_output(result.stdout))
    except Exception:
        return None


def get_task_info(*, task_name: str = AUTOSTART_TASK_NAME) -> Optional[Dict[str, Any]]:
    action = get_autostart_task_action(task_name=task_name)
    if action is None:
        return None
    return {
        "exists": True,
        "name": task_name,
        "command": action[0],
        "arguments": action[1],
    }


def autostart_task_exists(*, task_name: str = AUTOSTART_TASK_NAME) -> bool:
    return get_autostart_task_action(task_name=task_name) is not None


def delete_autostart_task(*, task_name: str = AUTOSTART_TASK_NAME) -> bool:
    if os.name != "nt":
        return False
    try:
        result = _run_schtasks(["/Delete", "/TN", task_name, "/F"])
        if result.returncode == 0:
            return True
        log.debug("Autostart task delete skipped: %s", _format_schtasks_error(result))
        return False
    except Exception as exc:
        log.debug("Autostart task delete skipped: %s", exc)
        return False


task_exists = autostart_task_exists
create_task = create_or_update_autostart_task
delete_task = delete_autostart_task