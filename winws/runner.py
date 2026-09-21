# winws/runner.py
"""Запуск и мониторинг процесса winws (скрытый, с логом в файл)."""
from __future__ import annotations

import os
import subprocess
import threading
import time
from datetime import datetime
from typing import Any, Dict, Optional

from . import args
from .paths import log_path, tmp_dir

CREATE_NO_WINDOW = 0x08000000
STARTUP_STABLE_SECONDS = 1.2
_STATE = {"state": "stopped", "pid": None, "mode": "", "label": "", "exe": "", "work_dir": "",
          "last_error": "", "started_at": "", "exit_code": None}

_lock = threading.RLock()
_proc: Optional[subprocess.Popen] = None
_watcher: Optional[threading.Thread] = None


def _timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _write_log_line(line: str) -> None:
    try:
        with open(log_path(), "a", encoding="utf-8") as f:
            f.write(f"[{_timestamp()}] {line}\n")
    except OSError:
        pass


def _hidden_popen_kwargs() -> Dict[str, Any]:
    kwargs: Dict[str, Any] = {}
    if os.name == "nt":
        kwargs["creationflags"] = CREATE_NO_WINDOW
        try:
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = subprocess.SW_HIDE
            kwargs["startupinfo"] = si
        except Exception:
            pass
    return kwargs


def _collect_startup_output(proc: subprocess.Popen) -> str:
    data = []
    for stream in (getattr(proc, "stdout", None), getattr(proc, "stderr", None)):
        if stream is None:
            continue
        try:
            chunk = stream.read()
        except Exception:
            chunk = None
        if isinstance(chunk, bytes):
            data.append(chunk.decode("utf-8", errors="replace"))
        elif chunk:
            data.append(str(chunk))
    return " ".join(part.strip() for part in data if part and part.strip())[:300]


def _start_watcher(proc: subprocess.Popen) -> None:
    global _watcher

    def _watch() -> None:
        try:
            code = proc.wait()
        except Exception:
            code = None
        with _lock:
            if _proc is proc:
                _STATE["exit_code"] = int(code) if code is not None else None
                _STATE["state"] = "exited"
                _STATE["pid"] = None
                _write_log_line(f"winws process exited (code {code})")

    _watcher = threading.Thread(target=_watch, name="winws-exit-watcher", daemon=True)
    _watcher.start()


def is_running() -> bool:
    with _lock:
        return _proc is not None and _proc.poll() is None


def _orphaned_engine_pids(exe_dir: str) -> list[int]:
    """PID запущенных winws.exe/winws2.exe из указанного каталога движка.

    Осиротевшие экземпляры появляются, когда предыдущий GUI упал или окно
    закрыли без выхода через трей — движок остаётся и блокирует новый старт
    («A copy of winws2 is already running» → immediate_exit).
    """
    from utils.windows_process_probe import iter_process_module_paths, iter_process_records

    if os.name != "nt":
        return []
    norm_dir = os.path.normcase(os.path.abspath(exe_dir))
    names = {"winws.exe", "winws2.exe"}
    orphaned: list[int] = []
    try:
        for record in iter_process_records():
            name = str(record.get("name") or "").lower()
            if name not in names:
                continue
            pid = int(record.get("pid") or 0)
            if pid <= 0:
                continue
            try:
                module_paths = list(iter_process_module_paths(pid))
            except Exception:
                continue
            exe_path = ""
            for path in module_paths:
                if str(path).lower().endswith(name):
                    exe_path = str(path)
                    break
            if not exe_path:
                continue
            if os.path.normcase(os.path.abspath(exe_path)).startswith(norm_dir):
                orphaned.append(pid)
    except Exception:
        pass
    return orphaned


def _kill_orphaned_engines(exe_dir: str) -> int:
    """Гасит осиротевшие winws/winws2 из каталога движка перед стартом."""
    from utils.process_killer import kill_process_by_pid_winapi

    killed = 0
    with _lock:
        own_pid = _proc.pid if _proc is not None and _proc.poll() is None else None
    for pid in _orphaned_engine_pids(exe_dir):
        if pid == own_pid:
            continue
        if kill_process_by_pid_winapi(pid):
            killed += 1
    if killed:
        time.sleep(0.4)
        _write_log_line(f"killed {killed} orphaned engine process(es) before start")
    return killed


def status() -> Dict[str, Any]:
    with _lock:
        if _proc is not None and _proc.poll() is None:
            _STATE["state"] = "running"
        elif _proc is not None:
            _STATE["state"] = "exited"
        return dict(_STATE)


def start(*, mode: str, exe_path: str, work_dir: str, text: str, label: str = "") -> Dict[str, Any]:
    """Запускает winws с профилем. Возвращает {ok, state, error?, detail?}."""
    global _proc
    validate = args.validate_profile_text(text)
    if validate:
        return {"ok": False, "error": validate}

    missing = args.missing_references(text, work_dir)
    if missing:
        return {
            "ok": False,
            "error": "missing_files",
            "detail": "\n".join(missing[:8]),
        }

    with _lock:
        # Если что-то уже работает — останавливаем перед новым стартом.
        if _proc is not None and _proc.poll() is None:
            stop()

    exe_abs = os.path.abspath(exe_path)
    if not os.path.exists(exe_abs):
        return {"ok": False, "error": "engine_missing"}

    work_dir_abs = os.path.abspath(work_dir)
    _kill_orphaned_engines(work_dir_abs)

    if mode == "winws2":
        try:
            at_config = args.write_at_config(text, str(tmp_dir()), label or mode)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        cmd = [exe_abs, f"@{at_config}"]
    else:
        cmd = [exe_abs, *args.launch_args_from_text(text)]

    log_file_handle = None
    try:
        log_file_handle = open(log_path(), "ab")
    except OSError:
        pass

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=work_dir,
            stdin=subprocess.DEVNULL,
            stdout=log_file_handle,
            stderr=log_file_handle,
            **_hidden_popen_kwargs(),
        )
    except Exception as exc:
        if log_file_handle is not None:
            try:
                log_file_handle.close()
            except Exception:
                pass
        if getattr(exc, "winerror", None) == 740:
            return {"ok": False, "error": "needs_admin",
                    "detail": "Нужны права администратора (WinDivert). Запустите приложение от имени администратора."}
        return {"ok": False, "error": "spawn_failed", "detail": str(exc)}

    with _lock:
        _proc = proc
        _STATE.update({
            "state": "starting",
            "pid": proc.pid,
            "mode": mode,
            "label": label or os.path.basename(exe_abs),
            "exe": exe_abs,
            "work_dir": work_dir,
            "last_error": "",
            "started_at": _timestamp(),
            "exit_code": None,
        })
        _write_log_line(f"Starting {' '.join(cmd[:3])}... (mode={mode}, pid={proc.pid}, cwd={work_dir})")

    # Стабильный старт: процесс должен продержаться несколько секунд.
    stable_deadline = time.monotonic() + STARTUP_STABLE_SECONDS
    while time.monotonic() < stable_deadline:
        time.sleep(0.15)
        if proc.poll() is not None:
            break

    if proc.poll() is not None:
        exit_code = proc.returncode
        output = _collect_startup_output(proc)
        with _lock:
            _proc = None
            _STATE["state"] = "error"
            _STATE["pid"] = None
            _STATE["exit_code"] = int(exit_code) if exit_code is not None else None
            _STATE["last_error"] = f"exit_{exit_code}" + (f": {output}" if output else "")
        _write_log_line(f"winws exited immediately (code {exit_code}): {output}")
        return {"ok": False, "error": "immediate_exit", "code": int(exit_code) if exit_code is not None else None,
                "output": output}

    with _lock:
        _STATE["state"] = "running"
    _start_watcher(proc)
    return {"ok": True, "state": "running", "pid": proc.pid}


def stop(*, kill_timeout: float = 5.0) -> Dict[str, Any]:
    """Мягкая остановка процесса (terminate → kill), затем очистка WinDivert."""
    global _proc
    with _lock:
        proc = _proc
        if proc is None:
            return {"ok": True, "detail": "not_running"}
        pid = proc.pid
        try:
            proc.terminate()
            try:
                proc.wait(timeout=min(max(kill_timeout, 0.5), 5.0))
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    pass
        except Exception:
            pass
        _proc = None
        _STATE.update({"state": "stopped", "pid": None, "exit_code": None})
        _write_log_line(f"winws stopped (pid {pid})")
        return {"ok": True, "detail": "stopped"}


def restart(*, mode: str, exe_path: str, work_dir: str, text: str, label: str = "") -> Dict[str, Any]:
    """Останавливает текущий процесс и запускает заново."""
    with _lock:
        if _proc is not None:
            stop()
    return start(mode=mode, exe_path=exe_path, work_dir=work_dir, text=text, label=label)


def kill_all() -> Dict[str, Any]:
    """Принудительно гасит все процессы winws.exe/winws2.exe (например, при выходе)."""
    global _proc
    if os.name != "nt":
        return {"ok": True, "detail": "skipped"}
    killed = 0
    with _lock:
        proc = _proc
        if proc is not None:
            try:
                proc.kill()
            except Exception:
                pass
            _proc = None
            killed += 1
    try:
        import subprocess as _sp
        for name in ("winws.exe", "winws2.exe"):
            try:
                result = _sp.run(["taskkill", "/F", "/IM", name], capture_output=True, timeout=10)
                if result.returncode == 0:
                    killed += 1
            except Exception:
                continue
    except Exception:
        pass
    with _lock:
        _STATE.update({"state": "stopped", "pid": None})
    return {"ok": True, "detail": f"killed={killed}"}