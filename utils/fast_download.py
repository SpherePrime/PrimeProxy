from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Sequence, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .hardened_file_ops import _atomic_write_bytes

USER_AGENT = "prime-proxy"
READ_CHUNK = 1024 * 1024
DEFAULT_TIMEOUT = (10, 30)
DEFAULT_ATTEMPTS = 2


def _timeout_value(timeout: Any) -> float:
    if isinstance(timeout, (tuple, list)) and timeout:
        return float(timeout[0])
    return float(timeout)


def _open(url: str, timeout: Any):
    request = Request(url, headers={"User-Agent": USER_AGENT})
    return urlopen(request, timeout=_timeout_value(timeout))


def _cleanup(path: Path) -> None:
    try:
        if path.exists():
            path.unlink()
    except OSError:
        pass


def _describe_error(exc: Exception) -> str:
    if isinstance(exc, HTTPError):
        return f"HTTP {exc.code}"
    message = str(exc)
    return message or exc.__class__.__name__


def _result(
    ok: bool,
    path: Optional[str],
    size: int,
    started: float,
    error: Optional[str],
    errors: Optional[Sequence[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    return {
        "ok": bool(ok),
        "path": path,
        "size": int(size),
        "elapsed": round(time.monotonic() - started, 3),
        "error": error,
        "errors": list(errors) if errors else [],
    }


def download(
    url: str,
    dest,
    *,
    sha256: Optional[str] = None,
    timeout: Any = DEFAULT_TIMEOUT,
    max_bytes: Optional[int] = None,
    progress_cb: Optional[Callable[[int, int], None]] = None,
    stop_event=None,
    attempts: int = DEFAULT_ATTEMPTS,
) -> Dict[str, Any]:
    started = time.monotonic()
    dest_path = Path(dest)
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    failed: list[Dict[str, Any]] = []
    expected_sha = str(sha256).strip().lower() if sha256 else None
    attempt_count = max(int(attempts), 1)

    for attempt in range(attempt_count):
        tmp_path = dest_path.with_name(f"{dest_path.name}.{attempt}.part")
        if stop_event is not None and stop_event.is_set():
            return _result(False, None, 0, started, "cancelled", failed)
        try:
            resp = _open(url, timeout)
        except (OSError, URLError, HTTPError, ValueError) as exc:
            failed.append({"attempt": attempt + 1, "error": _describe_error(exc)})
            continue
        try:
            total: Optional[int] = None
            try:
                raw = resp.headers.get("Content-Length") if resp.headers else None
                if raw:
                    total = int(raw)
            except (TypeError, ValueError, AttributeError):
                total = None
            digest = hashlib.sha256() if expected_sha else None
            size = 0
            cancelled = False
            size_limited = False
            with open(tmp_path, "wb") as handle:
                while True:
                    if stop_event is not None and stop_event.is_set():
                        cancelled = True
                        break
                    chunk = resp.read(READ_CHUNK)
                    if not chunk:
                        break
                    if max_bytes is not None and size + len(chunk) > max_bytes:
                        size_limited = True
                        break
                    handle.write(chunk)
                    size += len(chunk)
                    if digest is not None:
                        digest.update(chunk)
                    if progress_cb is not None:
                        progress_cb(size, total or 0)
            resp.close()
        except (OSError, URLError, HTTPError, ValueError) as exc:
            failed.append({"attempt": attempt + 1, "error": _describe_error(exc)})
            _cleanup(tmp_path)
            continue
        if cancelled:
            _cleanup(tmp_path)
            return _result(False, None, size, started, "cancelled", failed)
        if size_limited:
            _cleanup(tmp_path)
            return _result(False, None, size, started, "size_limit", failed)
        if expected_sha and digest is not None:
            if digest.hexdigest().lower() != expected_sha:
                _cleanup(tmp_path)
                return _result(False, None, size, started, "checksum", failed)
        try:
            os.replace(str(tmp_path), str(dest_path))
        except OSError as exc:
            _cleanup(tmp_path)
            failed.append({"attempt": attempt + 1, "error": _describe_error(exc)})
            continue
        return _result(True, str(dest_path), size, started, None, failed)

    return _result(False, None, 0, started, "download_failed", failed)


def download_verified(
    urls: Sequence[str],
    dest,
    *,
    sha256: Optional[str] = None,
    timeout: Any = DEFAULT_TIMEOUT,
    max_bytes: Optional[int] = None,
    progress_cb: Optional[Callable[[int, int], None]] = None,
    stop_event=None,
) -> Dict[str, Any]:
    started = time.monotonic()
    history: list[Dict[str, Any]] = []
    for url in urls or []:
        if stop_event is not None and stop_event.is_set():
            return _result(False, None, 0, started, "cancelled", history)
        result = download(
            url,
            dest,
            sha256=sha256,
            timeout=timeout,
            max_bytes=max_bytes,
            progress_cb=progress_cb,
            stop_event=stop_event,
        )
        if result["ok"]:
            return {
                **result,
                "url": url,
                "tried": len(history) + 1,
                "errors": history,
            }
        history.append({"url": url, "error": result["error"]})
        if stop_event is not None and stop_event.is_set():
            break
    return {
        **_result(False, None, 0, started, "download_failed", history),
        "url": None,
        "tried": len(history),
    }