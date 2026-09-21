from __future__ import annotations

import os
import threading
import time
from typing import Dict, List, Optional

from ._log import log


class ProcessMonitor:
    """Фоновый наблюдатель за процессами winws: статус и история сбоев."""

    def __init__(self, process_names: Optional[List[str]] = None, interval_s: float = 2.5):
        self.process_names = list(process_names or ["winws.exe", "winws2.exe"])
        self.interval_s = interval_s
        self._stop_flag = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._pids: Dict[str, List[int]] = {}
        self._alive_count: Dict[str, int] = {}
        self._dead_since: Dict[str, Optional[float]] = {}
        self._observed_exit_codes: List[int] = []
        self._lock = threading.Lock()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_flag.clear()
        self._thread = threading.Thread(target=self._run, name="winws-health-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_flag.set()
        if self._thread:
            self._thread.join(timeout=1.0)
            self._thread = None

    def snapshot(self) -> Dict[str, object]:
        with self._lock:
            running_count = sum(len(pids) for pids in self._pids.values())
            return {
                "running": running_count > 0,
                "count": running_count,
                "processes": {name: list(pids) for name, pids in self._pids.items()},
                "recent_exit_codes": list(self._observed_exit_codes[-10:]),
            }

    def _run(self) -> None:
        while not self._stop_flag.is_set():
            try:
                self._poll()
            except Exception as exc:
                log.debug(f"Опрос процессов не выполнен: {exc}")
            self._stop_flag.wait(self.interval_s)

    def _poll(self) -> None:
        alive: Dict[str, List[int]] = {}
        for name in self.process_names:
            try:
                from utils.process_killer import get_process_pids
                pids = list(get_process_pids(name))
            except Exception:
                pids = []
            with self._lock:
                previous = set(self._pids.get(name, []))
            new_ones = [pid for pid in pids if pid not in previous]
            if new_ones:
                with self._lock:
                    self._observed_exit_codes.append(0)
            alive[name] = pids
        with self._lock:
            self._pids = alive