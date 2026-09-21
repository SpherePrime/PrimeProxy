from __future__ import annotations

import logging

_log = logging.getLogger("swift-health")


class _HealthLogger:
    """Шим логгера: поддерживает log(msg, level), log.log(msg, level) и log.error(msg)."""

    def __call__(self, message, level="INFO"):
        self.log(message, level)

    def log(self, message, level="INFO"):
        text = "".join(ch for ch in str(level or "").lower() if ch.isalnum())
        method = getattr(_log, text, _log.info)
        method(str(message))

    def debug(self, message, *args):
        _log.debug(str(message), *args)

    def info(self, message, *args):
        _log.info(str(message), *args)

    def warn(self, message, *args):
        _log.warning(str(message), *args)

    def warning(self, message, *args):
        _log.warning(str(message), *args)

    def error(self, message, *args):
        _log.error(str(message), *args)


log = _HealthLogger()