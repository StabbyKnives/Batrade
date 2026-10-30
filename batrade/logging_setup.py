"""Logging estructurado con rotación (RNF-07).

Un archivo JSONL para máquina y consola legible para humano. Los errores de
herramientas externas deben registrarse con el comando y el código de salida.
"""
from __future__ import annotations

import json
import logging
import logging.handlers
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_LOGGERS: dict[str, logging.Logger] = {}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(
                timespec="milliseconds"
            ),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        extra = getattr(record, "fields", None)
        if isinstance(extra, dict):
            payload.update(extra)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


class HumanFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        fields = getattr(record, "fields", None)
        tail = ""
        if isinstance(fields, dict) and fields:
            tail = " " + " ".join(f"{k}={v}" for k, v in fields.items())
        return f"{ts} {record.levelname:<7} {record.name:<18} {record.getMessage()}{tail}"


def setup_logging(log_dir: Path, component: str = "batrade", level: int = logging.INFO,
                  console: bool = True) -> logging.Logger:
    """Configura (idempotente) el logger del componente."""
    if component in _LOGGERS:
        return _LOGGERS[component]

    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(component)
    logger.setLevel(level)
    logger.propagate = False

    fh = logging.handlers.RotatingFileHandler(
        log_dir / f"{component}.log", maxBytes=2 * 1024 * 1024, backupCount=5,
        encoding="utf-8",
    )
    fh.setFormatter(JsonFormatter())
    logger.addHandler(fh)

    if console:
        ch = logging.StreamHandler(sys.stderr)
        ch.setFormatter(HumanFormatter())
        logger.addHandler(ch)

    _LOGGERS[component] = logger
    return logger


def log(logger: logging.Logger, level: int, msg: str, **fields: Any) -> None:
    """Log con campos estructurados, seguros ante claves reservadas de logging."""
    logger.log(level, msg, extra={"fields": fields})
