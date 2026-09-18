"""Structured (JSON-lines) logging for NetProof.

Configure once at server startup and every uvicorn/middleware record is emitted
as one JSON object per line — machine-parsable by any log shipper, with no
third-party dependency.
"""
from __future__ import annotations

import json
import logging
import time


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime_format(record.created),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0] is not None:
            payload["exc"] = self.formatException(record.exc_info)
        if hasattr(record, "event"):
            payload["event"] = record.event
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def datetime_format(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(epoch))


def setup_logging(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "app"):
        logging.getLogger(name).handlers = [handler]
        logging.getLogger(name).propagate = False
        logging.getLogger(name).setLevel(level)