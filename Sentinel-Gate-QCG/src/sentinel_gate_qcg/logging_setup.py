"""Structured logging.

Logging uses structlog to emit either machine-readable JSON (default) or
human-friendly console output, with UTC timestamps so forensic events from
multiple hosts and replicas can be correlated. Output defaults to stdout for a
container/log driver to collect.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog


def configure_logging(log_format: str = "json", level: str = "INFO") -> None:
    """Configure structlog + stdlib logging once at startup."""
    timestamper = structlog.processors.TimeStamper(fmt="iso", utc=True)
    shared: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        timestamper,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    renderer = (
        structlog.processors.JSONRenderer()
        if log_format == "json"
        else structlog.dev.ConsoleRenderer(colors=False)
    )
    structlog.configure(
        processors=[*shared, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)
