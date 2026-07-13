"""Sentinel Gate QCG: an application-layer abuse-prevention and telemetry gateway."""
from __future__ import annotations

__version__ = "1.1.1"

from .app import create_app

__all__ = ["__version__", "create_app"]
