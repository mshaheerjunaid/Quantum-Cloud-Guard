"""Sentinel Gate QCG: a multi-layer (L3/L4/L7) DDoS and security gateway."""

from __future__ import annotations

__version__ = "1.1.1"

from .app import create_app

__all__ = ["__version__", "create_app"]
