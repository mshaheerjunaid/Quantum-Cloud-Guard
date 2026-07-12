"""Run the KMS: ``python -m qcg_kms``.

Binds to ``settings.host`` (127.0.0.1 by default) because Sentinel Gate is the
public face. Settings are validated fail-fast before the server starts.
"""

from __future__ import annotations

import uvicorn

from .app import create_app
from .config import get_settings


def main() -> None:
    settings = get_settings()
    app = create_app(settings)
    uvicorn.run(app, host=settings.host, port=settings.port,
                log_level=settings.log_level)


if __name__ == "__main__":
    main()
