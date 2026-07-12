# syntax=docker/dockerfile:1
# ---- builder ---------------------------------------------------------------
FROM python:3.12-slim AS builder
WORKDIR /build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
# Build a wheel and resolve runtime deps into a venv we can copy over clean.
RUN python -m venv /venv \
 && /venv/bin/pip install --upgrade pip build \
 && /venv/bin/pip install ".[ml]"

# ---- runtime ---------------------------------------------------------------
FROM python:3.12-slim AS runtime
# Create an unprivileged user; the gateway never needs root.
RUN useradd --create-home --uid 10001 sentinel
COPY --from=builder /venv /venv
ENV PATH="/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SENTINEL_ENVIRONMENT=production
USER sentinel
WORKDIR /home/sentinel
EXPOSE 8000
# Liveness is cheap and dependency-free; readiness (/readyz) checks Redis.
HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz').status==200 else 1)"
ENTRYPOINT ["python", "-m", "sentinel_gate_qcg"]
