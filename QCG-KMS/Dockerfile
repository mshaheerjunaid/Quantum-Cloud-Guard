# syntax=docker/dockerfile:1

# --- stage 1: build the React UI ------------------------------------------
FROM node:22-slim AS ui
WORKDIR /ui
COPY ui/package.json ui/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY ui/ ./
RUN npm run build

# --- stage 2: build a venv with the package + UI --------------------------
FROM python:3.12-slim AS builder
WORKDIR /build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
# Bring the built UI into the package so it ships inside the wheel.
COPY --from=ui /ui/dist ./src/qcg_kms/static
RUN python -m venv /venv && /venv/bin/pip install .

# --- stage 3: minimal runtime --------------------------------------------
FROM python:3.12-slim AS runtime
RUN useradd --create-home --uid 10001 qcg && mkdir -p /data && chown qcg:qcg /data
COPY --from=builder /venv /venv
ENV PATH="/venv/bin:$PATH" \
    QCG_HOST=0.0.0.0 \
    QCG_PORT=8800 \
    QCG_DB_PATH=/data/qcg_kms.db
USER qcg
WORKDIR /home/qcg
EXPOSE 8800
# slim images have no curl; use python's urllib.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8800/healthz').status==200 else 1)"]
CMD ["python", "-m", "qcg_kms"]
