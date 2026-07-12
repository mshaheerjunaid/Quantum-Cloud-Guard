# Testing and Running Sentinel Gate QCG

There are four ways to exercise this system, in increasing order of setup. You
do **not** need Docker for most of them. Pick the lowest tier that answers your
question.

## Tier 0, Run the test suite (no Docker, no Redis)

This is the fastest way to verify everything works. The tests run against
`fakeredis`, an in-memory stand-in for Redis (including its Lua scripting), so
nothing external is required.

```bash
python -m venv .venv
# Windows PowerShell:  .venv\Scripts\Activate.ps1
# WSL2 / Linux / macOS: source .venv/bin/activate
pip install -e ".[dev,ml]"
make check        # runs ruff (lint) + mypy (types) + pytest (59 tests)
# or just: pytest -q
```

If `make check` passes, the limiter, challenge, reputation, anomaly detector,
client-IP resolution, config validation, kernel-sync IP extraction, telemetry
file logging, and the full end-to-end middleware (including the
bypass-resistance tests) are all verified. **No Docker needed for this tier.**

## Tier 1, Run the application locally (needs Redis, no Docker required)

To actually start the gateway and send it traffic, the application needs a real
Redis. You have two options for Redis:

- **Without Docker:** install Redis natively. On WSL2 / Ubuntu:
  `sudo apt-get install redis-server && sudo service redis-server start`.
- **With Docker (just for Redis):** `docker run -p 6379:6379 redis:8-alpine`.

Then run the gateway (development mode auto-generates the signing secret):

```bash
export SENTINEL_ENVIRONMENT=development
python -m sentinel_gate_qcg
```

In another terminal, send the adversarial smoke test at it and confirm every
application-layer bypass is contained:

```bash
python tools/attack_simulator.py --url http://localhost:8000
```

You can also watch the structured logs scroll on stdout, hit
`http://localhost:8000/metrics` for Prometheus counters, and
`http://localhost:8000/healthz` for liveness.

## Tier 2, Run the full stack with Docker Compose (needs Docker)

This brings up the gateway **and** a hardened Redis together as one system, the
way it is meant to be deployed. **This is the tier that needs Docker installed.**

- **Windows / macOS:** install **Docker Desktop** (it includes both the Docker
  Engine and Docker Compose). On Windows it runs on the WSL2 backend.
- **Linux:** install Docker Engine and the Compose plugin from your package
  manager.

Then, from the project folder:

```bash
export SENTINEL_VIP_API_KEY=$(python -c "import secrets;print(secrets.token_urlsafe(32))")
export SENTINEL_HMAC_SECRET=$(python -c "import secrets;print(secrets.token_urlsafe(48))")
export SENTINEL_ADMIN_TOKEN=$(python -c "import secrets;print(secrets.token_urlsafe(32))")
docker compose up --build
```

`docker compose up` reads `docker-compose.yml`, builds the gateway image from
the `Dockerfile`, starts Redis, waits for it to be healthy, then starts the
gateway on port 8000. Logs appear with `docker compose logs -f gateway`.
`docker compose down` stops it.

You only install Docker for this tier. The `docker-compose.yml` file is not
something you "run" on its own, it is the recipe `docker compose` follows.

## Tier 3, The kernel layer (needs a real Linux host)

The Layer 3 / Layer 4 packet-filter layer (`deploy/nftables.conf`,
`deploy/sysctl.conf`, `kernel_sync.py`) acts on real network packets, so it
must run on a Linux host with privilege:

```bash
sudo sysctl -p deploy/sysctl.conf
sudo nft -f deploy/nftables.conf
sudo python -m sentinel_gate_qcg.kernel_sync --interval 5
```

Honest caveat: WSL2 is fine for experimenting with `nft` syntax, but its
kernel does not expose the full networking stack (reverse-path filtering and
some conntrack behaviour differ), so validate this tier on a real Linux VM or
the production host, not on WSL2. The application tiers (0–2) are unaffected by
this and run anywhere.

## Quick decision guide

| Your question | Tier | Docker? |
|---|---|---|
| "Does the logic work / did I break anything?" | 0 | No |
| "Let me run it and attack it." | 1 | Optional (Redis only) |
| "Run it like production, gateway + Redis." | 2 | Yes |
| "Test the packet-level flood defenses." | 3 | No (real Linux host) |

## A note on the CI file

`.github/workflows/ci.yml` is **not** run on your machine. It runs
automatically on GitHub's servers whenever you push code, executing Tier 0 on
Python 3.11 and 3.12 and then building the Docker image. You never invoke it
directly; it is your automatic safety net.
