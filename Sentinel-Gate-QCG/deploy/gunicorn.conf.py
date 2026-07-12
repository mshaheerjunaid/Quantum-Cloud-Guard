"""Production server config for Sentinel Gate QCG (Layer 7).

Run with:  gunicorn -c deploy/gunicorn.conf.py "sentinel_gate_qcg.app:create_app()"

Critical: proxy/forwarded headers are NOT trusted at the server layer. Client
identity is resolved by the gateway itself from the real socket peer plus the
configured SENTINEL_TRUSTED_PROXIES. Letting the server rewrite the peer from
X-Forwarded-For would happen before the gateway runs and would undermine
source identity. forwarded_allow_ips is therefore empty.
"""

import multiprocessing

bind = "0.0.0.0:8000"
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "uvicorn.workers.UvicornWorker"
forwarded_allow_ips = ""          # do NOT trust X-Forwarded-For at the server
proxy_allow_ips = ""
keepalive = 5                      # short keep-alive blunts slow-client hold
timeout = 30
graceful_timeout = 10
limit_request_line = 8190
limit_request_fields = 100
limit_request_field_size = 8190
