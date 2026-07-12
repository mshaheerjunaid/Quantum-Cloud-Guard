"""Client-IP resolution tests -- the anti-spoofing keystone."""

from __future__ import annotations

from sentinel_gate_qcg.client_ip import ClientIPResolver
from sentinel_gate_qcg.config import Settings


def _settings(**kw):
    base = dict(vip_enabled=False, hmac_secret="x" * 40)
    base.update(kw)
    return Settings(**base)


def test_untrusted_peer_ignores_forwarded_header():
    # An attacker sending a spoofed XFF from a direct connection must be
    # pinned to their real socket IP, defeating header-based IP rotation.
    r = ClientIPResolver(_settings(trusted_proxies=["10.0.0.0/8"]))
    resolved = r.resolve("203.0.113.5", "1.1.1.1, 2.2.2.2, 3.3.3.3")
    assert resolved.ip == "203.0.113.5"
    assert resolved.via_trusted_proxy is False


def test_rotating_xff_does_not_create_new_buckets():
    r = ClientIPResolver(_settings(trusted_proxies=["10.0.0.0/8"]))
    ips = {
        r.resolve("203.0.113.5", f"9.9.9.{i}").ip for i in range(50)
    }
    assert ips == {"203.0.113.5"}  # all collapse to the real peer


def test_trusted_peer_honours_forwarded_header():
    r = ClientIPResolver(_settings(trusted_proxies=["10.0.0.0/8"], trusted_proxy_hops=1))
    resolved = r.resolve("10.0.0.1", "198.51.100.23")
    assert resolved.ip == "198.51.100.23"
    assert resolved.via_trusted_proxy is True


def test_trusted_proxy_hops_selects_correct_entry():
    # client -> edge -> internal-lb(this). Two trusted hops; take client.
    r = ClientIPResolver(_settings(trusted_proxies=["10.0.0.0/8"], trusted_proxy_hops=2))
    resolved = r.resolve("10.0.0.2", "198.51.100.23, 10.0.0.9")
    assert resolved.ip == "198.51.100.23"


def test_malformed_forwarded_entries_are_skipped():
    r = ClientIPResolver(_settings(trusted_proxies=["10.0.0.0/8"], trusted_proxy_hops=1))
    resolved = r.resolve("10.0.0.1", "garbage, 198.51.100.50:443")
    assert resolved.ip == "198.51.100.50"


def test_no_trusted_proxies_never_trusts_headers():
    r = ClientIPResolver(_settings(trusted_proxies=[]))
    resolved = r.resolve("198.51.100.7", "1.2.3.4")
    assert resolved.ip == "198.51.100.7"


def test_subnet_aggregation():
    r = ClientIPResolver(_settings(trusted_proxies=[]))
    resolved = r.resolve("198.51.100.7", None)
    assert resolved.network_24 == "198.51.100.0"
