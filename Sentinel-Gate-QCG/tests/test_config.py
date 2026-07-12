"""Configuration safety tests."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from sentinel_gate_qcg.config import Settings


def test_vip_enabled_without_key_is_rejected():
    # In production, VIP enabled without a real key must refuse to start, so an
    # unset key can never silently promote everyone to VIP.
    with pytest.raises(ValidationError):
        Settings(environment="production", vip_enabled=True, vip_api_key=None,
                 hmac_secret="x" * 40, admin_token="y" * 32)


def test_vip_placeholder_key_is_rejected():
    with pytest.raises(ValidationError):
        Settings(environment="production", vip_enabled=True,
                 vip_api_key="your_secret_key_here",
                 hmac_secret="x" * 40, admin_token="y" * 32)


def test_vip_without_key_auto_disables_in_development():
    # Outside production the gateway must start cleanly; VIP is simply turned
    # off rather than blocking startup.
    s = Settings(environment="development", vip_enabled=True, vip_api_key=None)
    assert s.vip_enabled is False


def test_production_requires_strong_vip_key():
    with pytest.raises(ValidationError):
        Settings(environment="production", vip_enabled=True,
                 vip_api_key="short", hmac_secret="x" * 40,
                 admin_token="t" * 40)


def test_production_requires_hmac_and_admin_token():
    with pytest.raises(ValidationError):
        Settings(environment="production", vip_enabled=False, hmac_secret=None)


def test_invalid_trusted_proxy_cidr_rejected():
    with pytest.raises(ValidationError):
        Settings(vip_enabled=False, hmac_secret="x" * 40,
                 trusted_proxies=["not-a-cidr"])


def test_dev_autogenerates_hmac_secret():
    s = Settings(vip_enabled=False, hmac_secret=None, environment="development")
    assert s.hmac_secret and len(s.hmac_secret) > 20


def test_route_cost_lookup():
    s = Settings(vip_enabled=False, hmac_secret="x" * 40)
    assert s.route_cost("/search") == 5.0
    assert s.route_cost("/unknown") == s.default_route_cost


def test_trusted_proxies_accepts_empty_env_string():
    # An empty env string (as docker-compose passes for an unset var) must
    # become an empty list, not crash the settings parser.
    s = Settings(environment="development", trusted_proxies="")
    assert s.trusted_proxies == []


def test_trusted_proxies_accepts_comma_separated():
    s = Settings(environment="development",
                 trusted_proxies="10.0.0.0/8, 192.168.0.0/16")
    assert s.trusted_proxies == ["10.0.0.0/8", "192.168.0.0/16"]


def test_trusted_hosts_accepts_empty_and_csv():
    assert Settings(environment="development", trusted_hosts="").trusted_hosts == []
    assert Settings(environment="development",
                    trusted_hosts="a.com, b.com").trusted_hosts == ["a.com", "b.com"]
