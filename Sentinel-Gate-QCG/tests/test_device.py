"""Tests for best-effort device and network classification (dashboard signals)."""
from __future__ import annotations

from sentinel_gate_qcg.device import NetworkClassifier, classify_device


def test_classify_device_mobile():
    ua = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
          "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148")
    assert classify_device(ua) == "mobile"
    android = ("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/120 Mobile Safari/537.36")
    assert classify_device(android) == "mobile"


def test_classify_device_desktop():
    ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/120 Safari/537.36")
    assert classify_device(ua) == "desktop"
    mac = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
           "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17 Safari/605.1.15")
    assert classify_device(mac) == "desktop"


def test_classify_device_bot():
    assert classify_device("curl/8.4.0") == "bot"
    assert classify_device("python-requests/2.31.0") == "bot"
    assert classify_device("Googlebot/2.1 (+http://www.google.com/bot.html)") == "bot"


def test_classify_device_unknown():
    assert classify_device(None) == "unknown"
    assert classify_device("") == "unknown"
    assert classify_device("something-totally-opaque") == "unknown"


def test_bot_wins_over_browser_token():
    # An automated client that also reports a browser token is still automation.
    ua = "HeadlessChrome/120 (Windows NT 10.0)"
    assert classify_device(ua) == "bot"


def test_network_classifier_datacenter():
    nc = NetworkClassifier()
    # Hetzner range is built in.
    assert nc.classify("5.9.1.2") == "datacenter"


def test_network_classifier_direct():
    nc = NetworkClassifier()
    # A globally-routable public IP not in any known hosting range -> direct
    # (likely residential). 24.48.0.1 is a real, globally-routable address.
    assert nc.classify("24.48.0.1") == "direct"


def test_network_classifier_private_is_unknown():
    nc = NetworkClassifier()
    assert nc.classify("127.0.0.1") == "unknown"
    assert nc.classify("10.0.0.5") == "unknown"
    assert nc.classify("192.168.1.1") == "unknown"


def test_network_classifier_garbage_is_unknown():
    nc = NetworkClassifier()
    assert nc.classify("not-an-ip") == "unknown"
    assert nc.classify(None) == "unknown"


def test_network_classifier_extra_cidrs():
    # Use a real, globally-routable block for the custom entry, and a global
    # address outside it for the negative case.
    nc = NetworkClassifier(["45.79.0.0/16"])
    assert nc.classify("45.79.1.7") == "datacenter"
    assert nc.classify("24.48.0.1") == "direct"


def test_oversized_user_agent_is_capped():
    # A megabyte-long User-Agent must not be fully scanned; still classified
    # safely. A bot token placed past the cap is intentionally ignored.
    huge = "Mozilla/5.0 (Windows NT 10.0) " + ("x" * 1_000_000) + " curl"
    # The bot token is beyond the 512-char cap, so this stays desktop.
    assert classify_device(huge) == "desktop"


def test_network_classifier_ipv6_public_is_direct():
    nc = NetworkClassifier()
    # Public IPv6 not in our (v4) hosting list -> direct, no crash.
    assert nc.classify("2606:4700:4700::1111") == "direct"


def test_network_classifier_ipv6_loopback_and_linklocal_unknown():
    nc = NetworkClassifier()
    assert nc.classify("::1") == "unknown"
    assert nc.classify("fe80::1") == "unknown"


def test_network_classifier_malformed_ipv4_unknown():
    nc = NetworkClassifier()
    assert nc.classify("999.999.999.999") == "unknown"
    assert nc.classify("1.2.3") == "unknown"
