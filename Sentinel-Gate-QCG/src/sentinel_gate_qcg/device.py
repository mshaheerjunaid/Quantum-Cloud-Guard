"""Working out two extra things about each visitor: what kind of device they
are on, and whether they look like they are coming from a hosting provider.

Both of these are just for the dashboard and for looking back at traffic later.
Neither one ever decides whether a request is allowed through. That matters,
because it means we do not have to be perfect here. If someone fakes their
User-Agent, the worst that happens is one row on a dashboard is mislabelled.
Nobody gets past the gate because of it.

device_type is "mobile", "desktop", "bot", or "unknown", read off the
User-Agent. Good enough to see the rough shape of who is connecting.

network_type is "datacenter", "direct", or "unknown". If the IP sits in a known
cloud or hosting range, it is very likely a VPN, a proxy, or some automated
client rather than a person at home. We call this "datacenter" on purpose, not
"vpn", because that is all we can honestly tell from the IP. A real residential
VPN looks exactly like a normal home connection, and pretending otherwise would
just put a confident wrong answer on the screen.

Both functions are pure and have no side effects, so they are easy to test and
safe to call from anywhere.
"""
from __future__ import annotations

import ipaddress

# We scan the User-Agent for known giveaways. Order matters: check for bots
# first, then mobile, then desktop, because plenty of mobile User-Agents also
# carry desktop-looking tokens and we do not want those to win.
_BOT_HINTS = (
    "bot", "crawler", "spider", "slurp", "curl", "wget", "python-requests",
    "httpx", "go-http-client", "java/", "okhttp", "headlesschrome",
    "scrapy", "phantomjs",
)
_MOBILE_HINTS = (
    "iphone", "android", "ipad", "ipod", "mobile", "windows phone",
    "blackberry", "opera mini", "iemobile",
)
_DESKTOP_HINTS = (
    "windows nt", "macintosh", "mac os x", "x11", "linux", "cros",
)


def classify_device(user_agent: str | None) -> str:
    """Read a User-Agent and say "mobile", "desktop", "bot", or "unknown".

    No User-Agent at all comes back as "unknown", which is common for automated
    clients that do not send one. We check for bots first and let that win,
    because something that calls itself a browser but is really a script is
    still a script as far as the traffic mix is concerned.

    Only the first 512 characters get looked at. A normal User-Agent is far
    shorter than that, and the cap means nobody can make us burn CPU by sending
    a header that is a megabyte long. The gateway limits header sizes anyway,
    but it does not hurt for this function to look after itself.
    """
    if not user_agent:
        return "unknown"
    ua = user_agent[:512].lower()
    if any(h in ua for h in _BOT_HINTS):
        return "bot"
    if any(h in ua for h in _MOBILE_HINTS):
        return "mobile"
    if any(h in ua for h in _DESKTOP_HINTS):
        return "desktop"
    return "unknown"


# A short list of well-known cloud and hosting ranges. This is not meant to be
# complete, just a handful of the big providers, enough that a match is a
# strong hint the traffic is not coming from someone's home connection. If you
# need more coverage you can add your own ranges with SENTINEL_DATACENTER_CIDRS
# at deploy time. Shipping a small built-in list means this works on day one
# without wiring up any external data feed.
_BUILTIN_DATACENTER_CIDRS = (
    # Hetzner, which is where QCG itself runs, so handy for spotting self-tests
    "5.9.0.0/16", "88.198.0.0/16", "116.202.0.0/16", "78.46.0.0/15",
    # A few of the bigger AWS blocks
    "3.0.0.0/9", "13.32.0.0/15", "52.0.0.0/11", "54.224.0.0/12",
    # Google Cloud
    "34.0.0.0/9", "35.184.0.0/13",
    # Microsoft Azure
    "20.0.0.0/8", "40.64.0.0/10",
    # DigitalOcean
    "104.131.0.0/16", "159.65.0.0/16", "165.227.0.0/16", "167.99.0.0/16",
    # OVH
    "51.68.0.0/16", "51.75.0.0/16", "141.94.0.0/16",
)


def _compile_networks(cidrs) -> list:
    nets = []
    for cidr in cidrs:
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    return nets


class NetworkClassifier:
    """Decides whether an IP looks like a hosting provider or a real connection.

    It starts from the built-in provider ranges and you can hand it extra ones.
    The lookup is just a walk down a short list (a few dozen entries), which is
    cheap, and it only ever runs on the background telemetry consumer, never
    while a request is waiting.
    """

    def __init__(self, extra_cidrs: list[str] | None = None) -> None:
        self._nets = _compile_networks(_BUILTIN_DATACENTER_CIDRS)
        if extra_cidrs:
            self._nets.extend(_compile_networks(extra_cidrs))

    def classify(self, ip: str | None) -> str:
        """Return "datacenter", "direct", or "unknown" for an IP.

        Anything private, loopback, or otherwise internal comes back as
        "unknown" so we never accidentally label our own traffic, and the same
        goes for anything we cannot parse.
        """
        if not ip:
            return "unknown"
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return "unknown"
        if addr.is_private or addr.is_loopback or addr.is_reserved \
                or addr.is_link_local or addr.is_multicast:
            return "unknown"
        for net in self._nets:
            if addr.version == net.version and addr in net:
                return "datacenter"
        return "direct"
