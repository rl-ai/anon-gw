"""Transport layer: how packets reach the cloud. Direct for dev; socks5/tor/vps for real use.

Review finding 6: a transport must ENFORCE the intended network path — no
environment proxy inheritance, no redirects that could carry Authorization to
another origin, HTTPS-only upstreams (loopback excepted for testing).
"""
import os
import urllib.error
import urllib.request


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(newurl, code,
                                     "anon-gw: redirects are not followed "
                                     "(Authorization could leak to another origin)",
                                     headers, fp)


class Transport:
    def open(self, req):
        raise NotImplementedError


class Direct(Transport):
    def __init__(self):
        # ProxyHandler({}) = ignore environment proxies: packets leave via the
        # machine's own address only when the user explicitly chose direct.
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect())

    def open(self, req):
        return self.opener.open(req, timeout=600)


class Proxied(Transport):
    """Routes through an HTTP(S)_PROXY-style endpoint (vps relay, corporate proxy),
    or a SOCKS5 endpoint (Tor: socks5h://127.0.0.1:9050) if PySocks is installed."""

    def __init__(self, proxy_url):
        if proxy_url.startswith("socks"):
            try:
                import socks  # noqa: F401 - PySocks optional dependency
                from sockshandler import SocksiPyHandler
            except ImportError:
                raise ValueError(
                    f"socks transport {proxy_url!r} needs PySocks: pip install pysocks")
            socks_host, socks_port = self._parse_socks(proxy_url)
            self.opener = urllib.request.build_opener(
                SocksiPyHandler(socks.PROXY_TYPE_SOCKS5, socks_host, socks_port,
                                rdns=True),
                _NoRedirect())
            self.proxy_url = proxy_url
            return
        self.proxy_url = proxy_url
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}),
            _NoRedirect())

    @staticmethod
    def _parse_socks(url):
        rest = url.split("://", 1)[1]
        host, _, port = rest.rpartition(":")
        return host or "127.0.0.1", int(port or 9050)

    def open(self, req):
        return self.opener.open(req, timeout=600)


def check_upstream(url):
    """HTTPS-only upstream, loopback http allowed for local testing."""
    if url.startswith("https://"):
        return
    if url.startswith("http://127.0.0.1") or url.startswith("http://localhost"):
        return
    raise ValueError(f"upstream must be https (got {url.split(':')[0]}://...)")


def from_env():
    url = os.environ.get("ANON_GW_TRANSPORT", "direct")
    if url == "direct":
        return Direct()
    return Proxied(url)
