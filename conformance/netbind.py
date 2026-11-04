"""Where the kit's own listeners bind, and the address a target is told to reach them at.

By default every listener the kit starts (the recorder, `mockserver.MockServer`; the stub A's
status source, `requester.StubRequester.serve`) binds 127.0.0.1 and names that address in its
URL, because the target runs on the same host. For a target on another machine (P19 with B on
separate machines), two variables change that:

- ``ACK_BIND_HOST``: the address to bind, for example ``::`` (every interface, IPv6) on a host
  whose private network is IPv6 only;
- ``ACK_ADVERTISE_HOST``: the address put in the URLs given to the target, for example the kit
  machine's private IPv6 address. Without it, the bound address, as before.

An IPv6 address binds an IPv6 server (`server_class`) and is bracketed in URLs (`url_host`).
Nothing here decides a verdict; it only says where a socket listens.
"""
from __future__ import annotations

import os
import socket
from http.server import ThreadingHTTPServer
from typing import Optional, Type

BIND_ENV = "ACK_BIND_HOST"
ADVERTISE_ENV = "ACK_ADVERTISE_HOST"
LOCAL = "127.0.0.1"


def bind_host(explicit: Optional[str] = None) -> str:
    """The address to bind: `explicit` when given, else ``ACK_BIND_HOST``, else 127.0.0.1."""
    if explicit is not None:
        return explicit
    return os.environ.get(BIND_ENV) or LOCAL


def advertise_host(bound: str) -> str:
    """The address a target is told: ``ACK_ADVERTISE_HOST``, else `bound` as it is (a wildcard
    included, as before this module existed: adapters that bind 0.0.0.0 rewrite the URL
    themselves)."""
    return os.environ.get(ADVERTISE_ENV) or bound


def url_host(host: str) -> str:
    """`host` as it appears in a URL: IPv6 literals in brackets."""
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


class _V6Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6

    def server_bind(self) -> None:
        # Accept IPv4 too where the host allows it (dual stack); harmless when it does not.
        try:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except (AttributeError, OSError):
            pass
        super().server_bind()


def server_class(host: str) -> Type[ThreadingHTTPServer]:
    """The HTTP server class for binding `host`: IPv6 for an IPv6 address."""
    return _V6Server if ":" in host else ThreadingHTTPServer
