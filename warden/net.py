"""The single doorway to the network.

Warden is local-first: with default settings it makes no network connection at
all. The few features that can (opt-in hash reputation, installing a rule pack
from a URL) all go through this module, which gives one place to enforce:

  * **Offline mode.** ``--offline``, ``WARDEN_OFFLINE=1`` or ``"offline": true``
    in the config makes every request raise ``OfflineError`` before a socket is
    opened - a hard guarantee, not a best-effort preference.
  * **HTTPS only**, with certificate verification left on.
  * **Bounded responses**, so a hostile or broken server can't feed us an
    endless body.

There is no telemetry, update check, or crash reporting anywhere in Warden, so
this module has no code for any of those.
"""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlparse

try:
    import httpx
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

_TRUE = ("1", "true", "yes", "on")
_forced_offline = False

USER_AGENT = "warden-scanner"


class OfflineError(RuntimeError):
    """Raised when something tries to use the network while offline mode is on."""


class NetworkError(RuntimeError):
    """A request was refused (bad scheme, too large) or failed."""


def set_offline(on: bool = True) -> None:
    """Force offline mode for this process (the ``--offline`` flag)."""
    global _forced_offline
    _forced_offline = bool(on)


def is_offline(config: Any = None) -> bool:
    if _forced_offline:
        return True
    if os.environ.get("WARDEN_OFFLINE", "").strip().lower() in _TRUE:
        return True
    return bool(getattr(config, "offline", False))


def available() -> bool:
    return httpx is not None


def _check(url: str, config: Any) -> None:
    if is_offline(config):
        raise OfflineError("offline mode is on: network access is disabled")
    if httpx is None:
        raise NetworkError("httpx is not installed")
    if urlparse(url).scheme != "https":
        raise NetworkError("refusing a non-HTTPS URL")


def get(url: str, *, config: Any = None, params: dict | None = None,
        headers: dict | None = None, timeout: float = 10.0):
    """HTTPS GET for small API responses. Raises OfflineError when offline."""
    _check(url, config)
    hdrs = {"user-agent": USER_AGENT, **(headers or {})}
    return httpx.get(url, params=params, headers=hdrs, timeout=timeout, follow_redirects=False)


def download(url: str, *, max_bytes: int, config: Any = None, timeout: float = 30.0) -> bytes:
    """HTTPS download with a hard size cap (streamed, never trusting
    Content-Length). Follows redirects only to other HTTPS URLs."""
    _check(url, config)
    try:
        with httpx.stream("GET", url, headers={"user-agent": USER_AGENT}, timeout=timeout,
                          follow_redirects=True) as resp:
            if urlparse(str(resp.url)).scheme != "https":
                raise NetworkError("redirected to a non-HTTPS URL")
            if resp.status_code != 200:
                raise NetworkError(f"download failed: HTTP {resp.status_code}")
            buf = bytearray()
            for chunk in resp.iter_bytes():
                buf += chunk
                if len(buf) > max_bytes:
                    raise NetworkError(f"download larger than {max_bytes} bytes; aborted")
            return bytes(buf)
    except httpx.HTTPError as exc:
        raise NetworkError(f"download failed: {exc}") from exc
