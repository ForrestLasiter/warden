"""Secure-at-rest storage for small secrets (the optional VirusTotal API key).

Backends, in order of preference per platform:
  * Windows : DPAPI (CryptProtectData) - the ciphertext can only be decrypted by
              the same user on the same machine. Stored under ~/.warden/secrets.
  * macOS   : the login Keychain via the built-in `security` tool.
  * Linux   : the Secret Service via `secret-tool` (libsecret), when installed.
  * Fallback: an owner-only (0600) file in ~/.warden/secrets. Used when no OS
              keystore is available; never world-readable.

No third-party dependency is required. ``load_secret`` returns None when the
secret isn't set. Everything degrades gracefully; a keystore failure falls back
to the file store rather than losing the user's key.
"""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
from pathlib import Path

from .models import default_data_dir

_SERVICE = "warden"
_IS_WINDOWS = os.name == "nt"
_IS_MACOS = os.uname().sysname == "Darwin" if hasattr(os, "uname") else False


def _secrets_dir() -> Path:
    d = default_data_dir() / "secrets"
    d.mkdir(parents=True, exist_ok=True)
    if not _IS_WINDOWS:
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
    return d


# -- Windows DPAPI -------------------------------------------------------
def _dpapi(data: bytes, protect: bool) -> bytes:
    import ctypes
    from ctypes import wintypes

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = BLOB()
    fn = ctypes.windll.crypt32.CryptProtectData if protect else ctypes.windll.crypt32.CryptUnprotectData
    ok = fn(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out))
    if not ok:
        raise OSError("DPAPI operation failed")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


# -- public API ----------------------------------------------------------
def backend_name() -> str:
    if _IS_WINDOWS:
        return "Windows DPAPI"
    if _IS_MACOS and shutil.which("security"):
        return "macOS Keychain"
    if shutil.which("secret-tool"):
        return "Secret Service (libsecret)"
    return "owner-only file"


def store_secret(name: str, value: str) -> None:
    if _IS_WINDOWS:
        enc = base64.b64encode(_dpapi(value.encode("utf-8"), protect=True))
        _write_file(name + ".dpapi", enc)
        return
    if _IS_MACOS and shutil.which("security"):
        subprocess.run(["security", "add-generic-password", "-a", _SERVICE,
                        "-s", f"{_SERVICE}-{name}", "-w", value, "-U"],
                       capture_output=True, check=False)
        return
    if shutil.which("secret-tool"):
        proc = subprocess.run(["secret-tool", "store", "--label",
                               f"{_SERVICE} {name}", "service", _SERVICE, "name", name],
                              input=value, text=True, capture_output=True)
        if proc.returncode == 0:
            return
    _write_file(name, value.encode("utf-8"))


def load_secret(name: str) -> str | None:
    if _IS_WINDOWS:
        raw = _read_file(name + ".dpapi")
        if raw is None:
            return None
        try:
            return _dpapi(base64.b64decode(raw), protect=False).decode("utf-8")
        except Exception:  # noqa: BLE001
            return None
    if _IS_MACOS and shutil.which("security"):
        proc = subprocess.run(["security", "find-generic-password", "-a", _SERVICE,
                               "-s", f"{_SERVICE}-{name}", "-w"],
                              capture_output=True, text=True)
        if proc.returncode == 0:
            return proc.stdout.strip()
    if shutil.which("secret-tool"):
        proc = subprocess.run(["secret-tool", "lookup", "service", _SERVICE, "name", name],
                              capture_output=True, text=True)
        if proc.returncode == 0 and proc.stdout:
            return proc.stdout.strip()
    raw = _read_file(name)
    return raw.decode("utf-8").strip() if raw is not None else None


def delete_secret(name: str) -> None:
    if _IS_WINDOWS:
        _delete_file(name + ".dpapi")
        return
    if _IS_MACOS and shutil.which("security"):
        subprocess.run(["security", "delete-generic-password", "-a", _SERVICE,
                        "-s", f"{_SERVICE}-{name}"], capture_output=True, check=False)
        return
    if shutil.which("secret-tool"):
        subprocess.run(["secret-tool", "clear", "service", _SERVICE, "name", name],
                       capture_output=True, check=False)
    _delete_file(name)


# -- file-store fallback -------------------------------------------------
def _write_file(fname: str, data: bytes) -> None:
    from .storage import atomic_write_bytes
    atomic_write_bytes(_secrets_dir() / fname, data, mode=0o600)


def _read_file(fname: str) -> bytes | None:
    p = _secrets_dir() / fname
    try:
        return p.read_bytes()
    except OSError:
        return None


def _delete_file(fname: str) -> None:
    try:
        (_secrets_dir() / fname).unlink(missing_ok=True)
    except OSError:
        pass
