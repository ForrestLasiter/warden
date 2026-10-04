"""Signed, versioned rule packs with rollback.

Detection content ages quickly, so it needs an update path that is separate
from the program - and that path is a juicy target: whoever can feed Warden a
rule file controls what it calls clean. So rule packs are:

  * **Signed.** A pack is installed only if its detached Ed25519 signature
    verifies against a public key *you* have added to the trust store.
    Unsigned packs need an explicit ``--allow-unsigned``.
  * **Versioned, monotonic.** A pack carries an integer version. An older
    version than the active one is refused (a "downgrade to the rules that
    don't detect me" attack) unless explicitly allowed.
  * **Validated before activation.** Every file is hash-checked against the
    manifest, names are confined to the pack directory, sizes are bounded and
    all YARA must compile. A pack that fails any check changes nothing.
  * **Atomic and reversible.** A new version is unpacked beside the old one
    and activated by a single state-file swap; ``rollback`` re-activates the
    previous version instantly.
  * **Re-verified at load.** Installed files are re-hashed whenever a scanner
    starts; a pack that was altered on disk is not loaded and the scan is
    reported as degraded.

Pack format (a zip, conventionally ``<name>-<version>.wrp``)::

    manifest.json       {"format": 1, "name", "version", "created", "description",
                         "files": {"<relative path>": "<sha256>", ...}}
    *.yar / *.yara      YARA rules (any sub-folders)
    malware_hashes.txt  optional SHA-256 denylist

The signature (``<pack>.sig``) is JSON: ``{"algorithm": "ed25519", "key_id",
"signature"}`` over ``b"warden-rulepack-v1\\n" + <pack bytes>``.

There is no hosted "official" feed: Warden never downloads rules on its own.
You (or your organisation) build, sign and distribute packs; the rules bundled
with Warden ship inside the signed release binary.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import shutil
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import Config
from .models import now_iso
from .storage import atomic_write_bytes, atomic_write_json, file_lock, secure_dir

# Warden uses only modern primitives (Ed25519, AES-GCM, HKDF, scrypt). Telling
# the library not to load OpenSSL's "legacy" provider keeps it from failing at
# import on machines where that optional module isn't present.
os.environ.setdefault("CRYPTOGRAPHY_OPENSSL_NO_LEGACY", "1")

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    _CRYPTO = True
    _CRYPTO_ERROR = ""
except Exception as _exc:  # pragma: no cover - cryptography is a declared dependency
    _CRYPTO = False
    # Keep the reason: "is it missing, or did it fail to load?" is the first
    # question when this is hit inside a packaged build.
    _CRYPTO_ERROR = f"{type(_exc).__name__}: {_exc}"

FORMAT = 1
_DOMAIN = b"warden-rulepack-v1\n"
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_KEY_ID_RE = re.compile(r"^[0-9a-f]{16}$")
_ALLOWED_SUFFIXES = {".yar", ".yara", ".txt", ".md", ".json"}
MAX_PACK_BYTES = 64 * 1024 * 1024
_MAX_FILES = 2000
_MAX_FILE_BYTES = 32 * 1024 * 1024
_KEEP_OLD_VERSIONS = 3


class RulePackError(Exception):
    pass


@dataclass(slots=True)
class PackInfo:
    name: str
    version: int
    active: bool
    installed_at: str
    key_id: str | None
    signer: str | None
    files: int
    description: str
    path: str

    def to_dict(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in self.__slots__}


# -- keys ----------------------------------------------------------------
def _need_crypto() -> None:
    if not _CRYPTO:
        raise RulePackError("the 'cryptography' package is required for rule-pack signatures"
                            + (f" (it failed to load: {_CRYPTO_ERROR})" if _CRYPTO_ERROR else ""))


def key_id(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()[:16]


def generate_keypair() -> tuple[bytes, bytes]:
    """(private, public) raw 32-byte Ed25519 keys."""
    _need_crypto()
    priv = Ed25519PrivateKey.generate()
    raw_priv = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                  serialization.NoEncryption())
    raw_pub = priv.public_key().public_bytes(serialization.Encoding.Raw,
                                             serialization.PublicFormat.Raw)
    return raw_priv, raw_pub


def _decode_key(text: str | bytes, what: str) -> bytes:
    if isinstance(text, bytes):
        text = text.decode("ascii", errors="ignore")
    try:
        raw = base64.b64decode(text.strip(), validate=True)
    except (ValueError, TypeError):
        raise RulePackError(f"{what} is not valid base64") from None
    if len(raw) != 32:
        raise RulePackError(f"{what} must be a 32-byte Ed25519 key")
    return raw


def sign_pack(pack: bytes, private_key: bytes) -> bytes:
    """Detached signature document (JSON bytes) for a pack."""
    _need_crypto()
    priv = Ed25519PrivateKey.from_private_bytes(private_key)
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    sig = priv.sign(_DOMAIN + pack)
    doc = {"algorithm": "ed25519", "key_id": key_id(pub),
           "signature": base64.b64encode(sig).decode("ascii")}
    return json.dumps(doc, indent=2).encode("utf-8")


# -- building ------------------------------------------------------------
def build_pack(src_dir: Path, name: str, version: int, description: str = "") -> bytes:
    """Zip a directory of rules into a pack with a manifest."""
    _validate_identity(name, version)
    src_dir = Path(src_dir)
    if not src_dir.is_dir():
        raise RulePackError(f"not a directory: {src_dir}")
    files: dict[str, bytes] = {}
    for f in sorted(src_dir.rglob("*")):
        if not f.is_file() or f.is_symlink() or f.name == "manifest.json":
            continue
        if f.suffix.lower() not in _ALLOWED_SUFFIXES:
            continue
        rel = f.relative_to(src_dir).as_posix()
        _validate_member_name(rel)
        files[rel] = f.read_bytes()
    if not any(n.lower().endswith((".yar", ".yara", ".txt")) for n in files):
        raise RulePackError("no rule files (.yar/.yara) or hash lists (.txt) found to pack")
    manifest = {
        "format": FORMAT, "name": name, "version": version, "created": now_iso(),
        "description": description[:500],
        "files": {n: hashlib.sha256(b).hexdigest() for n, b in files.items()},
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True))
        for n, b in files.items():
            zf.writestr(n, b)
    return buf.getvalue()


def _validate_identity(name: str, version: Any) -> None:
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise RulePackError("pack name must be 1-64 chars of a-z, 0-9, '-' or '_' "
                            "(starting with a letter or digit)")
    if isinstance(version, bool) or not isinstance(version, int) or not (1 <= version < 2**31):
        raise RulePackError("pack version must be a positive integer")


def _validate_member_name(name: str) -> None:
    """Confine a member path to the pack directory (no traversal, no absolute
    paths, no drive letters, no backslashes, no hidden/control characters)."""
    if (not name or len(name) > 240 or name.startswith("/") or "\\" in name or ":" in name
            or any(ord(c) < 32 for c in name)):
        raise RulePackError(f"unsafe file name in pack: {name!r}")
    parts = name.split("/")
    if any(p in ("", ".", "..") or p.startswith(".") for p in parts):
        raise RulePackError(f"unsafe file name in pack: {name!r}")
    if Path(name).suffix.lower() not in _ALLOWED_SUFFIXES:
        raise RulePackError(f"file type not allowed in a rule pack: {name!r}")


def read_pack(pack: bytes) -> tuple[dict[str, Any], dict[str, bytes]]:
    """Validate a pack's structure and return (manifest, files). Raises
    RulePackError on anything out of line; never writes to disk."""
    if len(pack) > MAX_PACK_BYTES:
        raise RulePackError("pack is larger than the 64 MiB limit")
    try:
        zf = zipfile.ZipFile(io.BytesIO(pack))
    except (zipfile.BadZipFile, OSError, ValueError):
        raise RulePackError("pack is not a valid zip file") from None
    with zf:
        infos = zf.infolist()
        if len(infos) > _MAX_FILES:
            raise RulePackError("pack has too many files")
        members: dict[str, bytes] = {}
        total = 0
        for info in infos:
            if info.is_dir():
                continue
            if info.filename in members:
                raise RulePackError(f"duplicate file in pack: {info.filename!r}")
            if info.filename != "manifest.json":
                _validate_member_name(info.filename)
            try:
                with zf.open(info) as fh:
                    blob = fh.read(_MAX_FILE_BYTES + 1)
            except Exception:  # noqa: BLE001 - encrypted/corrupt member
                raise RulePackError(f"unreadable file in pack: {info.filename!r}") from None
            total += len(blob)
            if len(blob) > _MAX_FILE_BYTES or total > MAX_PACK_BYTES * 4:
                raise RulePackError("pack contents exceed the size limit")
            members[info.filename] = blob
    raw_manifest = members.pop("manifest.json", None)
    if raw_manifest is None:
        raise RulePackError("pack has no manifest.json")
    try:
        manifest = json.loads(raw_manifest.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise RulePackError("pack manifest is not valid JSON") from None
    if not isinstance(manifest, dict) or manifest.get("format") != FORMAT:
        raise RulePackError("unsupported pack format")
    _validate_identity(str(manifest.get("name", "")), manifest.get("version"))
    listed = manifest.get("files")
    if not isinstance(listed, dict) or not listed:
        raise RulePackError("pack manifest lists no files")
    if set(listed) != set(members):
        raise RulePackError("pack contents do not match its manifest")
    for name, digest in listed.items():
        if hashlib.sha256(members[name]).hexdigest() != digest:
            raise RulePackError(f"hash mismatch for {name!r} (pack is corrupt or was altered)")
    return manifest, members


def _compile_check(files: dict[str, bytes]) -> None:
    """Reject a pack whose YARA doesn't compile - before it can replace rules
    that do."""
    sources = {n: b for n, b in files.items() if n.lower().endswith((".yar", ".yara"))}
    if not sources:
        return
    try:
        import yara_x
    except Exception:  # noqa: BLE001 - engine unavailable: nothing to test against
        return
    compiler = yara_x.Compiler()
    for name, blob in sources.items():
        try:
            compiler.add_source(blob.decode("utf-8", errors="replace"))
        except Exception as exc:  # noqa: BLE001
            raise RulePackError(f"rule file {name!r} does not compile: {str(exc)[:300]}") from None
    try:
        compiler.build()
    except Exception as exc:  # noqa: BLE001
        raise RulePackError(f"rules do not build: {str(exc)[:300]}") from None


# -- manager -------------------------------------------------------------
class RulePackManager:
    def __init__(self, config: Config | None = None):
        self.config = config or Config.load()
        self.root = self.config.data_dir / "rulepacks"
        self.keys_dir = self.config.data_dir / "trusted_keys"
        self.state_path = self.root / "state.json"
        self._lock = self.root / "state.lock"

    # -- trust store ------------------------------------------------------
    def trust(self, public_key_b64: str | bytes, label: str = "") -> str:
        raw = _decode_key(public_key_b64, "public key")
        kid = key_id(raw)
        secure_dir(self.keys_dir)
        atomic_write_json(self.keys_dir / f"{kid}.json", {
            "key_id": kid, "public_key": base64.b64encode(raw).decode("ascii"),
            "name": "".join(c for c in label if c.isprintable())[:80], "added": now_iso(),
        }, mode=0o600)
        return kid

    def untrust(self, kid: str) -> None:
        if not _KEY_ID_RE.match(kid or ""):
            raise RulePackError("key id must be 16 hex characters")
        path = self.keys_dir / f"{kid}.json"
        if not path.exists():
            raise RulePackError(f"no trusted key with id {kid}")
        path.unlink()

    def trusted_keys(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        if not self.keys_dir.is_dir():
            return out
        for f in sorted(self.keys_dir.glob("*.json")):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                raw = _decode_key(str(data["public_key"]), "public key")
            except (OSError, ValueError, KeyError, TypeError, RulePackError):
                continue   # a damaged entry is simply not trusted
            # The id is derived from the key, so a renamed/edited file can't
            # masquerade as a different key.
            out.append({"key_id": key_id(raw), "public_key": raw,
                        "name": str(data.get("name", "")), "added": str(data.get("added", ""))})
        return out

    def verify(self, pack: bytes, signature_doc: bytes) -> dict[str, Any]:
        """Return the trusted key that signed ``pack``; raise if none did."""
        _need_crypto()
        try:
            doc = json.loads(signature_doc.decode("utf-8"))
            if not isinstance(doc, dict) or doc.get("algorithm") != "ed25519":
                raise ValueError
            sig = base64.b64decode(str(doc["signature"]), validate=True)
        except (ValueError, KeyError, TypeError, UnicodeDecodeError):
            raise RulePackError("signature file is not a valid Warden signature") from None
        keys = self.trusted_keys()
        if not keys:
            raise RulePackError("no trusted signing keys - add one with 'warden rules trust <key.pub>'")
        claimed = str(doc.get("key_id", ""))
        # Try the claimed key first, but accept a match from any trusted key.
        for k in sorted(keys, key=lambda k: k["key_id"] != claimed):
            try:
                Ed25519PublicKey.from_public_bytes(k["public_key"]).verify(sig, _DOMAIN + pack)
            except (InvalidSignature, ValueError):
                continue
            return k
        raise RulePackError("signature does not verify against any trusted key "
                            "(pack was altered, or its signer is not trusted)")

    # -- state ------------------------------------------------------------
    def _state(self) -> dict[str, Any]:
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def _save_state(self, state: dict[str, Any]) -> None:
        atomic_write_json(self.state_path, state, mode=0o600)

    def _version_dir(self, name: str, version: int) -> Path:
        return self.root / name / str(int(version))

    # -- actions ----------------------------------------------------------
    def install(self, pack: bytes, signature_doc: bytes | None = None, *,
                allow_unsigned: bool = False, allow_downgrade: bool = False) -> PackInfo:
        signer: dict[str, Any] | None = None
        if signature_doc is not None:
            signer = self.verify(pack, signature_doc)
        elif not allow_unsigned:
            raise RulePackError("pack has no signature; refusing to install "
                                "(pass --allow-unsigned only for packs you built yourself)")
        manifest, files = read_pack(pack)
        _compile_check(files)
        name, version = manifest["name"], int(manifest["version"])

        secure_dir(self.root)
        with file_lock(self._lock):
            state = self._state()
            entry = _as_dict(state.get(name))
            active = entry.get("active")
            if isinstance(active, int) and version <= active and not allow_downgrade:
                raise RulePackError(
                    f"{name} version {version} is not newer than the active version {active}; "
                    f"refusing to downgrade (use 'warden rules rollback {name}' to go back, "
                    f"or --allow-downgrade)")
            final = self._version_dir(name, version)
            final.parent.mkdir(parents=True, exist_ok=True)
            tmp = Path(tempfile.mkdtemp(dir=str(final.parent), prefix=".install-"))
            try:
                for rel, blob in files.items():
                    dest = tmp / rel
                    # Belt and braces: the name was validated, but confirm the
                    # resolved path really is inside the staging directory.
                    if not dest.resolve().is_relative_to(tmp.resolve()):
                        raise RulePackError(f"unsafe file name in pack: {rel!r}")
                    atomic_write_bytes(dest, blob)
                atomic_write_json(tmp / "manifest.json", manifest)
                if final.exists():
                    shutil.rmtree(final)
                os.replace(tmp, final)
            except BaseException:
                shutil.rmtree(tmp, ignore_errors=True)
                raise

            history = [v for v in entry.get("history", []) if isinstance(v, int) and v != version]
            if isinstance(active, int) and active != version:
                history.append(active)
            installed = _as_dict(entry.get("installed"))
            installed[str(version)] = {
                "installed_at": now_iso(),
                "key_id": signer["key_id"] if signer else None,
                "signer": signer["name"] if signer else None,
                "sha256": hashlib.sha256(pack).hexdigest(),
            }
            # Keep a bounded number of previous versions for rollback.
            for old in history[:-_KEEP_OLD_VERSIONS]:
                shutil.rmtree(self._version_dir(name, old), ignore_errors=True)
                installed.pop(str(old), None)
            history = history[-_KEEP_OLD_VERSIONS:]
            state[name] = {"active": version, "history": history, "installed": installed}
            self._save_state(state)
        return next(p for p in self.packs() if p.name == name and p.active)

    def rollback(self, name: str) -> PackInfo:
        """Re-activate the previously active version of a pack."""
        with file_lock(self._lock):
            state = self._state()
            entry = state.get(name)
            if not isinstance(entry, dict):
                raise RulePackError(f"no rule pack named '{name}' is installed")
            history = [v for v in entry.get("history", []) if isinstance(v, int)]
            while history:
                previous = history.pop()
                if self._version_dir(name, previous).is_dir():
                    break
            else:
                raise RulePackError(f"'{name}' has no earlier version to roll back to")
            entry["active"], entry["history"] = previous, history
            state[name] = entry
            self._save_state(state)
        return next(p for p in self.packs() if p.name == name and p.active)

    def remove(self, name: str) -> None:
        if not _NAME_RE.match(name or ""):
            raise RulePackError("invalid pack name")
        with file_lock(self._lock):
            state = self._state()
            if name not in state:
                raise RulePackError(f"no rule pack named '{name}' is installed")
            state.pop(name)
            self._save_state(state)
            shutil.rmtree(self.root / name, ignore_errors=True)

    def packs(self) -> list[PackInfo]:
        out: list[PackInfo] = []
        for name, entry in sorted(self._state().items()):
            if not isinstance(entry, dict) or not _NAME_RE.match(str(name)):
                continue
            installed = _as_dict(entry.get("installed"))
            versions = [entry.get("active"), *reversed(entry.get("history", []))]
            for v in versions:
                if not isinstance(v, int):
                    continue
                d = self._version_dir(name, v)
                meta = _as_dict(installed.get(str(v)))
                manifest = _load_manifest(d)
                out.append(PackInfo(
                    name=name, version=v, active=(v == entry.get("active")),
                    installed_at=str(meta.get("installed_at", "")),
                    key_id=meta.get("key_id"), signer=meta.get("signer"),
                    files=len(manifest.get("files", {})) if manifest else 0,
                    description=str(manifest.get("description", "")) if manifest else "",
                    path=str(d)))
        return out

    def active_dirs(self) -> tuple[list[Path], list[str]]:
        """Directories of active packs that pass an on-disk integrity check,
        plus a warning for each pack that doesn't (and so isn't loaded)."""
        dirs: list[Path] = []
        warnings: list[str] = []
        for name, entry in sorted(self._state().items()):
            if not isinstance(entry, dict) or not isinstance(entry.get("active"), int):
                continue
            if not _NAME_RE.match(str(name)):
                continue
            d = self._version_dir(name, entry["active"])
            problem = verify_installed(d)
            if problem:
                warnings.append(f"rule pack '{name}' v{entry['active']} not loaded: {problem}")
            else:
                dirs.append(d)
        return dirs, warnings


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _load_manifest(d: Path) -> dict[str, Any] | None:
    try:
        data = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def verify_installed(d: Path) -> str | None:
    """None if an installed pack directory matches its manifest, else why not."""
    manifest = _load_manifest(d)
    if manifest is None or not isinstance(manifest.get("files"), dict):
        return "manifest is missing or unreadable"
    listed = manifest["files"]
    for rel, digest in listed.items():
        try:
            _validate_member_name(str(rel))
            actual = hashlib.sha256((d / rel).read_bytes()).hexdigest()
        except (OSError, RulePackError):
            return f"file {rel!r} is missing or unreadable"
        if actual != digest:
            return f"file {rel!r} was modified after installation"
    # A rule file that isn't in the manifest was planted, not installed.
    for f in d.rglob("*"):
        if f.is_file() and f.name != "manifest.json" and f.relative_to(d).as_posix() not in listed:
            return f"unexpected file {f.relative_to(d).as_posix()!r} in the pack directory"
    return None
