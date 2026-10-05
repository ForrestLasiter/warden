"""Third-party license notices.

Warden is MIT-licensed, but a Warden *binary* also contains other people's
software: the Python runtime, the YARA-X engine, and a handful of libraries. Their
licenses (BSD, MIT, Apache-2.0, MPL-2.0, PSF, ISC) all allow redistribution on one
shared condition - that the copyright notice and license text travel with the
copy. This module assembles exactly that text from what is actually installed.

  * At build time the PyInstaller spec calls ``notices_text(frozen=True)`` and
    bundles the result, so each platform's binary carries the notices for the
    precise versions inside it.
  * ``warden licenses`` prints it (the bundled file in a binary; assembled live
    from package metadata when running from source).

Nothing here is legal advice; it is a faithful reproduction of upstream texts.
"""

from __future__ import annotations

import re
import sys
from importlib import metadata
from pathlib import Path
from typing import Any

_HERE = Path(__file__).parent
BUNDLED = _HERE / "THIRD_PARTY_NOTICES.txt"      # written into frozen builds
_VENDORED = _HERE / "licenses"                   # texts for packages that ship none
ROOT_DIST = "warden-scanner"

_LICENSE_FILE_RE = re.compile(r"(^|/)(LICEN[CS]E|COPYING|NOTICE)[^/]*$|/licenses/[^/]+$", re.I)
_MAX_LICENSE_BYTES = 200 * 1024

# Components that are part of every binary but are not Python distributions, so
# they have no package metadata to read.
_RUNTIME_COMPONENTS = [
    ("Python", "PSF-2.0", "https://docs.python.org/3/license.html",
     "The CPython interpreter and standard library are bundled in the binary. "
     "Copyright (c) Python Software Foundation; licensed under the PSF License "
     "Agreement. The interpreter also incorporates components under their own "
     "terms, listed at the URL above."),
    ("OpenSSL", "Apache-2.0", "https://www.openssl.org/source/license.html",
     "OpenSSL is included through Python's ssl/hashlib modules and the "
     "cryptography library. Copyright (c) The OpenSSL Project Authors; licensed "
     "under the Apache License 2.0."),
    ("YARA-X bundled Rust crates", "various (MIT / Apache-2.0 / BSD)",
     "https://github.com/VirusTotal/yara-x/blob/main/Cargo.lock",
     "The yara-x extension statically links Rust crates. Their names and versions "
     "are listed in the upstream Cargo.lock at the URL above; each is under its "
     "own permissive license, available from https://crates.io."),
]
_PYINSTALLER_NOTE = (
    "PyInstaller bootloader", "GPL-2.0-or-later WITH Bootloader-exception",
    "https://pyinstaller.org/en/stable/license.html",
    "This executable was produced with PyInstaller, whose bootloader is embedded "
    "in it. PyInstaller's license includes a special exception that permits "
    "distributing the bundled application, including the bootloader, under any "
    "terms - it places no licensing requirement on Warden.")


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _requirements(dist: metadata.Distribution) -> list[str]:
    """Names of the distributions ``dist`` needs in THIS environment."""
    out: list[str] = []
    for req in dist.requires or []:
        spec, _, marker = req.partition(";")
        if "extra ==" in marker or "extra==" in marker:
            continue                      # optional extras (dev tools) are not shipped
        if marker.strip() and not _marker_true(marker):
            continue
        name = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", spec)
        if name:
            out.append(name.group(1))
    return out


def _marker_true(marker: str) -> bool:
    try:
        from packaging.markers import Marker  # present wherever pip is
        return bool(Marker(marker.strip()).evaluate())
    except Exception:  # noqa: BLE001 - no 'packaging', or an odd marker: include it
        return True


def _license_name(dist: metadata.Distribution) -> str:
    meta: Any = dist.metadata      # email.message.Message at runtime
    expr = meta.get("License-Expression")
    if expr:
        return str(expr)
    classifiers = [c.split("::")[-1].strip() for c in meta.get_all("Classifier", []) or []
                   if c.startswith("License ::")]
    declared = (meta.get("License") or "").strip()
    if declared and len(declared) < 80 and "\n" not in declared:
        return declared
    return ", ".join(classifiers) or "see license text"


def _license_texts(dist: metadata.Distribution, name: str) -> list[tuple[str, str]]:
    texts: list[tuple[str, str]] = []
    for f in dist.files or []:
        rel = str(f).replace("\\", "/")
        if ".dist-info/" not in rel and not rel.endswith((".txt", ".md", "LICENSE")):
            continue
        if not _LICENSE_FILE_RE.search(rel):
            continue
        try:
            path = Path(str(dist.locate_file(f)))
            if path.stat().st_size > _MAX_LICENSE_BYTES:
                continue
            texts.append((rel.rsplit("/", 1)[-1], path.read_text(encoding="utf-8", errors="replace").strip()))
        except OSError:
            continue
    vendored = _VENDORED / f"{_norm(name)}.txt"
    if not texts and vendored.is_file():
        texts.append((vendored.name, vendored.read_text(encoding="utf-8", errors="replace").strip()))
    return texts


def collect(root: str = ROOT_DIST) -> list[dict[str, Any]]:
    """Warden and everything it depends on (transitively), as installed here."""
    seen: dict[str, dict[str, Any]] = {}
    queue = [root]
    while queue:
        name = queue.pop(0)
        key = _norm(name)
        if key in seen:
            continue
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            continue
        meta: Any = dist.metadata
        url = meta.get("Home-page") or next(
            (u.split(",", 1)[1].strip() for u in meta.get_all("Project-URL", []) or [] if "," in u), "")
        seen[key] = {
            "name": meta.get("Name") or name, "version": dist.version,
            "license": _license_name(dist), "url": url,
            "texts": _license_texts(dist, meta.get("Name") or name),
        }
        queue.extend(_requirements(dist))
    ordered = sorted(seen.values(), key=lambda p: (_norm(p["name"]) != _norm(root), _norm(p["name"])))
    return ordered


def summary(packages: list[dict[str, Any]] | None = None) -> list[tuple[str, str, str]]:
    """(name, version, license) rows - the short form."""
    return [(p["name"], p["version"], p["license"]) for p in (packages or collect())]


def notices_text(*, frozen: bool | None = None) -> str:
    """The full notice document."""
    if frozen is None:
        frozen = bool(getattr(sys, "frozen", False))
        if frozen and BUNDLED.is_file():
            return BUNDLED.read_text(encoding="utf-8", errors="replace")
    packages = collect()
    rule = "=" * 78
    lines = [
        "WARDEN - THIRD-PARTY SOFTWARE NOTICES",
        rule,
        "Warden itself is licensed under the MIT License (first entry below).",
        "This distribution also contains the third-party software listed here.",
        "Each component is provided under its own license, reproduced in full.",
        "",
        "Components:",
    ]
    lines += [f"  - {n} {v}  ({lic})" for n, v, lic in summary(packages)]
    components = list(_RUNTIME_COMPONENTS) + ([_PYINSTALLER_NOTE] if frozen else [])
    lines += [f"  - {n}  ({lic})" for n, lic, _url, _note in components]
    lines.append("")
    for p in packages:
        lines += [rule, f"{p['name']} {p['version']}", f"License: {p['license']}"]
        if p["url"]:
            lines.append(f"Project: {p['url']}")
        lines.append(rule)
        if p["texts"]:
            for fname, text in p["texts"]:
                lines += ["", f"--- {fname} ---", text]
        else:
            lines += ["", "(No license file is shipped inside this package; see the project URL.)"]
        lines.append("")
    for name, lic, url, note in components:
        lines += [rule, name, f"License: {lic}", f"Details: {url}", rule, "", note, ""]
    return "\n".join(lines).rstrip() + "\n"


if __name__ == "__main__":      # python -m warden.notices [--frozen] > THIRD_PARTY_NOTICES.txt
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    sys.stdout.write(notices_text(frozen="--frozen" in sys.argv[1:]))
