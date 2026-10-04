"""End-to-end tests of scripts/install.sh against a fake, local "release".

`curl` and `uname` are replaced by stubs on PATH, so nothing touches the
network: the stub `curl` serves files from a directory that plays the part of a
GitHub release. The "binary" is a tiny shell script that answers `version`.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.name == "nt" or shutil.which("sh") is None, reason="POSIX shell installer")

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "install.sh"
ASSET = "warden-linux-x64"


def _exe(path: Path, text: str) -> None:
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class Env:
    def __init__(self, tmp: Path):
        self.release = tmp / "release"
        self.bin = tmp / "bin"
        self.home = tmp / "home"
        self.stubs = tmp / "stubs"
        for d in (self.release, self.home, self.stubs):
            d.mkdir()
        # curl stub: `curl -fSL <url> -o <dest>` -> copy <release>/<basename of url>.
        _exe(self.stubs / "curl", f"""#!/bin/sh
url=""; dest=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) shift; dest="$1" ;;
    -*) ;;
    *) url="$1" ;;
  esac
  shift
done
src="{self.release}/$(basename "$url")"
[ -f "$src" ] || exit 22
cp "$src" "$dest"
""")
        _exe(self.stubs / "uname", '#!/bin/sh\ncase "$1" in -m) echo x86_64 ;; *) echo Linux ;; esac\n')

    def publish(self, version: str, *, works: bool = True, sums: bool = True,
                wrong_sum: bool = False, listed: bool = True) -> None:
        body = f'#!/bin/sh\n[ "$1" = version ] && echo "Warden {version}" && exit 0\nexit 0\n'
        if not works:
            body = "#!/bin/sh\nexit 1\n"
        (self.release / ASSET).write_text(body)
        digest = hashlib.sha256(body.encode()).hexdigest()
        if wrong_sum:
            digest = "0" * 64
        target = self.release / "SHA256SUMS"
        if sums:
            name = ASSET if listed else "some-other-file"
            target.write_text(f"{digest}  {name}\n")
        elif target.exists():
            target.unlink()

    def run(self, *args: str) -> subprocess.CompletedProcess:
        env = {**os.environ, "PATH": f"{self.stubs}{os.pathsep}{os.environ['PATH']}",
               "HOME": str(self.home)}
        return subprocess.run(
            ["sh", str(SCRIPT), "--install-dir", str(self.bin), "--no-shortcuts", "--no-path", *args],
            capture_output=True, text=True, env=env, timeout=60)

    def installed(self) -> str:
        out = subprocess.run([str(self.bin / "warden"), "version"], capture_output=True, text=True)
        return out.stdout.strip()


@pytest.fixture()
def env(tmp_path):
    return Env(tmp_path)


def test_fresh_install_verifies_and_installs(env):
    env.publish("1.0.0")
    res = env.run()
    assert res.returncode == 0, res.stderr
    assert "Checksum verified." in res.stdout and "Installed Warden 1.0.0" in res.stdout
    assert env.installed() == "Warden 1.0.0"
    assert not (env.bin / "warden.previous").exists()


def test_rerun_is_idempotent(env):
    env.publish("1.0.0")
    env.run()
    res = env.run()
    assert res.returncode == 0 and "already installed" in res.stdout
    assert env.installed() == "Warden 1.0.0"


def test_upgrade_keeps_previous_and_rollback_swaps(env):
    env.publish("1.0.0")
    env.run()
    env.publish("2.0.0")
    res = env.run()
    assert res.returncode == 0 and "Upgraded Warden 1.0.0 -> 2.0.0" in res.stdout
    assert env.installed() == "Warden 2.0.0" and (env.bin / "warden.previous").exists()

    res = env.run("--rollback")
    assert res.returncode == 0 and "now version 1.0.0" in res.stdout
    assert env.installed() == "Warden 1.0.0"
    assert env.run("--rollback").returncode == 0           # and back again
    assert env.installed() == "Warden 2.0.0"


def test_rollback_without_previous_fails(env):
    env.publish("1.0.0")
    env.run()
    res = env.run("--rollback")
    assert res.returncode == 1 and "No previous version" in res.stderr


def test_broken_upgrade_restores_previous(env):
    env.publish("1.0.0")
    env.run()
    env.publish("2.0.0", works=False)                      # verifies, but won't start
    res = env.run()
    assert res.returncode == 1 and "restored version 1.0.0" in res.stderr
    assert env.installed() == "Warden 1.0.0"


def test_broken_first_install_leaves_nothing(env):
    env.publish("1.0.0", works=False)
    res = env.run()
    assert res.returncode == 1 and "nothing was installed" in res.stderr
    assert not (env.bin / "warden").exists()


def test_checksum_mismatch_is_always_fatal(env):
    env.publish("1.0.0")
    env.run()
    env.publish("6.6.6", wrong_sum=True)
    for extra in ((), ("--allow-unverified",)):            # never overridable
        res = env.run(*extra)
        assert res.returncode == 1 and "MISMATCH" in res.stderr
        assert env.installed() == "Warden 1.0.0"


def test_fails_closed_without_checksums(env):
    env.publish("1.0.0", sums=False)
    res = env.run()
    assert res.returncode == 1 and "Refusing to install unverified" in res.stderr
    assert not (env.bin / "warden").exists()

    env.publish("1.0.0", listed=False)                     # SHA256SUMS exists, asset not in it
    res = env.run()
    assert res.returncode == 1 and "does not list" in res.stderr
    assert not (env.bin / "warden").exists()


def test_allow_unverified_is_an_explicit_override(env):
    env.publish("1.0.0", sums=False)
    res = env.run("--allow-unverified")
    assert res.returncode == 0 and "WARNING" in res.stderr
    assert env.installed() == "Warden 1.0.0"


def test_uninstall_removes_binaries_but_not_data(env):
    env.publish("1.0.0")
    env.run()
    env.publish("2.0.0")
    env.run()
    data = env.home / ".warden"
    data.mkdir()
    (data / "config.json").write_text("{}")
    res = env.run("--uninstall")
    assert res.returncode == 0
    assert not (env.bin / "warden").exists() and not (env.bin / "warden.previous").exists()
    assert (data / "config.json").exists()


def test_help_and_unknown_option(env):
    res = env.run("--help")
    assert res.returncode == 0 and "--rollback" in res.stdout and "set -eu" not in res.stdout
    assert env.run("--bogus").returncode == 2
