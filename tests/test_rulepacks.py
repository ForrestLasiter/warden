"""Signed rule packs: trust, verification, install, downgrade refusal, rollback,
on-disk tamper detection."""

from __future__ import annotations

import base64
import io
import json
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from warden import net, rulepacks
from warden.cli import app
from warden.config import Config
from warden.rulepacks import RulePackError, RulePackManager
from warden.scanner import Scanner

runner = CliRunner()

RULE_V1 = 'rule Pack_Marker_One { strings: $a = "WARDEN-PACK-MARKER-ONE" condition: $a }\n'
RULE_V2 = 'rule Pack_Marker_Two { strings: $a = "WARDEN-PACK-MARKER-TWO" condition: $a }\n'


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _src(tmp_path: Path, rule: str, name: str = "src") -> Path:
    d = tmp_path / name
    (d / "rules").mkdir(parents=True, exist_ok=True)
    (d / "rules" / "marker.yar").write_text(rule, encoding="utf-8")
    return d


@pytest.fixture()
def env(tmp_path):
    cfg = Config(data_dir=tmp_path / "data")
    mgr = RulePackManager(cfg)
    priv, pub = rulepacks.generate_keypair()
    mgr.trust(_b64(pub), "Test Org")
    return cfg, mgr, priv, pub


def _signed(tmp_path, priv, rule, version, name="corp"):
    pack = rulepacks.build_pack(_src(tmp_path, rule, f"src{version}"), name, version, "test pack")
    return pack, rulepacks.sign_pack(pack, priv)


def _retamper(pack: bytes, member: str, new: bytes, *, fix_manifest: bool) -> bytes:
    """Rewrite one member of a pack (optionally fixing up the manifest hash)."""
    import hashlib
    src = zipfile.ZipFile(io.BytesIO(pack))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as dst:
        for info in src.infolist():
            blob = src.read(info)
            if info.filename == member:
                blob = new
            if info.filename == "manifest.json" and fix_manifest:
                m = json.loads(blob)
                m["files"][member] = hashlib.sha256(new).hexdigest()
                blob = json.dumps(m).encode()
            dst.writestr(info.filename, blob)
    return out.getvalue()


# -- signature + trust ---------------------------------------------------
def test_signed_pack_installs_and_rules_are_used(env, tmp_path):
    cfg, mgr, priv, _ = env
    pack, sig = _signed(tmp_path, priv, RULE_V1, 1)
    info = mgr.install(pack, sig)
    assert (info.name, info.version, info.active, info.signer) == ("corp", 1, True, "Test Org")

    result = Scanner(cfg).scan_bytes("note.txt", b"xx WARDEN-PACK-MARKER-ONE xx")
    assert "Pack_Marker_One" in {f.name for f in result.findings}


def test_unsigned_pack_refused_unless_explicit(env, tmp_path):
    _, mgr, _, _ = env
    pack = rulepacks.build_pack(_src(tmp_path, RULE_V1), "corp", 1)
    with pytest.raises(RulePackError, match="no signature"):
        mgr.install(pack, None)
    info = mgr.install(pack, None, allow_unsigned=True)
    assert info.key_id is None


def test_untrusted_or_wrong_signature_refused(env, tmp_path):
    _, mgr, priv, _ = env
    pack, sig = _signed(tmp_path, priv, RULE_V1, 1)

    other_priv, _ = rulepacks.generate_keypair()
    with pytest.raises(RulePackError, match="does not verify"):
        mgr.install(pack, rulepacks.sign_pack(pack, other_priv))

    # One flipped byte anywhere in the pack invalidates the signature.
    altered = bytearray(pack)
    altered[len(altered) // 2] ^= 0x01
    with pytest.raises(RulePackError):
        mgr.install(bytes(altered), sig)

    for bad in (b"not json", b"{}", json.dumps({"algorithm": "rsa", "signature": "AAAA"}).encode(),
                json.dumps({"algorithm": "ed25519", "signature": "!!!"}).encode()):
        with pytest.raises(RulePackError):
            mgr.install(pack, bad)
    assert mgr.packs() == []


def test_no_trusted_keys_means_nothing_verifies(tmp_path):
    mgr = RulePackManager(Config(data_dir=tmp_path / "data"))
    priv, _ = rulepacks.generate_keypair()
    pack, sig = _signed(tmp_path, priv, RULE_V1, 1)
    with pytest.raises(RulePackError, match="no trusted signing keys"):
        mgr.install(pack, sig)


def test_untrust_revokes(env, tmp_path):
    _, mgr, priv, pub = env
    pack, sig = _signed(tmp_path, priv, RULE_V1, 1)
    mgr.untrust(rulepacks.key_id(pub))
    with pytest.raises(RulePackError):
        mgr.install(pack, sig)
    with pytest.raises(RulePackError):
        mgr.untrust("zz")


def test_trust_store_ignores_edited_entries(env):
    _, mgr, _, pub = env
    kid = rulepacks.key_id(pub)
    # Renaming a key file can't make it claim another identity.
    (mgr.keys_dir / f"{kid}.json").rename(mgr.keys_dir / "0000000000000000.json")
    assert [k["key_id"] for k in mgr.trusted_keys()] == [kid]
    (mgr.keys_dir / "junk.json").write_text("{not json", encoding="utf-8")
    assert len(mgr.trusted_keys()) == 1
    with pytest.raises(RulePackError):
        mgr.trust("not-base64!!")
    with pytest.raises(RulePackError):
        mgr.trust(_b64(b"short"))


# -- versioning + rollback ----------------------------------------------
def test_downgrade_refused_and_rollback_restores_previous(env, tmp_path):
    cfg, mgr, priv, _ = env
    p1, s1 = _signed(tmp_path, priv, RULE_V1, 1)
    p2, s2 = _signed(tmp_path, priv, RULE_V2, 2)
    mgr.install(p1, s1)
    mgr.install(p2, s2)

    with pytest.raises(RulePackError, match="refusing to downgrade"):
        mgr.install(p1, s1)                      # replaying the old signed pack
    with pytest.raises(RulePackError, match="refusing to downgrade"):
        mgr.install(p2, s2)                      # same version again

    def detects(marker):
        r = Scanner(cfg).scan_bytes("n.txt", f"WARDEN-PACK-MARKER-{marker}".encode())
        return {f.name for f in r.findings}

    assert detects("TWO") == {"Pack_Marker_Two"} and detects("ONE") == set()

    back = mgr.rollback("corp")
    assert back.version == 1 and back.active
    assert detects("ONE") == {"Pack_Marker_One"} and detects("TWO") == set()

    with pytest.raises(RulePackError, match="no earlier version"):
        mgr.rollback("corp")
    with pytest.raises(RulePackError):
        mgr.rollback("missing")

    # An explicit downgrade is possible, but only when asked for.
    assert mgr.install(p1, s1, allow_downgrade=True).version == 1


def test_old_versions_are_pruned(env, tmp_path):
    _, mgr, priv, _ = env
    for v in range(1, 7):
        mgr.install(*_signed(tmp_path, priv, RULE_V1, v))
    versions = sorted(p.version for p in mgr.packs())
    assert versions == [3, 4, 5, 6]
    assert not (mgr.root / "corp" / "1").exists()


def test_remove(env, tmp_path):
    _, mgr, priv, _ = env
    mgr.install(*_signed(tmp_path, priv, RULE_V1, 1))
    mgr.remove("corp")
    assert mgr.packs() == [] and not (mgr.root / "corp").exists()
    with pytest.raises(RulePackError):
        mgr.remove("corp")
    with pytest.raises(RulePackError):
        mgr.remove("../etc")


# -- content validation --------------------------------------------------
def test_manifest_hash_mismatch_is_rejected(tmp_path):
    pack = rulepacks.build_pack(_src(tmp_path, RULE_V1), "corp", 1)
    bad = _retamper(pack, "rules/marker.yar", b"rule X { condition: true }", fix_manifest=False)
    with pytest.raises(RulePackError, match="hash mismatch"):
        rulepacks.read_pack(bad)


def test_rules_that_do_not_compile_are_rejected(env, tmp_path):
    _, mgr, priv, _ = env
    pack = rulepacks.build_pack(_src(tmp_path, RULE_V1), "corp", 1)
    broken = _retamper(pack, "rules/marker.yar", b"rule Broken { condition: ", fix_manifest=True)
    with pytest.raises(RulePackError, match="does not compile|do not build"):
        mgr.install(broken, rulepacks.sign_pack(broken, priv))
    assert mgr.packs() == []


@pytest.mark.parametrize("evil", [
    "../escape.yar", "/abs.yar", "a/../../b.yar", "C:/x.yar", "a\\b.yar", ".hidden.yar",
    "rules/run.exe", "rules/a.yar\x00.txt", "",
])
def test_unsafe_member_names_are_rejected(tmp_path, evil):
    import hashlib
    buf = io.BytesIO()
    body = RULE_V1.encode()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("manifest.json", json.dumps({
            "format": 1, "name": "corp", "version": 1,
            "files": {evil: hashlib.sha256(body).hexdigest()}}))
        if evil:
            try:
                zf.writestr(evil, body)
            except ValueError:
                pytest.skip("zipfile refuses to write this name")
    with pytest.raises(RulePackError):
        rulepacks.read_pack(buf.getvalue())
    assert not (tmp_path.parent / "escape.yar").exists()


@pytest.mark.parametrize("manifest", [
    {"format": 2, "name": "corp", "version": 1, "files": {"a.yar": "x"}},
    {"format": 1, "name": "Bad Name", "version": 1, "files": {"a.yar": "x"}},
    {"format": 1, "name": "corp", "version": 0, "files": {"a.yar": "x"}},
    {"format": 1, "name": "corp", "version": "1", "files": {"a.yar": "x"}},
    {"format": 1, "name": "corp", "version": True, "files": {"a.yar": "x"}},
    {"format": 1, "name": "corp", "version": 1, "files": {}},
    {"format": 1, "name": "corp", "version": 1, "files": {"missing.yar": "x"}},
    ["not", "a", "dict"],
])
def test_bad_manifests_are_rejected(manifest):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("manifest.json", json.dumps(manifest))
        zf.writestr("a.yar", RULE_V1)
    with pytest.raises(RulePackError):
        rulepacks.read_pack(buf.getvalue())


def test_not_a_zip_and_missing_manifest():
    with pytest.raises(RulePackError):
        rulepacks.read_pack(b"definitely not a zip")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.yar", RULE_V1)
    with pytest.raises(RulePackError, match="no manifest"):
        rulepacks.read_pack(buf.getvalue())


def test_failed_install_leaves_previous_version_active(env, tmp_path):
    cfg, mgr, priv, _ = env
    mgr.install(*_signed(tmp_path, priv, RULE_V1, 1))
    pack2 = rulepacks.build_pack(_src(tmp_path, RULE_V2, "s2"), "corp", 2)
    broken = _retamper(pack2, "rules/marker.yar", b"rule Broken {", fix_manifest=True)
    with pytest.raises(RulePackError):
        mgr.install(broken, rulepacks.sign_pack(broken, priv))
    (active,) = [p for p in mgr.packs() if p.active]
    assert active.version == 1
    assert not list((mgr.root / "corp").glob(".install-*"))     # no staging debris


# -- on-disk integrity ---------------------------------------------------
def test_tampered_installed_pack_is_not_loaded(env, tmp_path):
    cfg, mgr, priv, _ = env
    info = mgr.install(*_signed(tmp_path, priv, RULE_V1, 1))
    rule_file = Path(info.path) / "rules" / "marker.yar"

    rule_file.write_text("rule Allow_Everything { condition: false }\n", encoding="utf-8")
    dirs, warnings = mgr.active_dirs()
    assert dirs == [] and "modified after installation" in warnings[0]

    scanner = Scanner(cfg)
    assert any("not loaded" in w for w in scanner.engine_warnings)
    f = tmp_path / "x.txt"
    f.write_text("hello")
    report = scanner.scan_path(f)
    assert not report.coverage_complete      # degraded scan is never reported clean


def test_planted_file_in_pack_dir_is_detected(env, tmp_path):
    _, mgr, priv, _ = env
    info = mgr.install(*_signed(tmp_path, priv, RULE_V1, 1))
    (Path(info.path) / "extra.yar").write_text("rule X { condition: true }", encoding="utf-8")
    dirs, warnings = mgr.active_dirs()
    assert dirs == [] and "unexpected file" in warnings[0]


def test_corrupt_state_file_is_tolerated(env):
    cfg, mgr, _, _ = env
    mgr.root.mkdir(parents=True, exist_ok=True)
    for junk in ("{not json", "[1,2,3]", json.dumps({"../x": {"active": 1}, "ok": "nope", "p": {"active": "1"}})):
        mgr.state_path.write_text(junk, encoding="utf-8")
        assert mgr.packs() == []
        assert mgr.active_dirs() == ([], [])
        Scanner(cfg)      # must not raise


# -- CLI -----------------------------------------------------------------
def test_cli_end_to_end(home, tmp_path):
    src = _src(tmp_path, RULE_V1)
    keys = tmp_path / "keys"
    keys.mkdir()
    assert runner.invoke(app, ["rules", "keygen", "corp", "--out", str(keys)]).exit_code == 0
    assert runner.invoke(app, ["rules", "keygen", "corp", "--out", str(keys)]).exit_code == 2  # no overwrite
    pack = tmp_path / "corp-1.wrp"
    res = runner.invoke(app, ["rules", "build", str(src), "--name", "corp", "--version", "1",
                              "--key", str(keys / "corp.key"), "--out", str(pack)])
    assert res.exit_code == 0, res.output
    assert pack.exists() and Path(str(pack) + ".sig").exists()

    # Not trusted yet -> refused.
    assert runner.invoke(app, ["rules", "install", str(pack)]).exit_code == 2
    assert runner.invoke(app, ["rules", "trust", str(keys / "corp.pub"), "--name", "Corp"]).exit_code == 0
    assert "Corp" in runner.invoke(app, ["rules", "keys"]).output
    assert runner.invoke(app, ["rules", "verify", str(pack)]).exit_code == 0
    res = runner.invoke(app, ["rules", "install", str(pack)])
    assert res.exit_code == 0 and "Installed" in res.output
    assert "active" in runner.invoke(app, ["rules", "list"]).output

    marker = tmp_path / "m.txt"
    marker.write_text("WARDEN-PACK-MARKER-ONE")
    assert runner.invoke(app, ["scan", str(marker)]).exit_code == 1

    assert runner.invoke(app, ["rules", "rollback", "corp"]).exit_code == 2   # nothing earlier
    assert runner.invoke(app, ["rules", "remove", "corp"]).exit_code == 0
    assert runner.invoke(app, ["scan", str(marker)]).exit_code == 0


def test_cli_unsigned_pack_and_separate_sign(home, tmp_path):
    src = _src(tmp_path, RULE_V1)
    pack = tmp_path / "p.wrp"
    assert runner.invoke(app, ["rules", "build", str(src), "--name", "p", "--version", "3",
                               "--out", str(pack)]).exit_code == 0
    assert runner.invoke(app, ["rules", "verify", str(pack)]).exit_code == 1    # structure ok, unsigned
    assert runner.invoke(app, ["rules", "install", str(pack)]).exit_code == 2
    assert runner.invoke(app, ["rules", "install", str(pack), "--allow-unsigned"]).exit_code == 0

    keys = tmp_path / "k"
    keys.mkdir()
    runner.invoke(app, ["rules", "keygen", "me", "--out", str(keys)])
    assert runner.invoke(app, ["rules", "sign", str(pack), "--key", str(keys / "me.key")]).exit_code == 0
    assert Path(str(pack) + ".sig").exists()


def test_cli_url_install_blocked_offline(home, monkeypatch):
    def boom(*a, **kw):
        raise AssertionError("network was used")

    if net.httpx is not None:
        monkeypatch.setattr(net.httpx, "stream", boom)
    res = runner.invoke(app, ["--offline", "rules", "install", "https://example.com/p.wrp"])
    assert res.exit_code == 2 and "offline" in res.output.lower()
    net.set_offline(False)
    # Plain http is refused outright, online or not.
    assert runner.invoke(app, ["rules", "install", "http://example.com/p.wrp"]).exit_code == 2
