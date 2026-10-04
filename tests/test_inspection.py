"""Tests for content inspection: executable metadata, archives, documents and
code-signature reporting. All inputs are synthetic and built in memory."""

from __future__ import annotations

import gzip
import struct
import sys
import types
from pathlib import Path

import pytest
from _builders import (
    make_elf64,
    make_macho64,
    make_ole,
    make_ooxml,
    make_tar,
    make_vba_project,
    make_zip,
    mark_zip_encrypted,
    vba_compress,
)

from warden import binfmt, signature
from warden.archive import ArchiveLimits, ArchiveStats, archive_kind, iter_members
from warden.config import Config
from warden.engines.base import ScanContext
from warden.engines.documents import (
    DocumentEngine,
    extract_vba_source,
    ole_streams,
    vba_decompress,
)
from warden.models import Severity
from warden.scanner import Scanner

# EICAR assembled at runtime and only ever held in memory.
EICAR = (
    "X5O!P%@AP[4" + chr(92) + "PZX54(P^)7CC)7}"
    + chr(36) + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" + chr(36) + "H+H*"
).encode()


@pytest.fixture()
def scanner(tmp_path):
    return Scanner(Config(data_dir=tmp_path / "data"))


def _names(findings):
    return {f.name for f in findings}


# -- executable metadata -------------------------------------------------
def test_identify_formats():
    assert binfmt.identify(b"MZ" + b"\x00" * 62) == "pe"
    assert binfmt.identify(make_elf64()) == "elf"
    assert binfmt.identify(make_macho64()) == "macho"
    assert binfmt.identify(b"plain text") is None
    # A Java class file shares the fat Mach-O magic but is NOT a Mach-O.
    assert binfmt.identify(b"\xca\xfe\xba\xbe" + struct.pack(">HH", 0, 52)) is None
    assert binfmt.identify(b"\xca\xfe\xba\xbe" + struct.pack(">I", 2) + b"\x00" * 40) == "macho"


def test_elf_metadata_and_observations():
    info = binfmt.binary_info(make_elf64(rwx=True, sections=False, upx=True))
    assert info["format"] == "elf" and info["arch"] == "x86_64" and info["bits"] == 64
    assert info["type"] == "executable"
    assert info["interpreter"] == "/lib64/ld-linux-x86-64.so.2"
    ids = {o["id"] for o in info["observations"]}
    assert {"elf-rwx-segment", "elf-no-section-headers", "elf-packed-upx"} <= ids

    clean = binfmt.binary_info(make_elf64())
    assert "elf-rwx-segment" not in {o["id"] for o in clean["observations"]}


def test_macho_metadata_signature_and_rwx():
    unsigned = binfmt.binary_info(make_macho64(rwx=True))
    assert unsigned["format"] == "macho" and unsigned["arch"] == "arm64"
    assert unsigned["signature_embedded"] is False
    ids = {o["id"] for o in unsigned["observations"]}
    assert {"macho-rwx-segment", "macho-unsigned-arm64"} <= ids

    signed = binfmt.binary_info(make_macho64(signed=True))
    assert signed["signature_embedded"] is True
    assert not signed["observations"]


def test_running_interpreter_is_described():
    """The real Python binary on this machine parses as this platform's format."""
    data = Path(sys.executable).read_bytes()
    info = binfmt.binary_info(data)
    assert info is not None
    assert info["format"] in ("pe", "elf", "macho")
    assert info.get("arch")


@pytest.mark.parametrize("blob", [
    b"MZ", b"MZ" + b"\xff" * 300, b"\x7fELF", b"\x7fELF\x02\x01" + b"\xff" * 80,
    b"\xcf\xfa\xed\xfe" + b"\xff" * 64, b"\xca\xfe\xba\xbe\x00\x00\x00\x05" + b"\xff" * 200,
    b"\x7fELF\x01\x02" + b"\x00" * 60,
])
def test_malformed_binaries_never_raise(blob):
    binfmt.binary_info(blob)   # must not raise; any return value is acceptable


def test_scanner_attaches_binary_meta(scanner, tmp_path):
    f = tmp_path / "tool"
    f.write_bytes(make_elf64(rwx=True))
    report = scanner.scan_path(f)
    result = report.results[0]
    assert result.meta["binary"]["format"] == "elf"
    assert "observations" not in result.meta["binary"]
    assert "elf-rwx-segment" in _names(result.findings)
    assert report.to_dict()["results"][0]["meta"]["binary"]["arch"] == "x86_64"


# -- archives ------------------------------------------------------------
def test_archive_kind_by_magic_not_extension():
    assert archive_kind(make_zip({"a.txt": b"x"})) == "zip"
    assert archive_kind(gzip.compress(b"x")) == "gzip"
    assert archive_kind(make_tar({"a": b"x"})) == "tar"
    assert archive_kind(b"just text") is None


def test_threat_inside_zip_is_found_and_attributed(scanner):
    blob = make_zip({"docs/readme.txt": b"hello", "docs/payload.com": EICAR})
    result = scanner.scan_bytes("bundle.zip", blob)
    hits = [f for f in result.findings if f.name == "EICAR_Test_File"]
    assert hits and hits[0].severity == Severity.CRITICAL
    assert hits[0].meta["archive_member"] == "bundle.zip!/docs/payload.com"
    assert "inside bundle.zip!/docs/payload.com" in hits[0].description
    assert result.meta["archive"]["members_scanned"] == 2


def test_nested_archives_are_walked(scanner):
    inner = make_zip({"evil.com": EICAR})
    outer = make_tar({"layer.zip": inner})
    result = scanner.scan_bytes("backup.tar.gz", gzip.compress(outer))
    assert "EICAR_Test_File" in _names(result.findings)


def test_nesting_depth_is_bounded(scanner):
    blob = EICAR
    for i in range(6):
        blob = make_zip({f"level{i}.zip": blob})
    result = scanner.scan_bytes("deep.zip", blob)
    assert "EICAR_Test_File" not in _names(result.findings)   # too deep to reach
    assert "archive-partially-scanned" in _names(result.findings)
    assert result.meta["archive"]["complete"] is False


def test_decompression_bomb_is_stopped_and_flagged(scanner):
    scanner.archive_limits = ArchiveLimits(max_total_bytes=2 * 1024 * 1024, max_ratio=50)
    bomb = gzip.compress(b"\x00" * (16 * 1024 * 1024))
    assert len(bomb) < 64 * 1024
    result = scanner.scan_bytes("big.gz", bomb)
    assert "archive-bomb-suspected" in _names(result.findings)
    assert result.is_threat


def test_zip_bomb_with_many_members_respects_total_limit():
    limits = ArchiveLimits(max_total_bytes=1024 * 1024, max_ratio=10_000_000)
    stats = ArchiveStats()
    blob = make_zip({f"f{i}": b"\x00" * (512 * 1024) for i in range(8)})
    got = list(iter_members(blob, "z.zip", limits, stats))
    assert len(got) <= 2 and stats.truncated
    assert stats.total_bytes <= limits.max_total_bytes + 512 * 1024


def test_member_count_limit():
    limits = ArchiveLimits(max_members=5)
    stats = ArchiveStats()
    blob = make_zip({f"f{i}.txt": b"x" for i in range(20)})
    assert len(list(iter_members(blob, "z.zip", limits, stats))) == 5
    assert stats.truncated and stats.members_skipped == 15


def test_encrypted_members_are_reported_not_ignored(scanner):
    blob = mark_zip_encrypted(make_zip({"secret.exe": b"MZ" + b"\x00" * 64}))
    result = scanner.scan_bytes("locked.zip", blob)
    assert "encrypted-archive-member" in _names(result.findings)
    assert result.meta["archive"]["encrypted_members"] == 1
    assert result.meta["archive"]["complete"] is False


def test_traversal_names_never_touch_disk(scanner, tmp_path):
    before = sorted(p.name for p in tmp_path.iterdir())
    blob = make_zip({"../../../escape.txt": b"x", "/abs/evil.txt": b"y", "C:\\evil.txt": b"z"})
    target = tmp_path / "t.zip"
    target.write_bytes(blob)
    report = scanner.scan_path(target)
    assert report.archive_members_scanned == 3
    after = sorted(p.name for p in tmp_path.iterdir())
    assert after == sorted(before + ["t.zip"])
    assert not (tmp_path.parent / "escape.txt").exists()


def test_control_characters_in_member_names_are_neutralized(scanner):
    blob = make_zip({"a\x1b[31mred\nline.pdf.exe": b"data"})
    result = scanner.scan_bytes("x.zip", blob)
    tags = [f.meta["archive_member"] for f in result.findings if "archive_member" in f.meta]
    assert tags and all("\x1b" not in t and "\n" not in t for t in tags)


def test_corrupt_archives_do_not_raise(scanner):
    good = make_zip({"a.txt": b"hello world"})
    for blob in (good[:30], good[:-10], b"PK\x03\x04" + b"\xff" * 200,
                 b"\x1f\x8b\x08" + b"\xff" * 50, b"BZh9" + b"\x00" * 50,
                 b"\xfd7zXZ\x00" + b"\x01" * 50, b"\x00" * 257 + b"ustar\x00" + b"\xff" * 300):
        scanner.scan_bytes("broken.bin", blob)


def test_scan_reports_archive_coverage(scanner, tmp_path):
    (tmp_path / "a.zip").write_bytes(make_zip({"invoice.pdf.exe": b"not really"}))
    report = scanner.scan_path(tmp_path / "a.zip")
    assert report.archives_opened == 1 and report.archive_members_scanned == 1
    assert report.threats, "double-extension member inside the zip should be flagged"
    cov = report.coverage()
    assert cov["archives_opened"] == 1 and cov["archive_members_skipped"] == 0


def test_archive_scanning_can_be_disabled(tmp_path):
    cfg = Config(data_dir=tmp_path / "data")
    cfg.scan_archives = False
    (tmp_path / "a.zip").write_bytes(make_zip({"invoice.pdf.exe": b"not really"}))
    report = Scanner(cfg).scan_path(tmp_path / "a.zip")
    assert report.archives_opened == 0 and not report.threats


def test_archive_members_never_trigger_online_lookups(tmp_path):
    calls = []

    class FakeReputation:
        available = True
        status = "fake"

        def check(self, sha256, sha1):
            calls.append(sha256)
            return None

    s = Scanner(Config(data_dir=tmp_path / "data"))
    s.hashes._reputation = FakeReputation()
    s.scan_bytes("pack.zip", make_zip({"a.exe": b"MZ" + b"\x00" * 100, "b.dll": b"MZ" + b"\x01" * 100}))
    assert calls == []


# -- VBA / OLE -----------------------------------------------------------
def test_vba_decompress_spec_vectors():
    # MS-OVBA 3.2.3 "Maximum Compression Example".
    assert vba_decompress(bytes.fromhex("0103b002614500")) == b"a" * 73
    # MS-OVBA 3.2.2 "Normal Compression Example".
    packed = bytes.fromhex(
        "012fb00023616161626364658266007061676869 6a013808616b6c00306d6e6f7006710270"
        "0410727374757610777879 7a003c".replace(" ", ""))
    assert vba_decompress(packed) == b"#aaabcdefaaaaghijaaaaaklaaamnopqaaaaaaaaaaaarstuvwxyzaaa"


def test_vba_roundtrip_and_tolerance():
    src = b"Attribute VB_Name = \"Module1\"\r\nSub Hello()\r\nEnd Sub\r\n" * 200
    assert vba_decompress(vba_compress(src)) == src
    assert vba_decompress(b"") == b""
    assert vba_decompress(b"\x02garbage") == b""
    vba_decompress(b"\x01\xff\xbf" + b"\xff" * 100)   # malformed tokens: no exception
    # A stored (uncompressed) chunk is passed through verbatim.
    raw = bytes(range(256)) * 16
    assert vba_decompress(b"\x01" + struct.pack("<H", 0x3FFF) + raw) == raw


def test_ole_reader_regular_and_mini_streams():
    big = bytes(range(256)) * 20           # 5120 bytes -> regular sectors
    small = b"tiny stream"                 # -> mini stream
    streams = dict(ole_streams(make_ole({"Big": big, "Small": small})))
    assert streams["Big"] == big
    assert streams["Small"] == small


def test_ole_reader_survives_garbage():
    assert ole_streams(b"") == []
    assert ole_streams(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\xff" * 2000) == []
    good = make_ole({"A": b"x" * 5000})
    for cut in (520, 700, 1500):
        ole_streams(good[:cut])            # truncated: no exception
    mangled = bytearray(good)
    mangled[512:1024] = b"\x01\x00\x00\x00" * 128   # FAT full of self-referencing loops
    ole_streams(bytes(mangled))


def test_macro_source_is_recovered():
    code = 'Attribute VB_Name = "ThisDocument"\r\nSub AutoOpen()\r\n  Shell "calc.exe"\r\nEnd Sub\r\n'
    text = extract_vba_source(ole_streams(make_vba_project(code)))
    assert "Sub AutoOpen()" in text and 'Shell "calc.exe"' in text


# -- documents engine ----------------------------------------------------
def _doc(data: bytes, name: str):
    return DocumentEngine().scan(ScanContext.from_bytes(name, data))


def test_legacy_office_autoexec_macro_is_high():
    code = ('Attribute VB_Name = "ThisDocument"\r\nSub Document_Open()\r\n'
            '  CreateObject("WScript.Shell").Run "powershell -enc AAAA"\r\nEnd Sub\r\n')
    findings = _doc(make_vba_project(code), "invoice.doc")
    hit = next(f for f in findings if f.name == "office-macro-autoexec-suspicious")
    assert hit.severity == Severity.HIGH
    assert "document_open" in hit.meta["autoexec"]


def test_benign_macro_is_only_low():
    code = 'Attribute VB_Name = "Module1"\r\nSub Total()\r\n  Range("A1").Value = 1\r\nEnd Sub\r\n'
    findings = _doc(make_vba_project(code), "budget.xls")
    assert _names(findings) == {"office-macros-present"}
    assert all(f.severity <= Severity.LOW for f in findings)


def test_ooxml_macro_in_macro_free_extension():
    code = 'Attribute VB_Name = "M"\r\nSub AutoOpen()\r\n  Shell("cmd.exe /c whoami")\r\nEnd Sub\r\n'
    doc = make_ooxml({"word/vbaProject.bin": make_vba_project(code)})
    names = _names(_doc(doc, "report.docx"))
    assert "office-macro-extension-mismatch" in names
    assert "office-macro-autoexec-suspicious" in names
    # The same content under an honest macro-enabled name: no mismatch.
    assert "office-macro-extension-mismatch" not in _names(_doc(doc, "report.docm"))


def test_ooxml_remote_template_injection():
    rels = (b'<Relationships><Relationship Id="rId1" '
            b'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
            b'Target="https://evil.example/t.dotm" TargetMode="External"/></Relationships>')
    findings = _doc(make_ooxml({"word/_rels/settings.xml.rels": rels}), "cv.docx")
    hit = next(f for f in findings if f.name == "office-remote-template")
    assert hit.severity == Severity.HIGH and "evil.example" in hit.meta["target"]


def test_plain_zip_and_clean_ooxml_have_no_document_findings():
    assert _doc(make_zip({"a.txt": b"hi"}), "a.zip") == []
    assert _doc(make_ooxml({}), "clean.docx") == []


def test_ooxml_macro_not_double_reported_by_archive_walk(scanner):
    code = 'Attribute VB_Name = "M"\r\nSub AutoOpen()\r\n  Shell("cmd.exe /c whoami")\r\nEnd Sub\r\n'
    doc = make_ooxml({"word/vbaProject.bin": make_vba_project(code)})
    result = scanner.scan_bytes("report.docm", doc)
    macro = [f for f in result.findings if f.name == "office-macro-autoexec-suspicious"]
    assert len(macro) == 1


def test_pdf_active_content():
    launch = b"%PDF-1.7\n1 0 obj\n<< /Type /Action /S /Launch /F (cmd.exe) >>\nendobj\n"
    f = _doc(launch, "a.pdf")
    assert next(x for x in f if x.name == "pdf-launch-action").severity == Severity.MEDIUM

    # Hex-escaped name must still be recognized.
    js = b"%PDF-1.4\n1 0 obj\n<< /OpenAction 2 0 R /S /J#61vaScript /JS (app.alert(1)) >>\nendobj\n"
    hit = next(x for x in _doc(js, "b.pdf") if x.name == "pdf-javascript")
    assert hit.meta["automatic_action"] is True

    # Bytes inside a stream must not be mistaken for a name.
    noise = b"%PDF-1.4\n1 0 obj\n<< /Length 30 >>\nstream\n....../Launch /JS /JavaScript....\nendstream\nendobj\n"
    assert _doc(noise, "c.pdf") == []
    assert _doc(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n", "d.pdf") == []


def test_rtf_objects():
    eq = b"{\\rtf1{\\object\\objemb{\\*\\objdata 0105000002000000 45 71 75 61 74 69 6f 6e 2e 33}}}"
    assert next(f for f in _doc(eq, "a.rtf") if f.name == "rtf-equation-editor-object").severity == Severity.HIGH
    upd = b"{\\rtf1{\\object\\objautlink\\objupdate{\\*\\objdata 01050000}}}"
    assert "rtf-auto-update-object" in _names(_doc(upd, "b.rtf"))
    assert _doc(b"{\\rtf1 Hello, world.}", "c.rtf") == []


def test_encrypted_office_document_is_reported():
    findings = _doc(make_ole({"EncryptedPackage": b"\x00" * 5000, "EncryptionInfo": b"\x00" * 100}), "x.docx")
    assert "encrypted-office-document" in _names(findings)


# -- signatures ----------------------------------------------------------
def test_common_name_extraction():
    assert signature._common_name("CN=Contoso Ltd, O=Contoso, C=US") == "Contoso Ltd"
    assert signature._common_name('CN="Acme, Inc.", O=Acme') == "Acme, Inc."
    assert signature._common_name("") is None


def test_authenticode_parses_publisher(monkeypatch):
    captured = {}

    def fake_run(cmd, **kw):
        captured["cmd"], captured["env"] = cmd, kw["env"]
        return types.SimpleNamespace(
            stdout='{"Status":"Valid","Subject":"CN=Contoso Ltd, O=Contoso","Issuer":"CN=Root CA","Thumbprint":"AB12"}',
            returncode=0)

    monkeypatch.setattr(signature.subprocess, "run", fake_run)
    evil = Path("x'; calc; '.exe")
    info = signature.authenticode_info(evil)
    assert info["status"] == "valid" and info["publisher"] == "Contoso Ltd"
    assert info["issuer"] == "Root CA"
    # The hostile name travels only in the environment, never in the script.
    assert str(evil) not in " ".join(captured["cmd"])
    assert captured["env"]["WARDEN_SIGPATH"] == str(evil)


def test_authenticode_tolerates_plain_and_failed_output(monkeypatch):
    monkeypatch.setattr(signature.subprocess, "run",
                        lambda cmd, **kw: types.SimpleNamespace(stdout="NotSigned", returncode=0))
    assert signature.authenticode_info(Path("a.exe"))["status"] == "unsigned"

    def boom(cmd, **kw):
        raise OSError("no powershell")

    monkeypatch.setattr(signature.subprocess, "run", boom)
    assert signature.authenticode_info(Path("a.exe"))["status"] == "unknown"


def test_signature_describe():
    assert "valid signature - Contoso" in signature.describe({"status": "valid", "publisher": "Contoso"})
    assert signature.describe({"status": "unsigned", "publisher": None}) == "not signed"
    assert signature.describe(None) == "signature not checked"


def test_signature_only_checked_for_flagged_executables(scanner, tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr("warden.signature.signature_info",
                        lambda p: calls.append(str(p)) or {"status": "unsigned", "publisher": None})
    clean = tmp_path / "notes.txt"
    clean.write_text("nothing to see")
    scanner.scan_path(clean)
    assert calls == []   # clean, non-executable file: no subprocess spent on it
