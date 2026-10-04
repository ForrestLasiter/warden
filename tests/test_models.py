"""Tests for the core data models (serialization + verdict logic)."""

from warden.models import FileResult, Finding, ScanReport, Severity


def test_severity_parse_and_order():
    assert Severity.parse("high") == Severity.HIGH
    assert Severity.parse("CRITICAL") == Severity.CRITICAL
    assert Severity.parse(4) == Severity.HIGH
    assert Severity.CLEAN < Severity.LOW < Severity.HIGH < Severity.CRITICAL
    assert Severity.HIGH.label == "High"


def test_fileresult_verdict_is_worst_finding():
    r = FileResult(path="x", findings=[
        Finding("yara", "a", Severity.LOW),
        Finding("heuristics", "b", Severity.HIGH),
        Finding("yara", "c", Severity.MEDIUM),
    ])
    assert r.verdict == Severity.HIGH
    assert r.is_threat is True


def test_fileresult_clean_when_no_findings():
    r = FileResult(path="x")
    assert r.verdict == Severity.CLEAN
    assert r.is_threat is False


def test_finding_roundtrip():
    f = Finding("yara", "EICAR", Severity.CRITICAL, "desc", {"k": "v"})
    f2 = Finding.from_dict(f.to_dict())
    assert f2.engine == f.engine and f2.name == f.name
    assert f2.severity == Severity.CRITICAL and f2.meta == {"k": "v"}


def test_fileresult_roundtrip():
    r = FileResult(path="p", size=10, sha256="abc",
                   findings=[Finding("yara", "x", Severity.HIGH)])
    r2 = FileResult.from_dict(r.to_dict())
    assert r2.path == "p" and r2.size == 10 and r2.sha256 == "abc"
    assert r2.verdict == Severity.HIGH


def test_scanreport_counts_and_threats():
    rep = ScanReport(root="r")
    rep.results = [
        FileResult(path="clean"),
        FileResult(path="bad", findings=[Finding("yara", "x", Severity.CRITICAL)]),
        FileResult(path="low", findings=[Finding("h", "y", Severity.LOW)]),
    ]
    assert len(rep.threats) == 1
    counts = rep.counts_by_verdict()
    assert counts["Clean"] == 1 and counts["Critical"] == 1 and counts["Low"] == 1
    d = rep.to_dict()
    assert d["threats"] == 1 and d["root"] == "r"
