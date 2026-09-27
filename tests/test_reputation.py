"""Offline tests for the reputation module (no network)."""

from warden.reputation import _parse_cymru_txt


def test_parse_cymru_known_bad():
    res = _parse_cymru_txt('"1790445048 97"')
    assert res is not None
    assert res.known and res.malicious
    assert res.detail["detection_pct"] == 97
    assert "97%" in res.detections


def test_parse_cymru_no_match():
    assert _parse_cymru_txt("") is None
    assert _parse_cymru_txt("garbage") is None
    assert _parse_cymru_txt("just one token") is None
