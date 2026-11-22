"""Base OUI: ubicaciones por distribución y formatos de fichero."""
from __future__ import annotations

from batrade.net import oui as oui_mod
from batrade.net.oui import OuiDB


def test_configured_path_missing_falls_back(tmp_path, monkeypatch):
    fallback = tmp_path / "nmap-mac-prefixes"
    fallback.write_text("000C29 VMware\n3C22FB Apple\n", encoding="utf-8")
    monkeypatch.setattr(oui_mod, "CANDIDATE_FILES", (str(fallback),))

    db = OuiDB.load(tmp_path / "no-existe")
    assert len(db) == 2
    assert db.lookup("00:0c:29:1b:2c:3d") == "VMware"
    assert db.source == str(fallback)


def test_ieee_data_hex_format(tmp_path, monkeypatch):
    path = tmp_path / "oui.txt"
    path.write_text("00-00-0C   (hex)       Cisco Systems, Inc\n", encoding="utf-8")
    monkeypatch.setattr(oui_mod, "CANDIDATE_FILES", ())

    db = OuiDB.load(path)
    assert db.lookup("00:00:0c:11:22:33") == "Cisco Systems, Inc"


def test_without_database_vendor_is_optional(tmp_path, monkeypatch):
    monkeypatch.setattr(oui_mod, "CANDIDATE_FILES", ())
    db = OuiDB.load(tmp_path / "missing")
    assert len(db) == 0
    assert db.lookup("00:0c:29:1b:2c:3d") is None
