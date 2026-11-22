"""Timeouts por perfil: las claves scan.*_timeout del YAML mandan de verdad."""
from __future__ import annotations

import subprocess

import pytest

from batrade.config import ConfigError, load_config
from batrade.net import nmap_scan
from batrade.net.caps import Capabilities
from batrade.net.nmap_scan import profile_timeout, run_scan

XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap">
<host><status state="up"/>
<ports><port protocol="tcp" portid="22"><state state="open"/></port></ports>
</host></nmaprun>"""


def test_quick_timeout_comes_from_config(cfg):
    cfg.scan.quick_timeout = 45
    assert profile_timeout(cfg, "quick") == 45


def test_standard_timeout_keeps_its_historical_cap(cfg):
    cfg.scan.standard_timeout = 120
    assert profile_timeout(cfg, "standard") == 120
    cfg.scan.standard_timeout = 9999
    assert profile_timeout(cfg, "standard") == nmap_scan.PROFILE_TIMEOUT["standard"]


def test_vuln_timeout_is_fixed(cfg):
    assert profile_timeout(cfg, "vuln") == nmap_scan.PROFILE_TIMEOUT["vuln"]


def test_run_scan_applies_quick_timeout(cfg, monkeypatch):
    cfg.scan.quick_timeout = 37
    captured = {}

    def fake_run(argv, **kwargs):
        captured["timeout"] = kwargs.get("timeout")
        xml = argv[argv.index("-oX") + 1]
        with open(xml, "w", encoding="utf-8") as fh:
            fh.write(XML)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(nmap_scan.subprocess, "run", fake_run)
    result = run_scan(cfg, "10.10.10.50", "quick", Capabilities())
    assert captured["timeout"] == 37
    assert result.ports and result.ports[0]["port"] == 22


def test_run_scan_explicit_timeout_wins(cfg, monkeypatch):
    captured = {}

    def fake_run(argv, **kwargs):
        captured["timeout"] = kwargs.get("timeout")
        xml = argv[argv.index("-oX") + 1]
        with open(xml, "w", encoding="utf-8") as fh:
            fh.write(XML)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(nmap_scan.subprocess, "run", fake_run)
    run_scan(cfg, "10.10.10.50", "quick", Capabilities(), timeout=5)
    assert captured["timeout"] == 5


@pytest.mark.parametrize("key, valor", [
    ("quick_timeout", 0),
    ("udp_timeout", 4),
    ("quick_periodic_hours", 0),
    ("weekly_rescan_days", 0),
])
def test_scan_ranges_are_validated(tmp_path, key, valor):
    path = tmp_path / "c.yaml"
    path.write_text(
        "network: { interface: lo, cidr: 10.10.10.0/24 }\n"
        f"scan: {{ {key}: {valor} }}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError) as exc:
        load_config(path, tmp_path)
    assert any(key in error for error in exc.value.errors)
