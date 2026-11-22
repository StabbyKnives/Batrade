"""Escaneo UDP real del catálogo: argv, parseo y eventos de puerto riesgoso."""
from __future__ import annotations

import subprocess
from pathlib import Path

from batrade import store
from batrade.net import caps as caps_mod
from batrade.net import nmap_scan
from batrade.net.caps import Capabilities
from batrade.net.nmap_scan import build_udp_argv, parse_xml, run_scan, udp_risky_ports

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "nmap" / "udp_scan.xml"

TCP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap">
<host><status state="up"/>
<ports><port protocol="tcp" portid="23"><state state="open"/></port></ports>
</host></nmaprun>"""

UDP_ONLY_OPEN = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sU">
<host><status state="up"/>
<ports>
<port protocol="udp" portid="1900"><state state="open"/><service name="upnp"/></port>
<port protocol="udp" portid="5353"><state state="open|filtered"/><service name="mdns"/></port>
</ports>
</host></nmaprun>"""

RAW = Capabilities(raw_capture=True, nmap=True)


def _device(conn, ip="10.10.10.50"):
    res = store.upsert_device(conn, mac="3c:22:fb:11:22:33", ip=ip, ts=1000)
    return res["device_id"]


# --------------------------------------------------------------------------- #
# argv
# --------------------------------------------------------------------------- #
def test_udp_argv_needs_raw_capture(cfg):
    assert build_udp_argv(cfg, "10.10.10.50", Capabilities(), Path("/tmp/x.xml")) == []


def test_udp_argv_is_bounded_and_uses_catalog(cfg):
    cfg.scan.risky_ports = dict(cfg.scan.risky_ports)
    from batrade.config import RiskyPort
    cfg.scan.risky_ports[("udp", 5353)] = RiskyPort(5353, "udp", "mDNS", "multicast")
    argv = build_udp_argv(cfg, "10.10.10.50", RAW, Path("/tmp/x.xml"))
    assert argv[0] == "nmap"
    assert "-sU" in argv
    assert argv[argv.index("-p") + 1] == "U:1900,5353"
    assert "--host-timeout" in argv and "--max-retries" in argv
    assert argv[argv.index("--max-retries") + 1] == nmap_scan.UDP_MAX_RETRIES
    assert argv[-1] == "10.10.10.50"
    assert "shell" not in argv


def test_udp_argv_rejects_target_outside_cidr(cfg):
    try:
        build_udp_argv(cfg, "8.8.8.8", RAW, Path("/tmp/x.xml"))
    except nmap_scan.ScanError:
        pass
    else:  # pragma: no cover
        raise AssertionError("debía rechazar un objetivo fuera del CIDR")


def test_udp_note_is_reported_without_raw(cfg):
    ports, note = udp_risky_ports(cfg, Capabilities())
    assert ports == []
    assert note and "UDP no verificable sin CAP_NET_RAW" in note


# --------------------------------------------------------------------------- #
# parseo
# --------------------------------------------------------------------------- #
def test_fixture_keeps_only_open_udp_ports():
    parsed = parse_xml(FIXTURE)
    assert [(p["port"], p["protocol"]) for p in parsed["ports"]] == [(1900, "udp")]
    assert parsed["hostnames"] == ["lab-tv.local"]


def test_open_filtered_never_reaches_the_database(conn, cfg, tmp_path):
    """``open|filtered`` es el resultado normal de UDP sin respuesta: no es evidencia."""
    did = _device(conn)
    parsed = parse_xml(_write(tmp_path, UDP_ONLY_OPEN))
    diff = store.apply_scan_ports(conn, did, parsed["ports"], 2000,
                                  cfg.scan.risky_ports, protocolos={"tcp", "udp"})
    assert [p["port"] for p in diff["new_risky"]] == [1900]
    assert all(p["port"] != 5353 for p in diff["new_risky"])


def _write(directory, content):
    path = Path(directory) / "scan.xml"
    path.write_text(content, encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# ejecución
# --------------------------------------------------------------------------- #
def _fake_nmap(monkeypatch, udp_xml: str | None = UDP_ONLY_OPEN):
    """Simula nmap: la primera llamada es TCP, la segunda (si hay) es UDP."""
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        xml = argv[argv.index("-oX") + 1]
        if "-sU" in argv:
            if udp_xml is None:
                return subprocess.CompletedProcess(argv, 1, "", "boom")
            Path(xml).write_text(udp_xml, encoding="utf-8")
        else:
            Path(xml).write_text(TCP_XML, encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(nmap_scan.subprocess, "run", fake_run)
    return calls


def test_run_scan_with_raw_adds_udp_pass(cfg, monkeypatch):
    calls = _fake_nmap(monkeypatch)
    result = run_scan(cfg, "10.10.10.50", "quick", RAW)
    assert len(calls) == 2 and "-sU" in calls[1]
    pairs = {(p["protocol"], p["port"]) for p in result.ports}
    assert ("tcp", 23) in pairs
    assert ("udp", 1900) in pairs
    assert ("udp", 5353) not in pairs          # open|filtered descartado
    assert result.protocols == {"tcp", "udp"}
    # El XML de la pasada UDP no se queda huérfano fuera de la retención.
    assert list(cfg.paths.scans_dir.glob("scan-udp-*.xml")) == []


def test_run_scan_without_raw_does_not_run_udp(cfg, monkeypatch):
    calls = _fake_nmap(monkeypatch)
    result = run_scan(cfg, "10.10.10.50", "quick", Capabilities())
    assert len(calls) == 1
    assert result.protocols == {"tcp"}


def test_udp_failure_does_not_invalidate_tcp_result(cfg, monkeypatch):
    _fake_nmap(monkeypatch, udp_xml=None)          # nmap "falla" en la pasada UDP
    result = run_scan(cfg, "10.10.10.50", "quick", RAW)
    assert [p["port"] for p in result.ports] == [23]
    assert result.protocols == {"tcp"}
    assert any("UDP" in note for note in result.notes)


# --------------------------------------------------------------------------- #
# eventos
# --------------------------------------------------------------------------- #
def test_udp_open_port_generates_port_risky(conn, cfg):
    did = _device(conn)
    found = [{"port": 1900, "protocol": "udp", "state": "open", "service": "upnp"}]
    diff = store.apply_scan_ports(conn, did, found, 2000, cfg.scan.risky_ports,
                                  protocolos={"tcp", "udp"})
    assert [p["port"] for p in diff["new_risky"]] == [1900]
    assert diff["new_risky"][0]["protocol"] == "udp"
    ports = {p["puerto"]: p for p in store.list_ports(conn, did)}
    assert ports[1900]["protocolo"] == "udp"
    assert ports[1900]["riesgoso"] == 1


def test_unscanned_protocol_ports_are_not_closed(conn, cfg):
    """Sin raw no se explora UDP: un puerto UDP abierto no puede pasar a cerrado."""
    did = _device(conn)
    store.apply_scan_ports(conn, did,
                           [{"port": 1900, "protocol": "udp", "state": "open"}],
                           2000, cfg.scan.risky_ports, protocolos={"tcp", "udp"})
    diff = store.apply_scan_ports(conn, did,
                                  [{"port": 23, "protocol": "tcp", "state": "open"}],
                                  3000, cfg.scan.risky_ports, protocolos={"tcp"})
    assert diff["disappeared"] == []
    ports = {p["puerto"]: p for p in store.list_ports(conn, did)}
    assert ports[1900]["estado"] == "open"


# --------------------------------------------------------------------------- #
# /health
# --------------------------------------------------------------------------- #
def test_health_page_reports_udp_coverage(cfg, monkeypatch):
    monkeypatch.setattr(caps_mod, "probe", lambda: Capabilities())
    from batrade.dashboard.app import create_app

    client = create_app(cfg).test_client()
    response = client.get("/health")
    assert response.status_code == 200
    assert "UDP no verificable sin CAP_NET_RAW".encode() in response.data


def test_health_page_omits_note_with_raw(cfg, monkeypatch):
    monkeypatch.setattr(caps_mod, "probe", lambda: RAW)
    from batrade.dashboard.app import create_app

    client = create_app(cfg).test_client()
    assert b"UDP no verificable" not in client.get("/health").data
