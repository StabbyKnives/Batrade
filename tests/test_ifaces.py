"""Detección de interfaces: el sensor debe arrancar sin editar el YAML.

Se simula la salida de ``ip`` (JSON y texto) para no depender de las interfaces
reales de la máquina que ejecuta los tests.
"""
from __future__ import annotations

import json

from batrade.net import ifaces

ADDR_JSON = json.dumps([
    {"ifname": "lo", "flags": ["LOOPBACK", "UP"], "operstate": "UNKNOWN",
     "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]},
    {"ifname": "eth0", "flags": ["BROADCAST", "MULTICAST", "UP"], "operstate": "UP",
     "addr_info": [{"family": "inet", "local": "192.168.1.10", "prefixlen": 24}]},
    {"ifname": "wlp2s0", "flags": ["BROADCAST", "MULTICAST", "UP"], "operstate": "UP",
     "addr_info": [{"family": "inet", "local": "10.0.0.50", "prefixlen": 24}]},
    {"ifname": "docker0", "flags": ["BROADCAST", "MULTICAST", "UP"], "operstate": "UP",
     "addr_info": [{"family": "inet", "local": "172.17.0.1", "prefixlen": 16}]},
])

ADDR_TEXT = (
    "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n"
    "3: enp3s0    inet 192.168.50.20/24 brd 192.168.50.255 scope global "
    "dynamic enp3s0\\       valid_lft 86390sec\n"
)


def _fake_run(addr=ADDR_JSON, route='[{"dst": "default", "dev": "eth0"}]', text=None):
    def run(argv, timeout=5.0):
        if "addr" in argv and "-j" in argv:
            return addr if text is None else None
        if "route" in argv and "-j" in argv:
            return route
        if "addr" in argv:
            return text or ""
        return None
    return run


def _no_sysfs(monkeypatch):
    monkeypatch.setattr(ifaces, "mac_of", lambda name: None)
    monkeypatch.setattr(ifaces, "is_wireless", lambda name: name == "wlp2s0")


def test_parse_json_and_cidr(monkeypatch):
    monkeypatch.setattr(ifaces, "_run", _fake_run())
    _no_sysfs(monkeypatch)
    rows = {r.name: r for r in ifaces.list_ipv4(include_loopback=True)}
    assert set(rows) == {"lo", "eth0", "wlp2s0", "docker0"}
    assert rows["eth0"].cidr == "192.168.1.0/24"
    assert rows["eth0"].kind == "ethernet"
    assert rows["wlp2s0"].kind == "wi-fi"
    assert rows["lo"].kind == "loopback"
    assert [r.name for r in ifaces.list_ipv4()] == ["eth0", "wlp2s0", "docker0"]


def test_default_iface_from_json(monkeypatch):
    monkeypatch.setattr(ifaces, "_run", _fake_run(
        route='[{"dst": "default", "gateway": "192.168.1.1", "dev": "eth0"}]'))
    assert ifaces.default_iface() == "eth0"


def test_pick_uses_default_route(monkeypatch):
    monkeypatch.setattr(ifaces, "_run", _fake_run(
        route='[{"dst": "default", "dev": "wlp2s0"}]'))
    _no_sysfs(monkeypatch)
    info, reason = ifaces.pick(None)
    assert info is not None and info.name == "wlp2s0"
    assert info.default is True
    assert "ruta por defecto" in reason


def test_pick_prefers_wired_without_default_route(monkeypatch):
    monkeypatch.setattr(ifaces, "_run", _fake_run(route="[]"))
    _no_sysfs(monkeypatch)
    info, reason = ifaces.pick(None)
    assert info is not None and info.name == "eth0"   # docker0 queda excluida
    assert "ethernet" in reason


def test_pick_ignores_virtual_default_route(monkeypatch):
    monkeypatch.setattr(ifaces, "_run", _fake_run(
        route='[{"dst": "default", "dev": "docker0"}]'))
    _no_sysfs(monkeypatch)
    info, reason = ifaces.pick(None)
    assert info is not None and info.name == "eth0"
    assert "ethernet" in reason


def test_pick_explicit_interface(monkeypatch):
    monkeypatch.setattr(ifaces, "_run", _fake_run())
    _no_sysfs(monkeypatch)
    info, reason = ifaces.pick("wlp2s0")
    assert info is not None and info.name == "wlp2s0"
    assert "configurada" in reason


def test_pick_missing_explicit_interface(monkeypatch):
    monkeypatch.setattr(ifaces, "_run", _fake_run())
    monkeypatch.setattr(ifaces, "exists", lambda name: False)
    info, _ = ifaces.pick("iface-fantasma")
    assert info is None


def test_text_fallback_when_json_is_unavailable(monkeypatch):
    monkeypatch.setattr(ifaces, "_run", _fake_run(text=ADDR_TEXT))
    rows = ifaces.list_ipv4()
    assert [r.name for r in rows] == ["enp3s0"]
    assert rows[0].cidr == "192.168.50.0/24"


def test_pick_without_ipv4_returns_none(monkeypatch):
    empty = json.dumps([{"ifname": "lo", "flags": ["LOOPBACK", "UP"],
                         "addr_info": []}])
    monkeypatch.setattr(ifaces, "_run", _fake_run(addr=empty, route="[]"))
    info, reason = ifaces.pick(None)
    assert info is None
    assert "sin interfaces" in reason
