"""Autodetección de interfaz, subred y gateway (arranque sin editar el YAML)."""
from __future__ import annotations

from pathlib import Path

import pytest

from batrade import config as config_mod
from batrade.config import ConfigError, load_config
from batrade.net import ifaces

AUTO_YAML = """
network:
  interface: auto
  cidr: auto
  gateway_ip: null
sensor:
  mode: degraded
  sweep_interval: 30
dashboard: { host: 127.0.0.1 }
"""


def _write(tmp_path, text=AUTO_YAML) -> Path:
    path = tmp_path / "auto.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def _fake_pick(info, reason="ruta por defecto (ethernet)"):
    return lambda configured=None: (info, reason)


def test_interface_cidr_and_gateway_are_detected(tmp_path, monkeypatch):
    info = ifaces.IfaceInfo(name="eth0", ip="192.168.1.10", prefixlen=24, up=True)
    monkeypatch.setattr(ifaces, "pick", _fake_pick(info))
    monkeypatch.setattr(config_mod, "default_gateway", lambda: "192.168.1.1")

    cfg = load_config(_write(tmp_path), tmp_path)
    assert cfg.network.interface == "eth0"
    assert cfg.network.cidr == "192.168.1.0/24"
    assert cfg.network.gateway_ip == "192.168.1.1"
    assert cfg.interface_auto is True
    assert cfg.cidr_auto is True
    assert any("interfaz autodetectada" in w for w in cfg.warnings)
    assert any("subred derivada" in w for w in cfg.warnings)
    assert any("gateway autodetectado" in w for w in cfg.warnings)


def test_wireless_interface_warns_about_passive_capture(tmp_path, monkeypatch):
    info = ifaces.IfaceInfo(name="wlp2s0", ip="192.168.0.123", prefixlen=24,
                            up=True, wireless=True)
    monkeypatch.setattr(ifaces, "pick", _fake_pick(info, "ruta por defecto (wi-fi)"))
    monkeypatch.setattr(config_mod, "default_gateway", lambda: "192.168.0.1")

    cfg = load_config(_write(tmp_path), tmp_path)
    assert cfg.network.interface == "wlp2s0"
    assert any("Wi-Fi" in w for w in cfg.warnings)


def test_gateway_outside_cidr_is_not_adopted(tmp_path, monkeypatch):
    info = ifaces.IfaceInfo(name="vmnet19", ip="192.168.200.1", prefixlen=24, up=True)
    monkeypatch.setattr(ifaces, "pick", _fake_pick(info))
    monkeypatch.setattr(config_mod, "default_gateway", lambda: "192.168.0.1")

    cfg = load_config(_write(tmp_path), tmp_path)
    assert cfg.network.gateway_ip is None
    assert any("fuera de" in w for w in cfg.warnings)


def test_no_interface_is_tolerated_in_simulate_mode(tmp_path, monkeypatch):
    text = """
network: { interface: auto, cidr: 10.10.10.0/24, gateway_ip: null }
sensor: { mode: simulate }
dashboard: { host: 127.0.0.1 }
"""
    monkeypatch.setattr(ifaces, "pick", lambda configured=None: (None, "sin interfaces"))
    cfg = load_config(_write(tmp_path, text), tmp_path)
    assert cfg.network.interface == ""
    assert cfg.network.cidr == "10.10.10.0/24"
    assert any("no necesita red real" in w for w in cfg.warnings)


def test_no_interface_is_an_error_for_live_sensor(tmp_path, monkeypatch):
    monkeypatch.setattr(ifaces, "pick", lambda configured=None: (None, "sin interfaces"))
    with pytest.raises(ConfigError) as exc:
        load_config(_write(tmp_path), tmp_path)
    assert any("autodetectar" in e for e in exc.value.errors)


def test_explicit_interface_keeps_manual_network(cfg):
    assert cfg.network.interface == "lo"
    assert cfg.network.cidr == "10.10.10.0/24"
    assert cfg.interface_auto is False
    assert cfg.cidr_auto is False
