"""Escenarios sintéticos y replay de pcap: la ruta que funciona sin privilegios."""
from __future__ import annotations

import pytest

from batrade.detect import scenarios
from batrade.detect.engine import Engine
from batrade.detect.state import Baseline


def _run(cfg, observations):
    ctx = scenarios.ScenarioContext(cfg)
    engine = Engine(cfg, Baseline(gateway_ip=ctx.gateway_ip, gateway_mac=ctx.gateway_mac,
                                  sensor_ips={ctx.sensor_ip}, learning=False))
    findings = []
    for obs in observations:
        findings.extend(engine.observe(obs))
    return findings


def test_arp_spoof_scenario_detects_gateway_change(cfg):
    findings = _run(cfg, scenarios.synthetic("arp_spoof", cfg))
    assert "arp_gateway_mac_change" in {f.tipo for f in findings}


def test_router_reboot_scenario_is_a_negative_test(cfg):
    """PA-05: un reinicio de router no puede generar críticos."""
    findings = _run(cfg, scenarios.synthetic("router_reboot", cfg))
    assert [f for f in findings if f.severidad == "crit"] == []
    assert "arp_flood" not in {f.tipo for f in findings}


def test_syn_scan_scenario_has_both_tiers(cfg):
    tipos = {f.tipo for f in _run(cfg, scenarios.synthetic("syn_scan", cfg))}
    assert "scan_ports_moderate" in tipos
    assert "scan_ports_aggressive" in tipos
    assert "scan_hosts_aggressive" in tipos


def test_dhcp_rogue_scenario(cfg):
    findings = _run(cfg, scenarios.synthetic("dhcp_rogue", cfg))
    assert any(f.tipo == "dhcp_rogue" and f.severidad == "crit" for f in findings)


def test_unknown_scenario_is_rejected(cfg):
    with pytest.raises(ValueError):
        scenarios.synthetic("inventado", cfg)


def test_pcap_roundtrip_preserves_detections(cfg, tmp_path):
    """El camino del sniffer real (paquete -> observación) se prueba sin CAP_NET_RAW."""
    path = tmp_path / "arp_spoof.pcap"
    scenarios.write_pcap("arp_spoof", str(path), cfg)
    assert path.exists() and path.stat().st_size > 0

    observations = scenarios.observations_from_pcap(str(path))
    kinds = {o.kind for o in observations}
    assert "arp" in kinds
    findings = _run(cfg, observations)
    assert "arp_gateway_mac_change" in {f.tipo for f in findings}


def test_pcap_roundtrip_dhcp(cfg, tmp_path):
    path = tmp_path / "dhcp.pcap"
    scenarios.write_pcap("dhcp_rogue", str(path), cfg)
    observations = scenarios.observations_from_pcap(str(path))
    offers = [o for o in observations if o.kind == "dhcp"]
    assert len(offers) == 2
    assert offers[1].ip_src != offers[0].ip_src


def test_mixed_scenario_is_the_longest(cfg):
    mixed = scenarios.synthetic("mixed", cfg)
    assert len(mixed) > len(scenarios.synthetic("arp_sweep", cfg))
    duration = scenarios.scenario_duration_ms(mixed)
    assert duration > 0
