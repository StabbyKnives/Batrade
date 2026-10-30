"""Motor: aislamiento de fallos, throttle y poda de memoria (C9)."""
from __future__ import annotations

from batrade.detect.engine import EMIT_THROTTLE_MS, Engine
from batrade.detect.observation import ARP, Finding, Observation


class FixedRule:
    name = "fixed"

    def __init__(self, severidad="warn"):
        self.severidad = severidad

    def evaluate(self, obs, state, baseline, cfg):
        return [Finding(tipo="test", severidad=self.severidad, clave="clave-fija",
                        detalle={"resumen": "x"})]


class EscalatingRule:
    name = "escalating"

    def evaluate(self, obs, state, baseline, cfg):
        sev = "crit" if obs.ts >= 1200 else "warn"
        return [Finding(tipo="test", severidad=sev, clave="misma-clave", detalle={})]


class BrokenRule:
    name = "broken"

    def evaluate(self, obs, state, baseline, cfg):
        raise RuntimeError("regla rota")


def _obs(ts):
    return Observation(kind=ARP, ts=ts, ip_src="10.10.10.5", mac_src="00:11:22:33:44:55")


def test_throttle_collapses_repeats(cfg, baseline):
    engine = Engine(cfg, baseline, rules=[FixedRule()])
    assert len(engine.observe(_obs(1000))) == 1
    assert engine.observe(_obs(1000 + EMIT_THROTTLE_MS - 1)) == []
    assert len(engine.observe(_obs(1000 + EMIT_THROTTLE_MS + 1))) == 1


def test_throttle_does_not_swallow_escalation(cfg, baseline):
    engine = Engine(cfg, baseline, rules=[EscalatingRule()])
    warn = engine.observe(_obs(1000))
    crit = engine.observe(_obs(1500))          # dentro del throttle, otra severidad
    assert [f.severidad for f in warn] == ["warn"]
    assert [f.severidad for f in crit] == ["crit"]


def test_a_broken_rule_does_not_stop_the_engine(cfg, baseline):
    engine = Engine(cfg, baseline, rules=[BrokenRule(), FixedRule()])
    findings = engine.observe(_obs(1000))
    assert len(findings) == 1
    assert engine.stats["rule_error:broken"] == 1


def test_prune_keeps_bounded_state(cfg, baseline):
    engine = Engine(cfg, baseline)          # reglas reales: aprenden bindings
    for i in range(50):
        engine.observe(Observation(kind=ARP, ts=1000 + i * 10,
                                   ip_src=f"10.10.10.{i + 1}",
                                   mac_src="00:11:22:33:44:55", op="reply"))
    before = engine.snapshot()["bindings"]
    assert before == 50
    engine.prune(1000 + 50 * 10 + 4 * 3600_000)
    assert engine.snapshot()["bindings"] == 0


def test_snapshot_documents_context(cfg, engine):
    snap = engine.snapshot()
    assert snap["gateway_ip"] == "10.10.10.1"
    assert "arp_binding" in snap["rules"]
    assert snap["learning"] is False
