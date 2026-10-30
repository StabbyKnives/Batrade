"""Motor de reglas: orquesta la evaluación, el throttle de emisión y el estado."""
from __future__ import annotations

import logging
from collections import Counter
from typing import Iterable, Sequence

from batrade.config import Config
from batrade.detect.observation import Finding, Observation
from batrade.detect.rules import RULES
from batrade.detect.state import Baseline, EngineState
from batrade.net.iputil import now_ms

log = logging.getLogger("batrade.engine")

# Una misma regla no puede escribir más de un evento por segundo y clave: la
# base ya aplica cooldown, pero el throttle evita miles de UPDATE por ataque.
EMIT_THROTTLE_MS = 1000
MAX_THROTTLE_KEYS = 4096


class Engine:
    def __init__(self, cfg: Config, baseline: Baseline | None = None,
                 rules: Sequence | None = None):
        self.cfg = cfg
        self.baseline = baseline or Baseline()
        self.state = EngineState(span_ms=cfg.detect.window_s * 1000)
        self.rules = tuple(rules if rules is not None else RULES)
        self._throttle: dict[tuple[str, str], int] = {}
        self.stats: Counter[str] = Counter()

    # ------------------------------------------------------------------ API
    def observe(self, obs: Observation) -> list[Finding]:
        """Evalúa una observación. Nunca propaga excepciones de una regla."""
        if not obs.ts:
            obs.ts = now_ms()
        self.stats[f"obs:{obs.kind}"] += 1
        emitted: list[Finding] = []
        for rule in self.rules:
            try:
                findings = rule.evaluate(obs, self.state, self.baseline, self.cfg)
            except Exception:  # una regla rota no puede tumbar el sensor
                log.exception("regla %s falló con %r", getattr(rule, "name", rule), obs)
                self.stats[f"rule_error:{getattr(rule, 'name', '?')}"] += 1
                continue
            for finding in findings:
                if self._allow(finding, obs.ts):
                    emitted.append(finding)
                    self.stats[f"find:{finding.tipo}"] += 1
        return emitted

    def observe_all(self, observations: Iterable[Observation]) -> list[Finding]:
        out: list[Finding] = []
        for obs in observations:
            out.extend(self.observe(obs))
        return out

    def prune(self, ts: int | None = None) -> None:
        self.state.prune(ts or now_ms())
        if len(self._throttle) > MAX_THROTTLE_KEYS:
            cutoff = (ts or now_ms()) - 60_000
            self._throttle = {k: v for k, v in self._throttle.items() if v >= cutoff}

    def set_learning(self, learning: bool) -> None:
        self.baseline.learning = learning

    def register_sensor(self, ip: str | None, mac: str | None) -> None:
        """Autoexclusión del propio sensor (RF-12, PA-08)."""
        if ip:
            self.baseline.sensor_ips.add(ip)
        if mac:
            self.baseline.sensor_macs.add(mac)

    def snapshot(self) -> dict:
        data = self.state.snapshot()
        data.update({
            "gateway_ip": self.baseline.gateway_ip,
            "gateway_mac": self.baseline.gateway_mac,
            "dhcp_server_ip": self.baseline.dhcp_server_ip,
            "learning": self.baseline.learning,
            "sensor_ips": sorted(self.baseline.sensor_ips),
            "sensor_macs": sorted(self.baseline.sensor_macs),
            "rules": [getattr(r, "name", str(r)) for r in self.rules],
        })
        return data

    # -------------------------------------------------------------- interno
    def _allow(self, finding: Finding, ts: int) -> bool:
        # La severidad forma parte de la clave: una escalada warn -> crit no debe
        # quedar silenciada por el throttle del nivel anterior.
        key = (finding.tipo, finding.clave, finding.severidad)
        last = self._throttle.get(key)
        if last is not None and (ts - last) < EMIT_THROTTLE_MS:
            self.stats["throttled"] += 1
            return False
        self._throttle[key] = ts
        return True
