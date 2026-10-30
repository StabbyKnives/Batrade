"""Persistencia común de hallazgos (sensor, replay y demo usan el mismo camino)."""
from __future__ import annotations

from typing import Callable, Iterable

from batrade import store
from batrade.config import Config
from batrade.detect.observation import Finding


def persist_findings(conn, findings: Iterable[Finding], cfg: Config, ts: int, *,
                     learning: bool = False,
                     enqueue: Callable[[int, int], object] | None = None
                     ) -> list[tuple[Finding, int, bool]]:
    """Guarda hallazgos con dedupe/cooldown y encola notificaciones.

    Devuelve [(finding, event_id, is_new)] para que el llamador pueda lanzar
    verificaciones o métricas sin volver a consultar la base.
    """
    out: list[tuple[Finding, int, bool]] = []
    for f in findings:
        severidad = f.severidad
        notificar = f.notificar
        if learning and f.tipo == "device_new":
            severidad, notificar = "info", False
        res = store.add_event(
            conn, ts=ts, tipo=f.tipo, severidad=severidad, clave_dedupe=f.clave,
            ip_origen=f.ip_origen, mac_origen=f.mac_origen, ip_destino=f.ip_destino,
            detalle=f.detalle, cooldown_s=cfg.detect.cooldown_s, verified=f.verified,
        )
        event_id = int(res["event_id"])
        if res["is_new"] and notificar and severidad in ("warn", "crit") and enqueue:
            try:
                enqueue(event_id, ts)
            except Exception:  # una cola rota no puede perder el evento
                import logging
                logging.getLogger("batrade.events").exception("no se pudo encolar %s", event_id)
        out.append((f, event_id, bool(res["is_new"])))
    return out


def tool_failure_findings(tool: str, error: str, failures: int, ts: int,
                          threshold: int = 3) -> list[Finding]:
    if failures < threshold:
        return []
    return [Finding(
        tipo="tool_failure", severidad="warn", clave=f"tool:fail:{tool}",
        detalle={
            "resumen": f"{tool} falló {failures} veces seguidas",
            "por_que": "Sin esta herramienta el sensor pierde visibilidad parcial.",
            "accion": "Revisar el log del sensor y la instalación de la herramienta.",
            "error": error[:300],
        },
    )]
