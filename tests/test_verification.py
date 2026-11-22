"""Verificación ARP: "no verificado" no es lo mismo que "no verificable"."""
from __future__ import annotations

import json
import queue
import threading
from typing import Any

import pytest

from batrade import db, store
from batrade.config import Config
from batrade.dashboard.app import verification_label
from batrade.detect.engine import Engine
from batrade.detect.observation import Finding
from batrade.detect.state import Baseline
from batrade.net.caps import Capabilities
from batrade.sensor import Sensor
from tests.conftest import ATTACKER_MAC, GW_IP, GW_MAC


def _finding() -> Finding:
    return Finding(
        tipo="arp_gateway_mac_change", severidad="crit",
        clave=f"arp:bind:{GW_IP}:{ATTACKER_MAC}",
        ip_origen=GW_IP, mac_origen=ATTACKER_MAC,
        detalle={"resumen": "El gateway cambió de MAC", "por_que": "MITM",
                 "accion": "Comprobar el router"},
        needs_verify=GW_IP,
    )


def _sensor(cfg: Config, raw: bool) -> Sensor:
    sensor: Any = object.__new__(Sensor)
    sensor.cfg = cfg
    sensor.caps = Capabilities(raw_capture=raw)
    sensor._lock = threading.RLock()
    sensor.scan_queue = queue.Queue()
    sensor._pending = set()
    sensor._threads = []
    sensor.engine = Engine(cfg, Baseline(gateway_ip=GW_IP, gateway_mac=GW_MAC))
    sensor.notifier = type("N", (), {
        "enqueue": lambda self, conn, eid, ts: store.enqueue_notification(
            conn, eid, "local", ts),
    })()
    return sensor


def _detalle(conn, event_id: int) -> dict:
    row = store.get_event(conn, event_id)
    assert row is not None
    detalle = json.loads(row["detalle_json"] or "{}")
    detalle["_verified"] = row["verified"]
    return detalle


def _persist_quiet(conn, sensor, ts: int = 1000) -> int:
    """Persiste el hallazgo sin lanzar el hilo real de sonda (red en tests)."""
    sensor._spawn_verification = lambda eid, ip: None
    sensor._persist(conn, [_finding()], ts)
    return int(_last_event(conn)["id"])


def _last_event(conn):
    return conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT 1").fetchone()


def _pending_notifications(conn) -> int:
    return conn.execute(
        "SELECT COUNT(*) AS n FROM notification_queue WHERE estado = 'pendiente'"
    ).fetchone()["n"]


@pytest.fixture
def conn2(cfg):
    connection = db.initialize(cfg.paths.db)
    yield connection
    connection.close()


def test_without_raw_the_event_says_not_verifiable(cfg, conn2):
    cfg.detect.arp_verify = True
    sensor = _sensor(cfg, raw=False)
    sensor._persist(conn2, [_finding()], 1000)
    event = _last_event(conn2)
    detalle = _detalle(conn2, event["id"])
    assert detalle["verificacion"]["estado"] == "no_verificable"
    assert "CAP_NET_RAW" in detalle["verificacion"]["motivo"]
    assert detalle["_verified"] == 0
    # C2: la falta de verificación no bloquea la alerta.
    assert _pending_notifications(conn2) == 1


def test_no_response_state(cfg, conn2, monkeypatch):
    cfg.detect.arp_verify = True
    sensor = _sensor(cfg, raw=True)
    event_id = _persist_quiet(conn2, sensor)
    monkeypatch.setattr("batrade.sensor.probe_binding", lambda *a, **k: set())
    sensor._run_verification(event_id, GW_IP)
    detalle = _detalle(conn2, event_id)
    assert detalle["verificacion"]["estado"] == "sin_respuesta"
    assert detalle["_verified"] == 0
    assert _pending_notifications(conn2) == 1


def test_confirmed_state_keeps_legacy_format(cfg, conn2, monkeypatch):
    cfg.detect.arp_verify = True
    sensor = _sensor(cfg, raw=True)
    event_id = _persist_quiet(conn2, sensor)
    monkeypatch.setattr("batrade.sensor.probe_binding",
                        lambda *a, **k: {GW_MAC, ATTACKER_MAC})
    sensor._run_verification(event_id, GW_IP)
    detalle = _detalle(conn2, event_id)
    assert isinstance(detalle["verificacion"], str)      # formato actual intacto
    assert len(detalle["macs_observadas"]) == 2
    assert detalle["_verified"] == 1


def test_discarded_state_keeps_legacy_format(cfg, conn2, monkeypatch):
    cfg.detect.arp_verify = True
    sensor = _sensor(cfg, raw=True)
    event_id = _persist_quiet(conn2, sensor)
    monkeypatch.setattr("batrade.sensor.probe_binding", lambda *a, **k: {GW_MAC})
    sensor._run_verification(event_id, GW_IP)
    detalle = _detalle(conn2, event_id)
    assert isinstance(detalle["verificacion"], str)
    assert detalle["_verified"] == 0
    assert _pending_notifications(conn2) == 1


def test_probe_unavailable_marks_not_verifiable(cfg, conn2, monkeypatch):
    cfg.detect.arp_verify = True
    sensor = _sensor(cfg, raw=True)
    event_id = _persist_quiet(conn2, sensor)
    monkeypatch.setattr("batrade.sensor.probe_binding", lambda *a, **k: None)
    sensor._run_verification(event_id, GW_IP)
    detalle = _detalle(conn2, event_id)
    assert detalle["verificacion"]["estado"] == "no_verificable"


def test_raw_sensor_spawns_verification(cfg, conn2, monkeypatch):
    cfg.detect.arp_verify = True
    sensor = _sensor(cfg, raw=True)
    lanzados = []
    monkeypatch.setattr(sensor, "_spawn_verification",
                        lambda eid, ip: lanzados.append((eid, ip)))
    sensor._persist(conn2, [_finding()], 1000)
    assert lanzados and lanzados[0][1] == GW_IP


def test_verification_disabled_writes_nothing(cfg, conn2):
    cfg.detect.arp_verify = False
    sensor = _sensor(cfg, raw=True)
    sensor._spawn_verification = lambda eid, ip: None
    sensor._persist(conn2, [_finding()], 1000)
    detalle = _detalle(conn2, _last_event(conn2)["id"])
    assert "verificacion" not in detalle


# --------------------------------------------------------------------------- #
# Etiqueta del panel
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("bloque, texto", [
    ({"verificacion": {"estado": "no_verificable", "motivo": "sin CAP_NET_RAW"}},
     "no verificable"),
    ({"verificacion": {"estado": "sin_respuesta", "motivo": "no respondió"}},
     "sin respuesta"),
])
def test_panel_labels(bloque, texto):
    label = verification_label(json.dumps(bloque))
    assert label is not None and label["texto"] == texto


def test_legacy_text_has_no_extra_label():
    assert verification_label(json.dumps({"verificacion": "Verificado: 2 MACs"})) is None
    assert verification_label("{}") is None
    assert verification_label(None) is None


def test_events_page_shows_distinct_labels(cfg, conn2):
    from batrade.dashboard.app import create_app

    conn2.execute(
        "INSERT INTO events(ts, first_ts, last_ts, severidad, tipo, detalle_json, "
        "clave_dedupe, verified) VALUES(1000,1000,1000,'crit','arp_gateway_mac_change',?,?,0)",
        (json.dumps({"verificacion": {"estado": "no_verificable",
                                      "motivo": "sin CAP_NET_RAW"}}), "k1"),
    )
    conn2.execute(
        "INSERT INTO events(ts, first_ts, last_ts, severidad, tipo, detalle_json, "
        "clave_dedupe, verified) VALUES(2000,2000,2000,'crit','arp_gateway_mac_change',?,?,0)",
        (json.dumps({"verificacion": {"estado": "sin_respuesta",
                                      "motivo": "la IP no respondió"}}), "k2"),
    )
    client = create_app(cfg).test_client()
    body = client.get("/events").data.decode()
    assert "no verificable" in body and "sin respuesta" in body
    assert "sin CAP_NET_RAW" in body
