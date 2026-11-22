"""Retención: cola de notificación, XML de escaneos y contención de rutas."""
from __future__ import annotations

import os
from typing import Any

from batrade import store
from batrade.sensor import Sensor, safe_unlink_scan

CORTE = 1_000_000


def _event(conn, ts: int = 2_000_000) -> int:
    return int(store.add_event(conn, ts=ts, tipo="device_new", severidad="warn",
                               clave_dedupe=f"k{ts}", cooldown_s=0)["event_id"])


def _queue_row(conn, event_id: int, estado: str, ts: int) -> None:
    conn.execute(
        "INSERT INTO notification_queue(event_id, canal, intentos, proximo_intento, "
        "estado, ts) VALUES(?,?,?,?,?,?)",
        (event_id, "local", 0, ts, estado, ts),
    )


def _scan(conn, device_id: int, fin: int, ruta_xml: str | None) -> None:
    conn.execute(
        "INSERT INTO scans(device_id, tipo, perfil, inicio, fin, estado, ruta_xml) "
        "VALUES(?,?,?,?,?,?,?)",
        (device_id, "standard", "standard", fin - 10, fin, "ok", ruta_xml),
    )


def _device(conn) -> int:
    return int(store.upsert_device(conn, mac="3c:22:fb:11:22:33", ip="10.10.10.50",
                                   ts=1)["device_id"])


# --------------------------------------------------------------------------- #
# Cola de notificación
# --------------------------------------------------------------------------- #
def test_purge_removes_sent_and_exhausted_but_never_pending(conn):
    eid = _event(conn)
    # Se usan canales distintos porque (evento, canal) es único en la cola.
    for canal, estado in (("telegram", "enviado"), ("discord", "agotado")):
        conn.execute(
            "INSERT INTO notification_queue(event_id, canal, intentos, proximo_intento, "
            "estado, ts) VALUES(?,?,?,?,?,?)",
            (eid, canal, 3, CORTE - 1, estado, CORTE - 5_000),
        )
    _queue_row(conn, eid, "pendiente", CORTE - 5_000)

    purged = store.purge(conn, CORTE)

    estados = {(r["canal"], r["estado"]) for r in conn.execute(
        "SELECT canal, estado FROM notification_queue")}
    assert purged["notifications"] == 2
    assert ("local", "pendiente") in estados
    assert ("telegram", "enviado") not in estados
    assert ("discord", "agotado") not in estados


def test_recent_queue_rows_are_kept(conn):
    eid = _event(conn)
    _queue_row(conn, eid, "enviado", CORTE + 5_000)
    assert store.purge(conn, CORTE)["notifications"] == 0
    assert conn.execute("SELECT COUNT(*) AS n FROM notification_queue").fetchone()["n"] == 1


# --------------------------------------------------------------------------- #
# XML de escaneos
# --------------------------------------------------------------------------- #
def test_purge_returns_xml_paths_of_purged_scans(conn, cfg):
    did = _device(conn)
    dentro = cfg.paths.scans_dir / "scan-standard-10.10.10.50-1.xml"
    dentro.write_text("<nmaprun/>", encoding="utf-8")
    _scan(conn, did, fin=CORTE - 1, ruta_xml=str(dentro))
    _scan(conn, did, fin=CORTE + 1, ruta_xml=str(cfg.paths.scans_dir / "reciente.xml"))

    purged = store.purge(conn, CORTE)

    assert purged["scans"] == 1
    assert purged["scan_xml"] == [str(dentro)]
    assert dentro.exists()          # borrar archivos no es trabajo de store


def test_safe_unlink_deletes_only_inside_scans_dir(tmp_path):
    base = tmp_path / "scans"
    base.mkdir()
    dentro = base / "scan-quick-10.10.10.50-1.xml"
    dentro.write_text("<nmaprun/>", encoding="utf-8")
    fuera = tmp_path / "secreto.xml"
    fuera.write_text("no se toca", encoding="utf-8")

    assert safe_unlink_scan(base, dentro) is True
    assert not dentro.exists()

    assert safe_unlink_scan(base, fuera) is False
    assert fuera.exists()

    assert safe_unlink_scan(base, base / ".." / "secreto.xml") is False
    assert fuera.exists()

    assert safe_unlink_scan(base, "/etc/passwd") is False
    assert os.path.exists("/etc/passwd")


def test_safe_unlink_refuses_symlink_escaping_scans_dir(tmp_path):
    base = tmp_path / "scans"
    base.mkdir()
    fuera = tmp_path / "objetivo.xml"
    fuera.write_text("datos ajenos", encoding="utf-8")
    enlace = base / "scan-trampa.xml"
    enlace.symlink_to(fuera)

    assert safe_unlink_scan(base, enlace) is False
    assert fuera.exists()


def test_safe_unlink_tolerates_missing_and_non_xml(tmp_path):
    base = tmp_path / "scans"
    base.mkdir()
    assert safe_unlink_scan(base, base / "no-existe.xml") is False
    otro = base / "notas.txt"
    otro.write_text("x", encoding="utf-8")
    assert safe_unlink_scan(base, otro) is False
    assert otro.exists()


# --------------------------------------------------------------------------- #
# Integración con el sensor
# --------------------------------------------------------------------------- #
def _bare_sensor(cfg) -> Any:
    sensor: Any = object.__new__(Sensor)
    sensor.cfg = cfg
    return sensor


def test_sensor_purge_deletes_scan_xml(conn, cfg):
    cfg.sensor.retention_days = 1
    did = _device(conn)
    xml = cfg.paths.scans_dir / "scan-standard-10.10.10.50-7.xml"
    xml.write_text("<nmaprun/>", encoding="utf-8")
    _scan(conn, did, fin=1_000, ruta_xml=str(xml))
    eid = _event(conn, ts=1_000)
    conn.execute(
        "INSERT INTO notification_queue(event_id, canal, intentos, proximo_intento, "
        "estado, ts) VALUES(?,?,?,?,?,?)", (eid, "local", 4, 1_000, "agotado", 1_000),
    )

    purged = _bare_sensor(cfg)._purge_retention(conn, ts=10 * 86_400_000)

    assert purged["xml"] == 1
    assert purged["scans"] == 1
    assert purged["notifications"] == 1
    assert not xml.exists()
