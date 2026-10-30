"""Notificaciones: formato, escapado, cola persistente y backoff (RF-15/16)."""
from __future__ import annotations

import pytest

from batrade import db, store
from batrade.notify import (LocalSink, NotificationError, Notifier, backoff_seconds,
                       format_discord, format_telegram, format_text)


def _event(conn, *, sev="crit", resumen="La puerta de enlace cambió de MAC"):
    return store.add_event(
        conn, ts=1000, tipo="arp_gateway_mac_change", severidad=sev, clave_dedupe="k1",
        ip_origen="10.10.10.1", mac_origen="aa:bb:cc:dd:ee:ff", ip_destino="10.10.10.1",
        detalle={"resumen": resumen, "por_que": "MITM", "accion": "Aislar el equipo"},
        cooldown_s=0,
    )


def _row(conn, channel="local"):
    event = _event(conn)
    store.enqueue_notification(conn, event["event_id"], channel, 1000)
    return event, store.due_notifications(conn, 10**13)[0]


def test_format_text_has_what_why_and_action(conn):
    _event_row, row = _row(conn)
    text = format_text(row)
    assert "Qué pasó" in text and "Por qué importa" in text and "Qué hacer" in text
    assert "10.10.10.1" in text


def test_telegram_escapes_untrusted_text(conn):
    event = _event(conn, resumen="<script>alert('xss')</script>")
    store.enqueue_notification(conn, event["event_id"], "telegram", 1000)
    row = store.due_notifications(conn, 10**13)[0]
    html = format_telegram(row)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_discord_payload_shape(conn):
    _event_row, row = _row(conn, "discord")
    payload = format_discord(row)
    assert payload["embeds"][0]["color"] == 0xD93025
    assert "Batrade" in payload["embeds"][0]["title"]


def test_backoff_is_exponential_and_capped():
    assert [backoff_seconds(n) for n in range(4)] == [5, 10, 20, 40]
    assert backoff_seconds(50) == 300


def test_process_once_marks_notified(conn, cfg):
    cfg.notify.channels = [{"type": "telegram"}]
    event = _event(conn)
    store.enqueue_notification(conn, event["event_id"], "telegram", 1000)
    delivered = []
    notifier = Notifier(cfg, lambda: db.connect(cfg.paths.db),
                        sender=lambda ch, row, timeout: delivered.append(row["event_id"]))
    assert notifier.process_once() == 1
    assert delivered == [event["event_id"]]
    assert store.get_event(conn, event["event_id"])["notificado"] == 1


def test_failure_keeps_event_in_queue(conn, cfg):
    cfg.notify.channels = [{"type": "telegram"}]
    event = _event(conn)
    store.enqueue_notification(conn, event["event_id"], "telegram", 1000)

    def boom(ch, row, timeout):
        raise NotificationError("sin internet")

    notifier = Notifier(cfg, lambda: db.connect(cfg.paths.db), sender=boom)
    assert notifier.process_once() == 0
    assert notifier.failed == 1
    row = conn.execute("SELECT * FROM notification_queue").fetchone()
    assert row["estado"] == "pendiente"
    assert row["intentos"] == 1
    assert row["proximo_intento"] > 0
    assert "sin internet" in row["last_error"]
    assert store.get_event(conn, event["event_id"])["notificado"] == 0


def test_attempts_exhausted(conn, cfg):
    cfg.notify.channels = [{"type": "telegram"}]
    cfg.notify.max_attempts = 1
    event = _event(conn)
    store.enqueue_notification(conn, event["event_id"], "telegram", 1000)
    notifier = Notifier(cfg, lambda: db.connect(cfg.paths.db),
                        sender=lambda *a: (_ for _ in ()).throw(RuntimeError("caído")))
    notifier.process_once()
    row = conn.execute("SELECT estado FROM notification_queue").fetchone()
    assert row["estado"] == "agotado"


def test_local_sink_writes_private_file(cfg):
    sink = LocalSink(cfg.paths.alerts_log)
    sink.write("alerta de prueba")
    assert cfg.paths.alerts_log.exists()
    assert "alerta de prueba" in cfg.paths.alerts_log.read_text()
    assert oct(cfg.paths.alerts_log.stat().st_mode)[-3:] == "600"


def test_unknown_channel_is_discarded(conn, cfg):
    cfg.notify.channels = [{"type": "local"}]
    event = _event(conn)
    store.enqueue_notification(conn, event["event_id"], "telegram", 1000)
    notifier = Notifier(cfg, lambda: db.connect(cfg.paths.db))
    notifier.process_once()
    row = conn.execute("SELECT estado, last_error FROM notification_queue").fetchone()
    assert row["estado"] == "agotado"
    assert "no configurado" in row["last_error"]


@pytest.mark.parametrize("severidad", ["warn", "crit"])
def test_both_severities_are_notifiable(conn, cfg, severidad):
    cfg.notify.channels = [{"type": "local"}]
    event = _event(conn, sev=severidad)
    notifier = Notifier(cfg, lambda: db.connect(cfg.paths.db))
    assert notifier.enqueue(conn, event["event_id"], 1000) == 1
