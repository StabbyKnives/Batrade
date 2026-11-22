"""`doctor`: legibilidad del diagnóstico y versión de esquema."""
from __future__ import annotations

from datetime import datetime

from batrade import cli, db, store
from batrade.net.iputil import now_ms


def _out(capsys) -> str:
    return capsys.readouterr().out


def test_doctor_shows_schema_version(cfg, capsys):
    db.initialize(cfg.paths.db)
    cli.cmd_doctor(cfg, None)
    salida = _out(capsys)
    assert f"schema v{db.SCHEMA_VERSION}" in salida


def test_doctor_prints_heartbeat_as_date_and_age(cfg, capsys):
    conn = db.initialize(cfg.paths.db)
    ts = now_ms() - 5_000
    store.heartbeat(conn, "sensor", ts, '{"mode": "degraded", "state": "running"}')
    conn.close()

    cli.cmd_doctor(cfg, None)
    linea = next(line for line in _out(capsys).splitlines() if line.strip().startswith("heartbeat"))
    assert datetime.fromtimestamp(ts / 1000).strftime("%Y-%m-%d %H:%M:%S") in linea
    assert "hace" in linea and "s" in linea
    assert str(ts) not in linea           # ya no se imprime el epoch desnudo


def test_doctor_marks_stale_heartbeat(cfg, capsys):
    conn = db.initialize(cfg.paths.db)
    store.heartbeat(conn, "sensor", now_ms() - 600_000, "{}")
    conn.close()

    cli.cmd_doctor(cfg, None)
    linea = next(line for line in _out(capsys).splitlines() if line.strip().startswith("heartbeat"))
    assert "sin latido reciente" in linea


def test_doctor_without_heartbeat(cfg, capsys):
    cli.cmd_doctor(cfg, None)
    linea = next(line for line in _out(capsys).splitlines() if line.strip().startswith("heartbeat"))
    assert "nunca" in linea


def test_human_ms_tolerates_garbage():
    assert cli._human_ms(0)
    assert cli._human_ms(10 ** 20) == "fecha inválida"
