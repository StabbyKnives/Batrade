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


# --------------------------------------------------------------------------- #
# Bloque «Prueba en VM»
# --------------------------------------------------------------------------- #
def test_looks_virtual_by_name_and_mac():
    assert cli.looks_virtual("vboxnet0", None) is True
    assert cli.looks_virtual("eth0", "08:00:27:aa:bb:cc") is True
    assert cli.looks_virtual("enp3s0", "3c:22:fb:11:22:33") is False
    assert cli.looks_virtual(None, None) is False


def test_vm_probe_lines_without_raw(cfg):
    from batrade.net.caps import Capabilities

    lineas = cli.vm_probe_lines(cfg, Capabilities(raw_capture=False), "degraded")
    texto = " ".join(lineas)
    assert "CAP_NET_RAW NO" in texto
    assert "sudo" in texto
    assert "virtual/NAT" in texto


def test_vm_probe_lines_with_raw(cfg):
    from batrade.net.caps import Capabilities

    texto = " ".join(cli.vm_probe_lines(cfg, Capabilities(raw_capture=True), "live"))
    assert "CAP_NET_RAW sí" in texto
    assert "listo para modo live" in texto


def test_doctor_prints_vm_block(cfg, capsys, monkeypatch):
    from batrade import db
    from batrade.net.caps import Capabilities

    monkeypatch.setattr(cli.caps_mod, "probe", lambda: Capabilities(raw_capture=False))
    db.initialize(cfg.paths.db)
    cli.cmd_doctor(cfg, None)
    salida = capsys.readouterr().out
    assert "prueba en VM" in salida
    assert "interfaz virtual/NAT" in salida
