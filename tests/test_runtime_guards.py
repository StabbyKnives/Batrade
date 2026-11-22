"""Guardas operativas: systemd vs CLI, privilegios y propiedad de `var/`."""
from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest

from batrade import cli, daemon
from batrade.daemon import DaemonError
from batrade.net.caps import Capabilities


# --------------------------------------------------------------------------- #
# systemd
# --------------------------------------------------------------------------- #
def _fake_run(returncode: int):
    def fake(argv, **kwargs):
        assert argv[0] == "systemctl"          # sin shell, nunca
        return subprocess.CompletedProcess(argv, returncode, "", "")
    return fake


def test_systemd_unit_active_true(monkeypatch):
    monkeypatch.setattr(daemon.subprocess, "run", _fake_run(0))
    assert daemon.systemd_unit_active("batrade-sensor.service") is True


def test_systemd_unit_active_false(monkeypatch):
    monkeypatch.setattr(daemon.subprocess, "run", _fake_run(3))
    assert daemon.systemd_unit_active("batrade-sensor.service") is False


def test_systemd_unit_active_without_systemd(monkeypatch):
    def boom(*_a, **_k):
        raise FileNotFoundError("systemctl no existe")

    monkeypatch.setattr(daemon.subprocess, "run", boom)
    assert daemon.systemd_unit_active("batrade-sensor.service") is False


def test_ensure_no_systemd_raises_with_active_unit(monkeypatch):
    monkeypatch.setattr(daemon, "systemd_unit_active", lambda unit: True)
    with pytest.raises(DaemonError) as exc:
        daemon.ensure_no_systemd("sensor")
    assert "systemctl" in str(exc.value)
    assert "batrade-sensor.service" in str(exc.value)


def test_ensure_no_systemd_allows_inactive_unit(monkeypatch):
    monkeypatch.setattr(daemon, "systemd_unit_active", lambda unit: False)
    daemon.ensure_no_systemd("sensor")          # no lanza


def test_start_component_refuses_when_unit_is_active(cfg, monkeypatch):
    monkeypatch.setattr(daemon, "systemd_unit_active", lambda unit: True)

    def sin_popen(*_a, **_k):                   # no debe llegar a lanzar nada
        raise AssertionError("no debía arrancar un proceso")

    monkeypatch.setattr(daemon.subprocess, "Popen", sin_popen)
    with pytest.raises(DaemonError) as exc:
        daemon.start_component(cfg, cfg.root / "config.yaml", "sensor")
    assert "systemctl" in str(exc.value)


# --------------------------------------------------------------------------- #
# Usuario, modo y propiedad de var/
# --------------------------------------------------------------------------- #
def test_whoami_includes_uid():
    texto = cli.whoami()
    assert "uid " in texto and "(" in texto


def test_mode_hint_without_raw():
    assert "sudo" in cli.mode_hint(Capabilities(raw_capture=False), "degraded")


def test_mode_hint_silent_in_live():
    assert cli.mode_hint(Capabilities(raw_capture=True), "live") is None


def test_var_owner_warning_only_for_root(tmp_path):
    var = tmp_path / "var"
    var.mkdir()
    assert cli.var_owner_warning(var, euid=1000) is None
    # euid 0 con un var/ de otro uid (el del usuario de la suite).
    if var.stat().st_uid == 0:
        pytest.skip("el directorio de pruebas pertenece a root")
    aviso = cli.var_owner_warning(var, euid=0)
    assert aviso is not None and "root" in aviso


def test_doctor_shows_user_mode_and_hint(cfg, capsys, monkeypatch):
    from batrade import db

    monkeypatch.setattr(cli.caps_mod, "probe", lambda: Capabilities(raw_capture=False))
    db.initialize(cfg.paths.db)
    cli.cmd_doctor(cfg, None)
    salida = capsys.readouterr().out
    assert "ejecutando como" in salida
    assert "uid" in salida
    assert "sudo" in salida


def test_status_shows_user_and_mode(cfg, capsys, monkeypatch):
    from batrade import db

    monkeypatch.setattr(cli.caps_mod, "probe", lambda: Capabilities(raw_capture=False))
    db.initialize(cfg.paths.db)
    cli.cmd_status(cfg, None)
    salida = capsys.readouterr().out
    assert "usuario" in salida and "uid" in salida
    assert "degraded" in salida
    assert "sudo" in salida


def test_status_works_without_database(cfg, capsys, monkeypatch):
    monkeypatch.setattr(cli.caps_mod, "probe", lambda: Capabilities())
    cfg.paths.db.unlink(missing_ok=True)
    cli.cmd_status(cfg, SimpleNamespace())
    assert "sin datos" in capsys.readouterr().out
