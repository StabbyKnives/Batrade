"""Control start/stop: procesos reales mínimos, sin abrir puertos ni tocar la red."""
from __future__ import annotations

import subprocess
import sys

import pytest

from batrade import daemon


def _child(*extra: str) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)", *extra],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def test_stale_pidfile_is_removed(cfg):
    path = daemon.pidfile(cfg, "sensor")
    path.write_text("999999", encoding="utf-8")
    assert daemon.pid_of(cfg, "sensor") is None
    assert not path.exists()


def test_foreign_process_is_not_taken_as_ours(cfg):
    proc = _child("no-es-batrade")
    try:
        daemon.pidfile(cfg, "sensor").write_text(str(proc.pid), encoding="utf-8")
        assert daemon.pid_of(cfg, "sensor") is None
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def test_stop_component_terminates_our_child(cfg):
    proc = _child("batrade", "sensor")
    try:
        daemon.pidfile(cfg, "sensor").write_text(str(proc.pid), encoding="utf-8")
        assert daemon.pid_of(cfg, "sensor") == proc.pid
        info, message = daemon.stop_component(cfg, "sensor", timeout=5)
        assert info.pid is None
        assert "detenido" in message
        assert not daemon.pidfile(cfg, "sensor").exists()
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)


def test_start_is_idempotent(cfg, monkeypatch):
    monkeypatch.setattr(daemon, "pid_of", lambda cfg, name: 4242)
    info, message = daemon.start_component(cfg, cfg.root / "config.yaml", "sensor")
    assert info.pid == 4242
    assert "ya estaba en marcha" in message


def test_start_spawns_detached_child(cfg, monkeypatch):
    class FakeProc:
        pid = 4242

        def poll(self):
            return None

    seen: dict = {}

    def fake_popen(argv, **kwargs):
        seen["argv"] = argv
        seen["kwargs"] = kwargs
        return FakeProc()

    monkeypatch.setattr(daemon, "START_VERIFY_S", 0)
    monkeypatch.setattr(daemon.subprocess, "Popen", fake_popen)

    info, message = daemon.start_component(
        cfg, cfg.root / "config.yaml", "sensor", mode="degraded")
    assert info.pid == 4242
    assert "iniciado" in message
    assert seen["argv"][1:4] == ["-m", "batrade", "--root"]
    assert seen["argv"][-2:] == ["--mode", "degraded"]
    assert seen["kwargs"]["start_new_session"] is True
    assert daemon.pidfile(cfg, "sensor").read_text() == "4242"


def test_start_reports_early_death(cfg, monkeypatch):
    class DeadProc:
        pid = 4243

        def poll(self):
            return 7

    monkeypatch.setattr(daemon, "START_VERIFY_S", 0)
    monkeypatch.setattr(daemon.subprocess, "Popen",
                        lambda argv, **kwargs: DeadProc())
    with pytest.raises(daemon.DaemonError) as exc:
        daemon.start_component(cfg, cfg.root / "config.yaml", "dashboard")
    assert "terminó al arrancar" in str(exc.value)
    assert not daemon.pidfile(cfg, "dashboard").exists()
