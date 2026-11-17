"""Parada del sensor: idempotente y con limpieza aunque la señal ya marcó el evento."""
from __future__ import annotations

import queue
import threading
import types
from typing import Any

from batrade.sensor import Sensor


class FakeConn:
    def __init__(self):
        self.closed = False
        self.heartbeat_written = False

    def execute(self, sql, params=()):
        if "heartbeat" in sql:
            self.heartbeat_written = True
        return None

    def close(self):
        self.closed = True


def _bare_sensor() -> Any:
    sensor: Any = object.__new__(Sensor)
    sensor.stop_event = threading.Event()
    sensor._closed = False
    sensor.notifier = types.SimpleNamespace(stop_event=threading.Event(), sent=0,
                                            failed=0)
    sensor.scan_queue = queue.Queue()
    sensor._threads = []
    sensor.conn = FakeConn()
    sensor.mode = "degraded"
    return sensor


def test_stop_runs_cleanup_once_even_if_signal_set_the_event():
    sensor = _bare_sensor()
    sensor.stop_event.set()          # como hace cli_signal_handlers con SIGTERM

    sensor.stop()
    assert sensor.conn.closed
    assert sensor.conn.heartbeat_written
    assert sensor.notifier.stop_event.is_set()

    # Segunda llamada: no debe repetir trabajo ni lanzar.
    sensor.conn.closed = False
    sensor.stop()
    assert not sensor.conn.closed


def test_stop_sets_events_when_called_normally():
    sensor = _bare_sensor()
    sensor.stop()
    assert sensor.stop_event.is_set()
    assert sensor.notifier.stop_event.is_set()
    assert sensor.conn.closed
