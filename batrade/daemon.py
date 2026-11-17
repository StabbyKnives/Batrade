"""Control rápido del sensor y el panel: start/stop/restart/status.

Los procesos se lanzan en una sesión nueva (sobreviven al cierre de la
terminal), con su PID y su log en ``var/``. El PID se valida contra
``/proc/<pid>/cmdline`` antes de enviar señales, para no matar un proceso
ajeno que haya reutilizado el número.
"""
from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from batrade.config import Config

log = logging.getLogger("batrade.daemon")

COMPONENTS = ("sensor", "dashboard")
START_VERIFY_S = 0.6
STOP_TIMEOUT_S = 8.0


class DaemonError(RuntimeError):
    """El proceso no arrancó o no se pudo controlar."""


@dataclass(slots=True)
class ProcInfo:
    name: str
    pid: int | None
    alive: bool
    pidfile: Path
    logfile: Path

    def state(self) -> str:
        return f"en marcha (PID {self.pid})" if self.alive else "detenido"


# --------------------------------------------------------------------------- #
# Ficheros de estado
# --------------------------------------------------------------------------- #
def pidfile(cfg: Config, name: str) -> Path:
    return cfg.paths.db.parent / f"{name}.pid"


def logfile(cfg: Config, name: str) -> Path:
    return cfg.paths.log_dir / f"{name}.out"


def _read_pid(path: Path) -> int | None:
    try:
        raw = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    try:
        pid = int(raw)
    except ValueError:
        return None
    return pid if pid > 0 else None


def _alive(pid: int) -> bool:
    """True si el PID existe y no es un zombi a la espera de ser recogido."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        state = stat.split(") ", 1)[1].split()[0]
    except (OSError, IndexError):
        return True
    return state != "Z"


def _belongs(pid: int, name: str) -> bool:
    """Comprueba que el PID es realmente un `batrade <name>`."""
    try:
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return False
    return b"batrade" in cmdline and name.encode() in cmdline


def pid_of(cfg: Config, name: str) -> int | None:
    """PID vivo del componente, o None. Limpia PID files obsoletos."""
    path = pidfile(cfg, name)
    pid = _read_pid(path)
    if pid is None:
        return None
    if _alive(pid) and _belongs(pid, name):
        return pid
    path.unlink(missing_ok=True)
    return None


def status_all(cfg: Config) -> list[ProcInfo]:
    rows: list[ProcInfo] = []
    for name in COMPONENTS:
        pid = pid_of(cfg, name)
        rows.append(ProcInfo(name=name, pid=pid, alive=pid is not None,
                             pidfile=pidfile(cfg, name), logfile=logfile(cfg, name)))
    return rows


# --------------------------------------------------------------------------- #
# Arranque
# --------------------------------------------------------------------------- #
def child_argv(cfg: Config, config_path: Path, name: str,
               mode: str | None = None) -> list[str]:
    argv = [sys.executable, "-m", "batrade", "--root", str(cfg.root),
            "--config", str(config_path), name]
    if name == "sensor" and mode:
        argv += ["--mode", mode]
    return argv


def _tail(path: Path, lines: int = 5) -> str:
    try:
        data = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    return " | ".join(data[-lines:]) if data else ""


def start_component(cfg: Config, config_path: Path, name: str,
                    mode: str | None = None) -> tuple[ProcInfo, str]:
    """Lanza un componente en segundo plano. Idempotente."""
    if name not in COMPONENTS:
        raise ValueError(f"componente desconocido: {name}")
    existing = pid_of(cfg, name)
    info = ProcInfo(name=name, pid=existing, alive=existing is not None,
                    pidfile=pidfile(cfg, name), logfile=logfile(cfg, name))
    if existing is not None:
        return info, f"{name} ya estaba en marcha (PID {existing})"

    log_path = logfile(cfg, name)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    argv = child_argv(cfg, config_path, name, mode)
    try:
        with log_path.open("ab", buffering=0) as fh:
            proc = subprocess.Popen(
                argv, cwd=str(cfg.root), stdin=subprocess.DEVNULL,
                stdout=fh, stderr=subprocess.STDOUT,
                start_new_session=True, close_fds=True,
            )
    except OSError as exc:
        raise DaemonError(f"no se pudo lanzar {name}: {exc}") from exc

    pidfile(cfg, name).write_text(str(proc.pid), encoding="utf-8")
    if START_VERIFY_S:
        time.sleep(START_VERIFY_S)
    code = proc.poll()
    if code is not None:
        pidfile(cfg, name).unlink(missing_ok=True)
        tail = _tail(log_path)
        raise DaemonError(f"{name} terminó al arrancar (código {code}). {tail}".strip())

    return (ProcInfo(name=name, pid=proc.pid, alive=True,
                     pidfile=pidfile(cfg, name), logfile=log_path),
            f"{name} iniciado (PID {proc.pid}) · log {log_path}")


# --------------------------------------------------------------------------- #
# Parada
# --------------------------------------------------------------------------- #
def _signal(pid: int, sig: int) -> None:
    """Señala al grupo si el proceso es líder de sesión (así muere nmap)."""
    try:
        pgid = os.getpgid(pid)
    except ProcessLookupError:
        return
    try:
        if pgid == pid:
            os.killpg(pgid, sig)
        else:
            os.kill(pid, sig)
    except ProcessLookupError:
        return
    except PermissionError as exc:
        raise DaemonError(f"sin permiso para señalizar el PID {pid}: {exc}") from exc


def stop_component(cfg: Config, name: str, timeout: float = STOP_TIMEOUT_S
                   ) -> tuple[ProcInfo, str]:
    """Detiene un componente con SIGTERM y, si no cede, SIGKILL."""
    pid = pid_of(cfg, name)
    info = ProcInfo(name=name, pid=None, alive=False,
                    pidfile=pidfile(cfg, name), logfile=logfile(cfg, name))
    if pid is None:
        return info, f"{name} ya estaba detenido"

    _signal(pid, signal.SIGTERM)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and _alive(pid):
        time.sleep(0.1)
    if _alive(pid):
        _signal(pid, signal.SIGKILL)
        time.sleep(0.2)
    pidfile(cfg, name).unlink(missing_ok=True)
    return info, f"{name} detenido (PID {pid})"
