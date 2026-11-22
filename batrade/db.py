"""Capa de persistencia SQLite en modo WAL.

Un único archivo es el contrato entre el demonio (escritor) y el dashboard
(lector mayoritario). Cada hilo/usuario abre su propia conexión: sqlite3 no es
seguro para compartir una conexión entre hilos.

Convenciones:
  - Todos los timestamps son epoch en **milisegundos UTC** (INTEGER).
  - Estados de confianza: confiable | desconocido | no_autorizado
  - Severidades: info | warn | crit
"""
from __future__ import annotations

import logging
import sqlite3
from collections.abc import Callable, Sequence
from pathlib import Path

log = logging.getLogger("batrade.db")

# Esquema inicial (versión 1). No se modifica: toda evolución del esquema va
# como una migración nueva, aditiva e idempotente al final de MIGRATIONS.
SCHEMA_V1 = """
CREATE TABLE IF NOT EXISTS identities (
    id          INTEGER PRIMARY KEY,
    key         TEXT NOT NULL UNIQUE,
    kind        TEXT NOT NULL,
    label       TEXT,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id              INTEGER PRIMARY KEY,
    identity_id     INTEGER REFERENCES identities(id) ON DELETE SET NULL,
    mac             TEXT NOT NULL UNIQUE,
    mac_aleatoria   INTEGER NOT NULL DEFAULT 0,
    ip_actual       TEXT,
    fabricante      TEXT,
    hostname        TEXT,
    alias           TEXT,
    estado_confianza TEXT NOT NULL DEFAULT 'desconocido'
        CHECK (estado_confianza IN ('confiable','desconocido','no_autorizado')),
    first_seen      INTEGER NOT NULL,
    last_seen       INTEGER NOT NULL,
    en_linea        INTEGER NOT NULL DEFAULT 0,
    misses          INTEGER NOT NULL DEFAULT 0,
    last_scan_ts    INTEGER,
    last_scan_profile TEXT,
    notes           TEXT
);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_devices_estado ON devices(estado_confianza);
CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_actual);

CREATE TABLE IF NOT EXISTS device_history (
    id        INTEGER PRIMARY KEY,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ts        INTEGER NOT NULL,
    ip        TEXT,
    evento    TEXT NOT NULL,
    detalle   TEXT
);
CREATE INDEX IF NOT EXISTS idx_hist_device ON device_history(device_id, ts DESC);

CREATE TABLE IF NOT EXISTS scans (
    id        INTEGER PRIMARY KEY,
    device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
    tipo      TEXT NOT NULL,
    perfil    TEXT,
    inicio    INTEGER,
    fin       INTEGER,
    estado    TEXT NOT NULL DEFAULT 'pendiente',
    ruta_xml  TEXT,
    cmd       TEXT,
    exit_code INTEGER,
    error     TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_device ON scans(device_id, inicio DESC);

CREATE TABLE IF NOT EXISTS ports (
    device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    protocolo  TEXT NOT NULL,
    puerto     INTEGER NOT NULL,
    estado     TEXT,
    servicio   TEXT,
    version    TEXT,
    riesgoso   INTEGER NOT NULL DEFAULT 0,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    PRIMARY KEY (device_id, protocolo, puerto)
);

CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY,
    ts            INTEGER NOT NULL,
    first_ts      INTEGER NOT NULL,
    last_ts       INTEGER NOT NULL,
    severidad     TEXT NOT NULL CHECK (severidad IN ('info','warn','crit')),
    tipo          TEXT NOT NULL,
    ip_origen     TEXT,
    mac_origen    TEXT,
    ip_destino    TEXT,
    detalle_json  TEXT,
    clave_dedupe  TEXT NOT NULL,
    repeat_count  INTEGER NOT NULL DEFAULT 1,
    notificado    INTEGER NOT NULL DEFAULT 0,
    ts_notificado INTEGER,
    disposicion   TEXT NOT NULL DEFAULT 'sin_evaluar'
        CHECK (disposicion IN ('sin_evaluar','tp','fp')),
    verified      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_sev ON events(severidad, ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_tipo ON events(tipo, ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_dedupe ON events(clave_dedupe, last_ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_disp ON events(disposicion, ts DESC);

CREATE TABLE IF NOT EXISTS scan_requests (
    id             INTEGER PRIMARY KEY,
    objetivo       TEXT NOT NULL,
    perfil         TEXT NOT NULL DEFAULT 'quick',
    solicitado_por TEXT,
    estado         TEXT NOT NULL DEFAULT 'pendiente'
        CHECK (estado IN ('pendiente','ejecutando','hecho','error','descartado')),
    ts             INTEGER NOT NULL,
    ts_fin         INTEGER,
    error          TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_scan_req_pending
    ON scan_requests(objetivo, perfil) WHERE estado = 'pendiente';

CREATE TABLE IF NOT EXISTS notification_queue (
    id              INTEGER PRIMARY KEY,
    event_id        INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    canal           TEXT NOT NULL,
    intentos        INTEGER NOT NULL DEFAULT 0,
    proximo_intento INTEGER NOT NULL,
    estado          TEXT NOT NULL DEFAULT 'pendiente'
        CHECK (estado IN ('pendiente','enviado','agotado')),
    last_error      TEXT,
    ts              INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nq_due ON notification_queue(estado, proximo_intento);

CREATE TABLE IF NOT EXISTS heartbeat (
    componente TEXT PRIMARY KEY,
    ts         INTEGER NOT NULL,
    detalle    TEXT
);

CREATE TABLE IF NOT EXISTS network_baseline (
    k          TEXT PRIMARY KEY,
    v          TEXT,
    updated_ts INTEGER
);

CREATE TABLE IF NOT EXISTS tool_status (
    herramienta TEXT PRIMARY KEY,
    ts          INTEGER NOT NULL,
    ok          INTEGER NOT NULL,
    exit_code   INTEGER,
    error       TEXT,
    fallos_consecutivos INTEGER NOT NULL DEFAULT 0
);
"""

# --------------------------------------------------------------------------- #
# Migraciones versionadas
# --------------------------------------------------------------------------- #
# Cada entrada es ``(versión, pasos)`` y las versiones deben ser crecientes.
# ``pasos`` puede ser un script SQL, una secuencia de sentencias o una función
# ``fn(conn)``. Reglas:
#   - sólo aditivas (ALTER TABLE ADD COLUMN, CREATE ... IF NOT EXISTS);
#   - idempotentes (se pueden repetir si el proceso muere antes de confirmar);
#   - nunca destructivas.
# El runner aplica cada una en su propia transacción y avanza
# ``PRAGMA user_version`` dentro de esa misma transacción.

def _migration_v2_notification_index(conn: sqlite3.Connection) -> None:
    """Índice para la purga de la cola de notificación por antigüedad (RNF-06)."""
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_nq_estado_ts ON notification_queue(estado, ts)"
    )


MIGRATIONS: list[tuple[int, str | Sequence[str] | Callable[[sqlite3.Connection], None]]] = [
    (1, SCHEMA_V1),
    (2, _migration_v2_notification_index),
]

# La versión del esquema se deriva de la lista: una sola fuente de verdad.
SCHEMA_VERSION = MIGRATIONS[-1][0]


def connect(path: str | Path, readonly: bool = False) -> sqlite3.Connection:
    """Abre una conexión con los PRAGMA que el diseño exige (WAL, busy_timeout)."""
    p = Path(path)
    if readonly:
        uri = f"file:{p}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=5.0, isolation_level=None)
    else:
        p.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(p), timeout=5.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA foreign_keys = ON")
    if not readonly:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA wal_autocheckpoint = 512")
    return conn


def user_version(conn: sqlite3.Connection) -> int:
    """Versión de esquema registrada en la base (0 = base vacía o sin migrar)."""
    row = conn.execute("PRAGMA user_version").fetchone()
    return int(row[0]) if row else 0


def _split_sql(script: str) -> list[str]:
    """Divide un script en sentencias completas para ejecutarlas una a una.

    ``executescript`` hace COMMIT implícito y rompería la transacción de la
    migración, así que las sentencias se ejecutan sueltas con ``execute``.
    """
    statements: list[str] = []
    buffer = ""
    for line in script.splitlines(keepends=True):
        buffer += line
        if sqlite3.complete_statement(buffer):
            if buffer.strip():
                statements.append(buffer.strip())
            buffer = ""
    if buffer.strip():
        statements.append(buffer.strip())
    return statements


def _run_migration(conn: sqlite3.Connection,
                   steps: str | Sequence[str] | Callable[[sqlite3.Connection], None]) -> None:
    if callable(steps):
        steps(conn)
        return
    if isinstance(steps, str):
        statements = _split_sql(steps)
    else:
        statements = [str(s) for s in steps]
    for statement in statements:
        conn.execute(statement)


def _main_db_path(conn: sqlite3.Connection) -> Path | None:
    """Ruta del archivo SQLite de la conexión (None para bases en memoria)."""
    for row in conn.execute("PRAGMA database_list"):
        name, file = row[1], row[2]
        if name == "main" and file:
            return Path(file)
    return None


def _write_backup(conn: sqlite3.Connection, tag: str) -> Path | None:
    """Copia `<db>.bak-<tag>` sin sobrescribir; permisos 600."""
    path = _main_db_path(conn)
    if path is None or not path.exists() or path.stat().st_size == 0:
        return None
    target = path.with_name(f"{path.name}.bak-{tag}")
    suffix = 2
    while target.exists():
        target = path.with_name(f"{path.name}.bak-{tag}-{suffix}")
        suffix += 1
    dest = sqlite3.connect(str(target))
    try:
        conn.backup(dest)
    finally:
        dest.close()
    try:
        target.chmod(0o600)
    except OSError:  # pragma: no cover - sistemas sin permisos POSIX
        pass
    log.info("copia de seguridad de la base en %s", target.name)
    return target


def backup(conn: sqlite3.Connection, version: int) -> Path | None:
    """Copia de seguridad previa a migrar: ``<db>.bak-v<versión>`` (permisos 600).

    Nunca sobrescribe una copia anterior: si el nombre ya existe añade ``-2``,
    ``-3``… Usa la API de backup de SQLite para incluir lo que aún esté en el
    WAL. Devuelve la ruta creada o ``None`` si no había nada que copiar.
    """
    return _write_backup(conn, f"v{version}")


def backup_tagged(conn: sqlite3.Connection, tag: str) -> Path | None:
    """Copia con una etiqueta libre, p. ej. ``reset-<epoch_ms>``."""
    return _write_backup(conn, str(tag))


def migrate(conn: sqlite3.Connection) -> int:
    """Aplica las migraciones pendientes y devuelve la versión resultante.

    - Sólo se ejecutan las versiones mayores que ``PRAGMA user_version``.
    - Cada migración corre en su propia transacción junto con el avance de
      ``user_version``: si falla, ni el esquema ni la versión cambian.
    - Antes de tocar una base existente con datos se guarda una copia.
    - Una base nueva recibe todas las migraciones y queda en la última versión.
    """
    current = user_version(conn)
    if current > SCHEMA_VERSION:
        log.warning("la base (v%s) es más nueva que el código (v%s); no se migra",
                    current, SCHEMA_VERSION)
        return current
    pending = [(v, steps) for v, steps in MIGRATIONS if v > current]
    if not pending:
        return current
    if current > 0:
        backup(conn, current)
    for version, steps in pending:
        try:
            conn.execute("BEGIN IMMEDIATE")
            _run_migration(conn, steps)
            conn.execute(f"PRAGMA user_version = {int(version)}")
            conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        log.debug("migración aplicada", extra={"fields": {"version": version}})
    return user_version(conn)


def recover_interrupted(conn: sqlite3.Connection, ts: int) -> dict[str, int]:
    """Cierra el estado que quedó a medias tras un reinicio del sensor.

    Sin esto, un escaneo cortado a mitad deja filas 'ejecutando' para siempre y
    el dashboard miente sobre lo que está pasando.
    """
    scans = conn.execute(
        "UPDATE scans SET estado = 'interrumpido', fin = ?, error = "
        "'sensor reiniciado durante el escaneo' WHERE estado = 'ejecutando'", (ts,)
    ).rowcount
    requests = conn.execute(
        "UPDATE scan_requests SET estado = 'pendiente', error = 'reintentado tras reinicio' "
        "WHERE estado = 'ejecutando'"
    ).rowcount
    return {"scans": scans, "requests": requests}


def initialize(path: str | Path) -> sqlite3.Connection:
    conn = connect(path)
    migrate(conn)
    return conn


def get_meta(conn: sqlite3.Connection, key: str, default: str | None = None) -> str | None:
    row = conn.execute("SELECT v FROM network_baseline WHERE k = ?", (key,)).fetchone()
    return row["v"] if row else default


def set_meta(conn: sqlite3.Connection, key: str, value: str | None, ts: int) -> None:
    conn.execute(
        "INSERT INTO network_baseline(k, v, updated_ts) VALUES(?,?,?) "
        "ON CONFLICT(k) DO UPDATE SET v = excluded.v, updated_ts = excluded.updated_ts",
        (key, value, ts),
    )


def is_learning(conn: sqlite3.Connection) -> bool:
    """Fase de aprendizaje activa si la línea base no fue aprobada (RF-04)."""
    return (get_meta(conn, "learning_complete", "0") or "0") != "1"
