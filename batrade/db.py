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

import sqlite3
from pathlib import Path

SCHEMA_VERSION = 1

SCHEMA = """
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


def migrate(conn: sqlite3.Connection) -> int:
    """Crea/actualiza el esquema. Idempotente.

    ``executescript`` hace COMMIT implícito, así que no se envuelve en una
    transacción explícita; todas las sentencias son CREATE ... IF NOT EXISTS.
    """
    try:
        conn.executescript(SCHEMA)
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    except sqlite3.DatabaseError:
        raise
    row = conn.execute("PRAGMA user_version").fetchone()
    return int(row[0]) if row else SCHEMA_VERSION


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
