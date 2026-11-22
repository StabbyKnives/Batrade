"""Panel web de solo lectura mayoritaria sobre SQLite (RF-17).

Escrituras permitidas, deliberadamente acotadas (decisión C1 del análisis):
  - devices.alias / devices.estado_confianza
  - scan_requests (botón de escaneo manual)
  - events.disposicion (marcar falso positivo, para el KPI)
El sensor es el único que escribe eventos, puertos y cola de notificación.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
from datetime import datetime
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for)

from batrade import db, store
from batrade.config import Config
from batrade.inventory import approve_baseline, review_candidates
from batrade.inventory import status as baseline_status
from batrade.net import caps as caps_mod
from batrade.net.iputil import ip_in_cidr, now_ms, valid_ipv4
from batrade.net.nmap_scan import udp_risky_ports

TRUST_LABEL = {"confiable": "Confiable", "desconocido": "Desconocido",
               "no_autorizado": "No autorizado"}
SEV_LABEL = {"info": "Informativo", "warn": "Advertencia", "crit": "Crítico"}
SEV_ICON = {"info": "·", "warn": "!", "crit": "!!"}


def _human_age(ms: int | None) -> str:
    if not ms:
        return "nunca"
    delta = max(0, now_ms() - int(ms))
    sec = delta // 1000
    if sec < 60:
        return f"hace {sec} s"
    if sec < 3600:
        return f"hace {sec // 60} min"
    if sec < 86400:
        return f"hace {sec // 3600} h"
    return f"hace {sec // 86400} d"


def create_app(cfg: Config) -> Flask:
    db.initialize(cfg.paths.db)
    caps = caps_mod.probe()
    mode, mode_notes = caps_mod.resolve_mode(cfg.sensor.mode, caps)
    _udp_ports, udp_note = udp_risky_ports(cfg, caps)

    app = Flask(__name__)
    secret = (hashlib.sha256(cfg.dashboard.auth_token.encode()).hexdigest()
              if cfg.dashboard.auth_token else secrets.token_hex(16))
    app.config.update(
        SECRET_KEY=secret,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_HTTPONLY=True,
        JSON_SORT_KEYS=False,
    )
    app.config["KG_CFG"] = cfg
    app.config["KG_CAPS"] = caps
    app.config["KG_MODE"] = mode

    # ------------------------------------------------------------- conexión
    def get_db() -> sqlite3.Connection:
        if "conn" not in g:
            g.conn = db.connect(cfg.paths.db)
        return g.conn

    app.get_db = get_db  # type: ignore[attr-defined]

    @app.teardown_appcontext
    def _close(_exc):  # noqa: ANN001
        conn = g.pop("conn", None)
        if conn is not None:
            conn.close()

    def _health(conn: sqlite3.Connection) -> dict:
        hb = store.get_heartbeat(conn, "sensor")
        age = now_ms() - int(hb["ts"]) if hb else None
        stale_after = cfg.sensor.heartbeat_interval * 3000
        detail: dict = {}
        if hb is not None and hb["detalle"]:
            try:
                detail = json.loads(hb["detalle"])
            except json.JSONDecodeError:
                detail = {}
        return {
            "age": age,
            "stale": age is None or age > stale_after,
            "detail": detail,
            "mode": detail.get("mode") or mode,
            "state": detail.get("state") or ("unknown" if hb is None else "running"),
            "caps": detail.get("caps") or caps.summary(),
        }

    # --------------------------------------------------------------- sesión
    @app.before_request
    def _guard():  # noqa: ANN202
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(18)
        endpoint = request.endpoint or ""
        if endpoint in ("static", "login"):
            return None
        if cfg.dashboard.auth_token and not session.get("auth"):
            return redirect(url_for("login", next=request.path))
        if request.method == "POST":
            sent = request.form.get("csrf") or request.headers.get("X-CSRF", "")
            if not sent or not hmac.compare_digest(sent, session.get("csrf", "")):
                abort(400, "Token CSRF inválido o ausente")
        return None

    # ------------------------------------------------------------ contexto
    @app.context_processor
    def _inject():  # noqa: ANN202
        conn = get_db()
        health = _health(conn)
        return {
            "cfg": cfg,
            "csrf": session.get("csrf", ""),
            "health": health,
            "mode": health["mode"],
            "learning": baseline_status(conn)["learning"],
            "trust_label": TRUST_LABEL,
            "sev_label": SEV_LABEL,
        }

    @app.template_filter("ts")
    def _fmt_ts(ms):  # noqa: ANN001
        if not ms:
            return "—"
        return datetime.fromtimestamp(int(ms) / 1000).strftime("%d/%m/%Y %H:%M:%S")

    @app.template_filter("ago")
    def _fmt_ago(ms):  # noqa: ANN001
        return _human_age(int(ms) if ms else None)

    @app.template_filter("mac")
    def _fmt_mac(mac):  # noqa: ANN001
        return mac or "—"

    @app.template_filter("json_pretty")
    def _json_pretty(raw):  # noqa: ANN001
        try:
            return json.dumps(json.loads(raw or "{}"), indent=2, ensure_ascii=False)
        except (json.JSONDecodeError, TypeError):
            return str(raw or "")

    # ------------------------------------------------------------- autenticación
    @app.route("/login", methods=["GET", "POST"])
    def login():  # noqa: ANN202
        if not cfg.dashboard.auth_token:
            return redirect(url_for("index"))
        if request.method == "POST":
            token = request.form.get("token", "")
            if hmac.compare_digest(token, cfg.dashboard.auth_token):
                session["auth"] = True
                return redirect(request.args.get("next") or url_for("index"))
            flash("Token incorrecto", "error")
        return render_template("login.html")

    # ------------------------------------------------------------------ panel
    @app.route("/")
    def index():  # noqa: ANN202
        conn = get_db()
        counts = store.count_devices(conn)
        today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        since = int(today.timestamp() * 1000)
        sev = store.event_counts(conn, since)
        recent = store.list_events(conn, limit=8)
        base = baseline_status(conn)
        total_today = sum(sev.values())
        fp_today = conn.execute(
            "SELECT COUNT(*) AS n FROM events WHERE last_ts >= ? AND disposicion = 'fp'",
            (since,)).fetchone()["n"]
        return render_template(
            "index.html", counts=counts, sev=sev, recent=recent, base=base,
            total_today=total_today, fp_today=int(fp_today),
            health=_health(conn), caps=caps.summary(), mode_notes=mode_notes,
        )

    # ------------------------------------------------------------ dispositivos
    @app.route("/devices")
    def devices():  # noqa: ANN202
        conn = get_db()
        estado = request.args.get("estado") or None
        search = request.args.get("q") or None
        only_online = request.args.get("online") == "1"
        rows = store.list_devices(conn, estado=estado, search=search,
                                  only_online=only_online)
        counts = store.count_devices(conn)
        return render_template("devices.html", devices=rows, counts=counts,
                               filtro={"estado": estado or "", "q": search or "",
                                       "online": only_online})

    @app.route("/devices/<int:device_id>")
    def device_detail(device_id: int):  # noqa: ANN202
        conn = get_db()
        device = store.get_device(conn, device_id)
        if device is None:
            abort(404)
        assert device is not None  # abort no retorna; ayuda al type checker
        gateway_ip = baseline_status(conn)["gateway_ip"] or cfg.network.gateway_ip
        return render_template(
            "device.html", device=device, ports=store.list_ports(conn, device_id),
            history=store.list_history(conn, device_id),
            events=store.events_for_device(conn, device_id),
            is_gateway=(device["ip_actual"] == gateway_ip),
            scans=list(conn.execute(
                "SELECT * FROM scans WHERE device_id = ? ORDER BY id DESC LIMIT 10",
                (device_id,))),
            profiles=("quick", "standard", "vuln"),
        )

    @app.route("/devices/<int:device_id>", methods=["POST"])
    def device_update(device_id: int):  # noqa: ANN202
        conn = get_db()
        device = store.get_device(conn, device_id)
        if device is None:
            abort(404)
        estado = request.form.get("estado") or None
        alias = request.form.get("alias")
        try:
            changed = store.set_device_state(
                conn, device_id, estado=estado if estado in TRUST_LABEL else None,
                alias=alias if alias is not None else None)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("device_detail", device_id=device_id))
        flash("Cambios guardados" if changed else "Sin cambios", "ok")
        return redirect(url_for("device_detail", device_id=device_id))

    # ----------------------------------------------------------------- alertas
    @app.route("/events")
    def events():  # noqa: ANN202
        conn = get_db()
        severidad = request.args.get("severidad") or None
        tipo = request.args.get("tipo") or None
        rows = store.list_events(conn, severidad=severidad, tipo=tipo, limit=300)
        tipos = [r["tipo"] for r in conn.execute(
            "SELECT DISTINCT tipo FROM events ORDER BY tipo")]
        return render_template("events.html", events=rows, tipos=tipos,
                               filtro={"severidad": severidad or "", "tipo": tipo or ""})

    @app.route("/events/<int:event_id>/disposicion", methods=["POST"])
    def event_disposition(event_id: int):  # noqa: ANN202
        conn = get_db()
        value = request.form.get("disposicion", "sin_evaluar")
        try:
            store.set_disposition(conn, event_id, value)
            flash("Disposición registrada (alimenta el KPI de falsos positivos)", "ok")
        except ValueError as exc:
            flash(str(exc), "error")
        return redirect(request.referrer or url_for("events"))

    # ------------------------------------------------------------- línea base
    @app.route("/learning")
    def learning():  # noqa: ANN202
        conn = get_db()
        return render_template("learning.html", base=baseline_status(conn),
                               pending=review_candidates(conn),
                               all_devices=store.list_devices(conn, limit=200))

    @app.route("/learning/approve", methods=["POST"])
    def learning_approve():  # noqa: ANN202
        conn = get_db()
        include = request.form.get("include_random") == "1"
        result = approve_baseline(conn, include_random_mac=include)
        flash(f"Línea base aprobada: {result['aprobados']} confiables, "
              f"{result['pendientes']} en revisión", "ok")
        return redirect(url_for("learning"))

    # ---------------------------------------------------------------- escaneo
    @app.route("/scan", methods=["POST"])
    def scan_request():  # noqa: ANN202
        conn = get_db()
        objetivo = valid_ipv4(request.form.get("objetivo"))
        perfil = request.form.get("perfil", "quick")
        back = request.form.get("back") or url_for("devices")
        if not objetivo or not ip_in_cidr(objetivo, cfg.network.cidr):
            flash(f"Objetivo inválido o fuera de {cfg.network.cidr}", "error")
            return redirect(back)
        if perfil not in ("quick", "standard", "vuln"):
            flash("Perfil inválido", "error")
            return redirect(back)
        if perfil == "vuln" and request.form.get("confirm") != "1":
            flash("El escaneo de vulnerabilidades es intrusivo: hay que confirmarlo", "error")
            return redirect(back)
        req_id = store.create_scan_request(conn, objetivo, perfil, "dashboard", now_ms())
        if req_id is None:
            flash("Ya hay un escaneo pendiente para ese objetivo y perfil", "warn")
        else:
            flash(f"Escaneo {perfil} solicitado para {objetivo}", "ok")
        return redirect(back)

    # ------------------------------------------------------------------ salud
    @app.route("/health")
    def health_page():  # noqa: ANN202
        conn = get_db()
        health = _health(conn)
        try:
            size = cfg.paths.db.stat().st_size
        except OSError:
            size = 0
        tools = store.tool_status(conn)
        hb = store.get_heartbeat(conn, "sensor")
        return render_template("health.html", health=health, caps=caps,
                               caps_summary=caps.summary(), mode_notes=mode_notes,
                               udp_note=udp_note,
                               tools=tools, heartbeat=hb, db_size=size,
                               requests=list(conn.execute(
                                   "SELECT * FROM scan_requests ORDER BY id DESC LIMIT 20")),
                               effective_mode=mode)

    @app.errorhandler(404)
    def _404(_exc):  # noqa: ANN202
        return render_template("error.html", code=404,
                               message="Ese recurso no existe"), 404

    @app.errorhandler(400)
    def _400(exc):  # noqa: ANN202
        return render_template("error.html", code=400,
                               message=getattr(exc, "description", "Petición inválida")), 400

    return app
