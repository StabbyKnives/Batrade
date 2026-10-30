"""Interfaz de línea de comandos de Batrade.

    python3 -m batrade doctor
    python3 -m batrade init
    python3 -m batrade sensor --mode simulate --scenario mixed
    python3 -m batrade dashboard
    python3 -m batrade approve-baseline
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import logging
import sys
from pathlib import Path

from batrade import __version__, db, store
from batrade.config import Config, ConfigError, load
from batrade.logging_setup import setup_logging
from batrade.net import caps as caps_mod
from batrade.net.iputil import default_gateway, interface_ipv4

log = logging.getLogger("batrade.cli")


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="batrade", description="Batrade Home-SOC")
    p.add_argument("--config", default="config.yaml", help="ruta de config.yaml")
    p.add_argument("--root", default=None, help="raíz del proyecto (por defecto cwd)")
    p.add_argument("--version", action="version", version=f"Batrade {__version__}")
    # Permite escribir `batrade sensor --config ...` además de `batrade --config ... sensor`.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", default=argparse.SUPPRESS)
    common.add_argument("--root", default=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("doctor", parents=[common], help="diagnóstico de entorno y configuración")
    sub.add_parser("init", parents=[common], help="crea la base de datos y los directorios")

    s = sub.add_parser("sensor", parents=[common], help="ejecuta el demonio de monitoreo")
    s.add_argument("--mode", default=None,
                   choices=["auto", "live", "degraded", "replay", "simulate"])
    s.add_argument("--scenario", default="mixed",
                   help="escenario sintético (arp_spoof, arp_sweep, syn_scan, dhcp_rogue, "
                        "router_reboot, mixed)")
    s.add_argument("--pcap", default=None, help="pcap a reproducir en modo replay")
    s.add_argument("--speed", type=float, default=5.0,
                   help="factor de aceleración del replay (por defecto 5x)")
    s.add_argument("--duration", type=float, default=None,
                   help="segundos antes de detenerse (útil en pruebas)")

    d = sub.add_parser("dashboard", parents=[common], help="sirve el panel web")
    d.add_argument("--host", default=None)
    d.add_argument("--port", type=int, default=None)

    demo = sub.add_parser("demo", parents=[common], help="siembra la base con escenarios de demostración")
    demo.add_argument("--scenarios", default="mixed,router_reboot",
                      help="lista separada por comas")

    ab = sub.add_parser("approve-baseline", parents=[common], help="aprueba el inventario como línea base")
    ab.add_argument("--include-random-mac", action="store_true",
                    help="aprueba también dispositivos con MAC aleatoria (no recomendado)")

    ex = sub.add_parser("export", parents=[common], help="exporta inventario o eventos")
    ex.add_argument("--what", choices=["devices", "events", "ports"], default="devices")
    ex.add_argument("--format", choices=["csv", "json"], default="csv")
    ex.add_argument("--out", default=None, help="archivo de salida (por defecto stdout)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        cfg = load(args.config, args.root)
    except ConfigError as exc:
        print("Configuración inválida:", file=sys.stderr)
        for err in exc.errors:
            print(f"  - {err}", file=sys.stderr)
        return 2

    setup_logging(cfg.paths.log_dir, "batrade")
    handler = {"doctor": cmd_doctor, "init": cmd_init, "sensor": cmd_sensor,
               "dashboard": cmd_dashboard, "demo": cmd_demo,
               "approve-baseline": cmd_approve, "export": cmd_export}[args.command]
    try:
        return int(handler(cfg, args) or 0)
    except KeyboardInterrupt:
        print("\ninterrumpido", file=sys.stderr)
        return 130


# --------------------------------------------------------------------------- #
# Comandos
# --------------------------------------------------------------------------- #
def cmd_doctor(cfg: Config, _args) -> int:
    caps = caps_mod.probe()
    mode, notes = caps_mod.resolve_mode(cfg.sensor.mode, caps)
    conn = db.initialize(cfg.paths.db)
    rows = store.count_devices(conn)
    hb = store.get_heartbeat(conn, "sensor")

    print(f"Batrade {__version__}  ·  {cfg.root}")
    print(f"  interfaz        : {cfg.network.interface} "
          f"({interface_ipv4(cfg.network.interface) or 'sin IPv4'})")
    print(f"  subred          : {cfg.network.cidr}")
    print(f"  gateway         : {cfg.network.gateway_ip or default_gateway() or 'desconocido'}")
    print(f"  modo solicitado : {cfg.sensor.mode}  ->  efectivo: {mode}")
    print(f"  CAP_NET_RAW     : {'sí' if caps.raw_capture else 'NO'}")
    print(f"  arp-scan        : {'sí' if caps.arp_scan else 'NO'}   "
          f"nmap: {'sí' if caps.nmap else 'NO'}   "
          f"tshark: {'sí' if caps.tshark else 'NO'}")
    print(f"  netlink vecinos : {'sí' if caps.netlink_neigh else 'NO'}   "
          f"scapy: {'sí' if caps.scapy else 'NO'}")
    print(f"  base de datos   : {cfg.paths.db}  schema v{db.SCHEMA_VERSION}")
    print(f"  dispositivos    : {rows.get('total', 0)} "
          f"(en línea {rows.get('online', 0)}, desconocidos {rows.get('desconocidos', 0)})")
    print(f"  heartbeat       : {'nunca' if hb is None else hb['ts']}")
    for note in notes:
        print(f"  aviso           : {note}")
    for reason in caps.reasons:
        print(f"  limitación      : {reason}")
    print("\nConsejo: `python3 -m batrade demo` puebla el panel sin privilegios.")
    return 0


def cmd_init(cfg: Config, _args) -> int:
    conn = db.initialize(cfg.paths.db)
    ts = store_now()
    gw = cfg.network.gateway_ip or default_gateway()
    if gw:
        store.set_meta(conn, "gateway_ip", gw, ts)
    store.set_meta(conn, "sensor_mode", cfg.sensor.mode, ts)
    print(f"Base de datos lista en {cfg.paths.db}")
    print(f"Directorio de escaneos: {cfg.paths.scans_dir}")
    print("Siguiente paso: `python3 -m batrade sensor --mode degraded` y "
          "`python3 -m batrade dashboard` en otra terminal.")
    return 0


def cmd_sensor(cfg: Config, args) -> int:
    from batrade.sensor import Sensor

    mode = args.mode or cfg.sensor.mode
    sensor = Sensor(cfg, mode, scenario=args.scenario, pcap=args.pcap,
                    speed=args.speed, duration=args.duration)
    print(f"batrade-sensor en modo {sensor.mode} · {cfg.network.cidr} sobre "
          f"{cfg.network.interface}")
    for note in sensor.mode_notes:
        print(f"  aviso: {note}")
    if sensor.mode in ("replay", "simulate"):
        print(f"  alimentando motor desde "
              f"{args.pcap or args.scenario} a {args.speed}x")
    sensor.run()
    return 0


def cmd_dashboard(cfg: Config, args) -> int:
    from batrade.dashboard.app import create_app

    host = args.host or cfg.dashboard.host
    port = args.port or cfg.dashboard.port
    app = create_app(cfg)
    print(f"Panel en http://{host}:{port}  (Ctrl+C para detener)")
    if host not in ("127.0.0.1", "localhost", "::1") and not cfg.dashboard.auth_token:
        print("  ADVERTENCIA: expuesto fuera de loopback sin DASHBOARD_TOKEN", file=sys.stderr)
    app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)
    return 0


def cmd_demo(cfg: Config, args) -> int:
    from batrade.demo import seed_demo

    names = [s.strip() for s in args.scenarios.split(",") if s.strip()]
    final = seed_demo(cfg, names)
    print("Datos de demostración cargados:")
    for k, v in final.items():
        print(f"  {k:<14}: {v}")
    print("\nAbre el panel con: python3 -m batrade dashboard")
    return 0


def cmd_approve(cfg: Config, args) -> int:
    from batrade.inventory import approve_baseline

    conn = db.initialize(cfg.paths.db)
    result = approve_baseline(conn, include_random_mac=args.include_random_mac)
    print(f"Aprobados como confiables: {result['aprobados']}")
    print(f"Quedan en revisión        : {result['pendientes']}")
    return 0


def cmd_export(cfg: Config, args) -> int:
    conn = db.connect(cfg.paths.db, readonly=True)
    if args.what == "devices":
        rows = [dict(r) for r in conn.execute(
            "SELECT id, mac, ip_actual, fabricante, hostname, alias, estado_confianza, "
            "mac_aleatoria, first_seen, last_seen, en_linea FROM devices ORDER BY id")]
    elif args.what == "ports":
        rows = [dict(r) for r in conn.execute(
            "SELECT device_id, protocolo, puerto, estado, servicio, version, riesgoso, "
            "first_seen, last_seen FROM ports ORDER BY device_id, puerto")]
    else:
        rows = [dict(r) for r in conn.execute(
            "SELECT id, ts, severidad, tipo, ip_origen, mac_origen, ip_destino, "
            "repeat_count, disposicion, notificado FROM events ORDER BY ts DESC")]
    conn.close()

    if args.format == "json":
        payload = json.dumps(rows, ensure_ascii=False, indent=2, default=str)
    else:
        buf = io.StringIO()
        if rows:
            writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        payload = buf.getvalue()

    if args.out:
        Path(args.out).write_text(payload, encoding="utf-8")
        print(f"Exportadas {len(rows)} filas a {args.out}")
    else:
        print(payload)
    return 0


def store_now() -> int:
    from batrade.net.iputil import now_ms
    return now_ms()
