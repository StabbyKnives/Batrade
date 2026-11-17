"""Preflight de capacidades del sistema.

El PRD asume CAP_NET_RAW. Esta VM no lo tiene, así que el sensor **debe**
arrancar degradado en lugar de morir: el modo efectivo se decide aquí y se
publica en el dashboard para que el operador nunca crea que está capturando
cuando en realidad no puede.
"""
from __future__ import annotations

import os
import shutil
import socket
from dataclasses import dataclass, field

AF_PACKET = 17  # socket.AF_PACKET en Linux; no expuesto de forma estable en Python
AF_NETLINK = 16
NETLINK_ROUTE = 0
RTMGRP_NEIGH = 4


@dataclass(slots=True)
class Capabilities:
    raw_capture: bool = False
    arp_scan: bool = False
    nmap: bool = False
    netlink_neigh: bool = False
    tshark: bool = False
    scapy: bool = False
    arpspoof: bool = False
    iproute: bool = False
    is_root: bool = False
    reasons: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, bool]:
        return {
            "raw_capture": self.raw_capture,
            "arp_scan": self.arp_scan,
            "nmap": self.nmap,
            "netlink_neigh": self.netlink_neigh,
            "tshark": self.tshark,
            "scapy": self.scapy,
            "iproute": self.iproute,
            "is_root": self.is_root,
        }


def _probe_raw_socket() -> tuple[bool, str | None]:
    try:
        with socket.socket(AF_PACKET, socket.SOCK_RAW, 0) as sock:
            sock.settimeout(0.2)
        return True, None
    except PermissionError:
        return False, "sin CAP_NET_RAW: captura pasiva y arp-scan no disponibles"
    except OSError as exc:
        return False, f"AF_PACKET no disponible: {exc}"


def _probe_netlink() -> tuple[bool, str | None]:
    try:
        with socket.socket(AF_NETLINK, socket.SOCK_RAW, NETLINK_ROUTE) as sock:
            sock.bind((0, RTMGRP_NEIGH))
        return True, None
    except OSError as exc:
        return False, f"netlink de vecinos no disponible: {exc}"


def _probe_scapy() -> bool:
    try:
        import scapy  # noqa: F401
        return True
    except Exception:
        return False


def probe() -> Capabilities:
    caps = Capabilities()
    caps.is_root = os.geteuid() == 0

    caps.raw_capture, raw_reason = _probe_raw_socket()
    if raw_reason:
        caps.reasons.append(raw_reason)

    caps.netlink_neigh, nl_reason = _probe_netlink()
    if nl_reason:
        caps.reasons.append(nl_reason)

    caps.arp_scan = shutil.which("arp-scan") is not None
    if not caps.arp_scan:
        caps.reasons.append("arp-scan no instalado")
    caps.iproute = shutil.which("ip") is not None
    if not caps.iproute:
        caps.reasons.append(
            "iproute2 (ip) no disponible: sin descubrimiento por vecinos ni barrido TCP"
        )
    caps.nmap = shutil.which("nmap") is not None
    if not caps.nmap:
        caps.reasons.append("nmap no instalado")
    caps.tshark = shutil.which("tshark") is not None
    caps.arpspoof = shutil.which("arpspoof") is not None
    caps.scapy = _probe_scapy()
    if not caps.scapy:
        caps.reasons.append("scapy no instalado: modo replay deshabilitado")
    return caps


def resolve_mode(requested: str, caps: Capabilities) -> tuple[str, list[str]]:
    """Devuelve (modo_efectivo, avisos). Nunca falla por falta de privilegios."""
    requested = (requested or "auto").lower()
    notes: list[str] = []

    if requested in ("replay", "simulate"):
        if not caps.scapy:
            raise RuntimeError("El modo replay/simulate requiere scapy instalado")
        return requested, notes

    if requested == "live":
        missing = []
        if not caps.raw_capture:
            missing.append("CAP_NET_RAW")
        if not caps.arp_scan:
            missing.append("arp-scan")
        if missing:
            notes.append(
                "modo live solicitado pero falta " + ", ".join(missing)
                + "; se arranca en modo degradado"
            )
            return "degraded", notes
        return "live", notes

    if requested == "degraded":
        return "degraded", notes

    # auto
    if caps.raw_capture and caps.arp_scan:
        return "live", notes
    notes.append("modo auto: sin CAP_NET_RAW -> modo degradado (netlink + nmap -sT)")
    return "degraded", notes


def scan_style(caps: Capabilities) -> str:
    """nmap sin privilegios hace connect scan (-sT) automáticamente."""
    return "-sS" if caps.raw_capture else "-sT"
