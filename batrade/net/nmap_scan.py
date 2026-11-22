"""Perfilado con nmap: perfiles, ejecución sin shell y parseo XML endurecido.

RNF-05: sin ``shell=True``, argumentos en lista, objetivo validado contra el CIDR
y XML leído con defusedxml (nunca con el parser estándar).
"""
from __future__ import annotations

import logging
import os
import re
import stat
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from defusedxml import ElementTree as DET

from batrade.config import Config
from batrade.net.caps import Capabilities
from batrade.net.iputil import ip_in_cidr, now_ms, valid_ipv4

log = logging.getLogger("batrade.nmap")

PROFILES: dict[str, list[str]] = {
    # RF-07 rápido: -F son 100 puertos, no 1000 (corrección #2 del PRD).
    "quick": ["-F", "--version-light"],
    # RF-07 estándar: top 1000 + detección de versión ligera.
    "standard": ["-sV", "--top-ports", "1000", "--version-light"],
    # RF-09 bajo demanda, intrusivo.
    "vuln": ["-sV", "--script", "vuln"],
}

PROFILE_TIMEOUT = {"quick": 120, "standard": 300, "vuln": 900}
HOST_TIMEOUT = {"quick": "60s", "standard": "120s", "vuln": "300s"}


def profile_timeout(cfg: Config, profile: str) -> int:
    """Límite de proceso del perfil, respetando ``scan.*_timeout`` del YAML.

    ``quick_timeout`` sustituye al valor fijo de 120 s del perfil rápido; el
    perfil ``standard`` mantiene su tope histórico y ``vuln`` es siempre el más
    largo porque ejecuta scripts.
    """
    default = PROFILE_TIMEOUT.get(profile, 300)
    if profile == "quick":
        return max(1, int(cfg.scan.quick_timeout))
    if profile == "standard":
        return max(1, min(default, int(cfg.scan.standard_timeout)))
    return default


class ScanError(RuntimeError):
    pass


@dataclass(slots=True)
class ScanResult:
    target: str
    profile: str
    ports: list[dict[str, Any]] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    xml_path: str | None = None
    cmd: list[str] = field(default_factory=list)
    exit_code: int | None = None
    duration_ms: int = 0
    notes: list[str] = field(default_factory=list)


def build_argv(cfg: Config, target: str, profile: str, caps: Capabilities,
               xml_path: Path) -> list[str]:
    if profile not in PROFILES:
        raise ScanError(f"perfil desconocido: {profile}")
    if not ip_in_cidr(target, cfg.network.cidr):
        raise ScanError(f"objetivo fuera del CIDR configurado: {target}")
    style = "-sS" if caps.raw_capture else "-sT"
    argv = ["nmap", style, "-Pn", *PROFILES[profile],
            cfg.scan.timing, "--host-timeout", HOST_TIMEOUT[profile],
            "-oX", str(xml_path), target]
    return argv


def run_scan(cfg: Config, target: str, profile: str = "standard",
             caps: Capabilities | None = None,
             timeout: int | None = None) -> ScanResult:
    """Ejecuta nmap y devuelve puertos y hostnames. No lanza por fallo de red."""
    target = valid_ipv4(target) or ""
    if not target:
        raise ScanError("objetivo IPv4 inválido")
    caps = caps or Capabilities()
    cfg.paths.scans_dir.mkdir(parents=True, exist_ok=True)
    try:
        cfg.paths.scans_dir.chmod(0o700)
    except OSError:
        pass

    xml_path = cfg.paths.scans_dir / f"scan-{profile}-{target}-{int(time.time())}.xml"
    argv = build_argv(cfg, target, profile, caps, xml_path)
    limit = timeout or profile_timeout(cfg, profile)
    start = now_ms()
    result = ScanResult(target=target, profile=profile, xml_path=str(xml_path), cmd=argv)

    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=limit,
                              check=False)
        result.exit_code = proc.returncode
        stderr = proc.stderr.strip()
    except subprocess.TimeoutExpired:
        _safe_unlink(xml_path)
        raise ScanError(f"nmap excedió {limit}s en {target}")
    except OSError as exc:
        raise ScanError(f"no se pudo ejecutar nmap: {exc}") from exc

    result.duration_ms = now_ms() - start
    if not xml_path.exists():
        raise ScanError(f"nmap no generó XML (código {result.exit_code}): {stderr[:200]}")
    try:
        parsed = parse_xml(xml_path)
    except Exception as exc:
        raise ScanError(f"XML de nmap inválido: {exc}") from exc
    result.ports = parsed["ports"]
    result.hostnames = parsed["hostnames"]
    try:
        xml_path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 600
    except OSError:
        pass
    if result.exit_code not in (0, None):
        result.notes.append(f"nmap terminó con código {result.exit_code}")
    return result


def parse_xml(path: str | Path) -> dict[str, Any]:
    """Parsea el XML de nmap con defusedxml (bloquea entidades externas)."""
    raw = Path(path).read_bytes()
    # Se elimina la declaración DOCTYPE completa (nmap la incluye); hacerlo por
    # reemplazo textual simple dejaría un fragmento inválido.
    raw = re.sub(rb"<!DOCTYPE[^>]*>", b"", raw, flags=re.IGNORECASE)
    root = DET.fromstring(raw)
    ports: list[dict[str, Any]] = []
    hostnames: list[str] = []

    for hostname in root.iter("hostname"):
        name = (hostname.get("name") or "").strip()
        if name:
            hostnames.append(name)

    for port in root.iter("port"):
        state_el = port.find("state")
        state = (state_el.get("state") if state_el is not None else "") or ""
        if state != "open":
            continue
        service_el = port.find("service")
        service = version = None
        if service_el is not None:
            service = service_el.get("name")
            product = service_el.get("product") or ""
            ver = service_el.get("version") or ""
            extra = service_el.get("extrainfo") or ""
            version = " ".join(p for p in (product, ver, extra) if p).strip() or None
        try:
            portid = int(port.get("portid", "0"))
        except (TypeError, ValueError):
            continue
        ports.append({
            "port": portid,
            "protocol": (port.get("protocol") or "tcp").lower(),
            "state": state,
            "service": service,
            "version": version,
        })
    return {"ports": ports, "hostnames": hostnames}


def _safe_unlink(path: Path) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def udp_risky_ports(cfg: Config, caps: Capabilities) -> tuple[list[int], str | None]:
    """Los puertos riesgosos UDP sólo se pueden verificar con privilegios."""
    udp = sorted(p.port for p in cfg.scan.risky_ports.values() if p.protocol == "udp")
    if not udp:
        return [], None
    if not caps.raw_capture:
        return [], ("sin CAP_NET_RAW no se puede escanear UDP: los puertos "
                    f"{udp} no se evaluaron (UPnP/SSDP, mDNS)")
    return udp, None
