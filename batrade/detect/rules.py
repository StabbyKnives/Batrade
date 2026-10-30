"""Reglas de detección (RF-11, RF-12, RF-13).

Cada regla es pura: recibe una observación y el estado, y devuelve hallazgos.
No envía paquetes, no escribe en la base y no conoce el transporte. La
verificación activa y el dedupe viven fuera, en el sensor y en el repositorio.

Desviaciones conscientes documentadas en README:
  - La "ráfaga ARP" exige al menos un conflicto de binding: el volumen solo
    nunca alerta (C6), si no un reinicio de router dispara críticos.
  - "Misma MAC, varias IPs" es Crítico solo si una de las IPs es la puerta de
    enlace; en el resto de casos es Advertencia para no confundir proxy ARP.
"""
from __future__ import annotations

from batrade.config import Config
from batrade.detect.observation import ARP, DHCP, NEIGH, SYN, Finding, Observation
from batrade.detect.state import Baseline, EngineState
from batrade.net.iputil import (
    is_locally_administered,
    is_multicast_mac,
    normalize_mac,
    valid_ipv4,
)

# Si el binding previo tiene más antigüedad que esto, un cambio de MAC se
# interpreta como reutilización legítima de IP por DHCP y no como ataque.
BINDING_REUSE_MS = 3_600_000
ARP_FLOOD_MIN = 20


def _f(tipo: str, severidad: str, clave: str, *, resumen: str, por_que: str,
       accion: str, ip_origen: str | None = None, mac_origen: str | None = None,
       ip_destino: str | None = None, needs_verify: str | None = None,
       **extra) -> Finding:
    detalle = {"resumen": resumen, "por_que": por_que, "accion": accion, **extra}
    return Finding(tipo=tipo, severidad=severidad, clave=clave, ip_origen=ip_origen,
                   mac_origen=mac_origen, ip_destino=ip_destino, detalle=detalle,
                   needs_verify=needs_verify)


class ArpBindingRule:
    """Cambio de MAC para una IP conocida, una MAC reclamando varias IPs."""

    name = "arp_binding"

    def evaluate(self, obs: Observation, state: EngineState, baseline: Baseline,
                 cfg: Config) -> list[Finding]:
        if obs.kind not in (ARP, NEIGH):
            return []
        if obs.op not in (None, "reply", "request"):
            return []
        ip = valid_ipv4(obs.ip_src)
        mac = normalize_mac(obs.mac_src)
        if not ip or not mac or is_multicast_mac(mac):
            return []
        # Autoexclusión del propio sensor (RF-12)
        if ip in baseline.sensor_ips or mac in baseline.sensor_macs:
            return []

        findings: list[Finding] = []
        is_gateway = baseline.gateway_ip == ip
        prev = state.binding(ip)

        if prev is None:
            binding = state.learn_binding(ip, mac, obs.ts)
            binding.in_baseline = True
            if is_gateway and not baseline.gateway_mac:
                baseline.gateway_mac = mac
        elif prev.mac != mac:
            trusted = baseline.gateway_mac if is_gateway else None
            if is_gateway and trusted and mac == trusted:
                # Vuelve la MAC legítima: sólo refrescamos.
                prev.last_ts = obs.ts
            else:
                stale = (obs.ts - prev.last_ts) > BINDING_REUSE_MS
                if is_gateway:
                    severity, tipo = "crit", "arp_gateway_mac_change"
                    resumen = (f"La puerta de enlace {ip} pasó de {prev.mac} a {mac}")
                    por_que = ("Alguien puede estar interceptando el tráfico de toda la "
                               "red (ARP spoofing / MITM).")
                    accion = ("Verificar el router y aislar el equipo con MAC "
                              f"{mac}; revisar si hay un test de laboratorio en curso.")
                elif stale:
                    severity, tipo = "info", "arp_ip_reuse"
                    resumen = f"La IP {ip} fue reasignada de {prev.mac} a {mac}"
                    por_que = "Reutilización normal de una IP por DHCP."
                    accion = "Ninguna; es un cambio esperado."
                else:
                    severity, tipo = "warn", "arp_ip_mac_change"
                    resumen = f"La IP {ip} respondió con una MAC distinta ({prev.mac} -> {mac})"
                    por_que = ("Puede ser suplantación de identidad en la LAN o un cambio "
                               "legítimo de dirección.")
                    accion = "Comprobar qué equipo tiene esa MAC y si debía tener esa IP."
                state.conflicts.add(mac, obs.ts, ip)
                findings.append(_f(
                    tipo, severity, f"arp:bind:{ip}:{mac}",
                    resumen=resumen, por_que=por_que, accion=accion,
                    ip_origen=ip, mac_origen=mac, ip_destino=ip,
                    prev_mac=prev.mac, gratuitous=obs.gratuitous,
                    needs_verify=ip if is_gateway else None,
                ))
                prev.last_ts = obs.ts
                if not is_gateway:
                    prev.mac, prev.first_ts, prev.count = mac, obs.ts, 1

        # Una misma MAC reclamando varias IPs
        if mac not in baseline.exceptions:
            claimed = state.mac_claims.add(mac, obs.ts, ip)
            distinct = state.mac_claims.distinct(mac, obs.ts)
            if distinct >= 2 and claimed >= 2:
                ips = [str(v) for v in state.mac_claims.values(mac, obs.ts) if v]
                if baseline.gateway_ip in ips or ip in baseline.sensor_ips:
                    severity = "crit"
                else:
                    severity = "warn"
                findings.append(_f(
                    "arp_mac_multiple_ips", severity, f"arp:multiip:{mac}",
                    resumen=f"La MAC {mac} aparece reclamando varias IPs: {', '.join(sorted(set(ips)))}",
                    por_que=("Un equipo que responde por varias IPs suele ser un intento de "
                             "suplantación; también puede ser un router con proxy ARP."),
                    accion=("Confirmar si es un proxy ARP/failover legítimo; si no, "
                            "aislar ese equipo y añadir la MAC a detect.arp_exceptions."),
                    ip_origen=ip, mac_origen=mac,
                    ips=sorted(set(ips)),
                ))
        return findings


class ArpSweepRule:
    """RF-12: 30 o más ARP requests a IPs distintas en la ventana."""

    name = "arp_sweep"

    def evaluate(self, obs: Observation, state: EngineState, baseline: Baseline,
                 cfg: Config) -> list[Finding]:
        if obs.kind != ARP or obs.op != "request":
            return []
        mac = normalize_mac(obs.mac_src)
        target = valid_ipv4(obs.ip_dst) or valid_ipv4(obs.ip_src)
        if not mac or not target or is_multicast_mac(mac):
            return []
        if mac in baseline.sensor_macs or mac in baseline.exceptions:
            return []
        if baseline.gateway_mac and mac == baseline.gateway_mac:
            return []  # el router sondea la red constantemente
        state.arp_requests.add(mac, obs.ts, target)
        distinct = state.arp_requests.distinct(mac, obs.ts)
        threshold = cfg.detect.arp_sweep_ips
        if distinct < threshold:
            return []
        crit = distinct >= threshold * 3
        return [_f(
            "arp_sweep", "crit" if crit else "warn", f"arp:sweep:{mac}",
            resumen=(f"Barrido ARP desde {mac}: {distinct} IPs distintas en "
                     f"{cfg.detect.window_s} s"),
            por_que=("Es el reconocimiento previo a un ataque: el equipo está "
                     "descubriendo todos los hosts de la red."),
            accion=("Identificar el equipo por su MAC y confirmar si es un escaneo "
                    "autorizado; si no, desconectarlo del Wi-Fi."),
            ip_origen=obs.ip_src, mac_origen=mac, distinct_ips=distinct,
        )]


class ArpFloodRule:
    """Ráfaga de respuestas ARP no solicitadas, sólo con conflicto real (C6)."""

    name = "arp_flood"

    def evaluate(self, obs: Observation, state: EngineState, baseline: Baseline,
                 cfg: Config) -> list[Finding]:
        if obs.kind != ARP or obs.op != "reply":
            return []
        mac = normalize_mac(obs.mac_src)
        if not mac or is_multicast_mac(mac):
            return []
        if mac in baseline.sensor_macs or mac in baseline.exceptions:
            return []
        count = state.arp_replies.add(mac, obs.ts, valid_ipv4(obs.ip_src))
        if count < ARP_FLOOD_MIN:
            return []
        conflicts = state.conflicts.count(mac, obs.ts)
        if conflicts == 0:
            # Volumen sin conflicto de binding: reinicio de router, no ataque.
            return []
        return [_f(
            "arp_flood", "warn", f"arp:flood:{mac}",
            resumen=f"Ráfaga de {count} respuestas ARP desde {mac} con {conflicts} conflicto(s)",
            por_que=("Una emisión masiva de ARP con MACs que no cuadran es el patrón "
                     "típico de un envenenamiento de caché."),
            accion="Aislar el equipo y comprobar la tabla ARP de la puerta de enlace.",
            ip_origen=obs.ip_src, mac_origen=mac, replies=count, conflicts=conflicts,
        )]


class SynScanRule:
    """RF-12: escaneo de puertos visible por el sensor (señuelo o puerto espejo)."""

    name = "syn_scan"

    def evaluate(self, obs: Observation, state: EngineState, baseline: Baseline,
                 cfg: Config) -> list[Finding]:
        if obs.kind != SYN:
            return []
        src = valid_ipv4(obs.ip_src)
        dst = valid_ipv4(obs.ip_dst)
        port = obs.port_dst
        if not src or not dst or port is None:
            return []
        # Excluir el propio sensor: su nmap no debe alertarse a sí mismo (RF-12)
        if src in baseline.sensor_ips or (obs.mac_src and obs.mac_src in baseline.sensor_macs):
            return []
        if "S" not in obs.flags:
            return []
        if "A" in obs.flags or "R" in obs.flags:
            return []  # SYN-ACK / RST no son intentos de conexión

        ports, dsts = state.syn.add(src, dst, port, obs.ts)
        findings: list[Finding] = []
        if ports >= cfg.detect.syn_ports_crit:
            findings.append(_f(
                "scan_ports_aggressive", "crit", f"scan:ports:{src}:{dst}",
                resumen=f"Escaneo agresivo de {ports} puertos desde {src} hacia {dst}",
                por_que="Reconocimiento masivo de la superficie de ataque del equipo.",
                accion="Identificar el origen y detener el escaneo; es actividad hostil o "
                       "un test no autorizado.",
                ip_origen=src, ip_destino=dst, puertos=ports,
            ))
        elif ports >= cfg.detect.syn_ports_warn:
            findings.append(_f(
                "scan_ports_moderate", "warn", f"scan:ports:{src}:{dst}",
                resumen=f"Sondeo de {ports} puertos desde {src} hacia {dst}",
                por_que="Alguien está enumerando servicios del equipo.",
                accion="Comprobar si es un escaneo propio autorizado (Batrade) o un intruso.",
                ip_origen=src, ip_destino=dst, puertos=ports,
            ))
        if dsts >= cfg.detect.syn_dsts_crit:
            findings.append(_f(
                "scan_hosts_aggressive", "crit", f"scan:hosts:{src}",
                resumen=f"Barrido de {dsts} hosts distintos desde {src}",
                por_que="Descubrimiento de toda la red: paso previo a un ataque dirigido.",
                accion="Localizar el equipo origen y revisar su estado.",
                ip_origen=src, hosts=dsts,
            ))
        return findings


class DhcpRogueRule:
    """RF-13: DHCPOFFER de un servidor distinto del esperado."""

    name = "dhcp_rogue"

    def evaluate(self, obs: Observation, state: EngineState, baseline: Baseline,
                 cfg: Config) -> list[Finding]:
        if obs.kind != DHCP or obs.op != "offer":
            return []
        server = valid_ipv4(obs.ip_src)
        if not server:
            return []
        expected = baseline.dhcp_server_ip
        if not expected:
            baseline.dhcp_server_ip = server
            return []
        if server == expected:
            return []
        return [_f(
            "dhcp_rogue", "crit", f"dhcp:rogue:{server}",
            resumen=f"DHCPOFFER de {server}, distinto del servidor esperado ({expected})",
            por_que=("Un servidor DHCP falso reparte puertas de enlace y DNS para "
                     "desviar todo el tráfico de la red."),
            accion=("Desconectar el equipo que ofrece DHCP y renovar los leases de "
                    "los clientes afectados."),
            ip_origen=server, mac_origen=normalize_mac(obs.mac_src),
            expected=expected, yiaddr=obs.extra.get("yiaddr"),
        )]


RULES = (ArpBindingRule(), ArpSweepRule(), ArpFloodRule(), SynScanRule(), DhcpRogueRule())


def is_private_mac(mac: str) -> bool:
    return is_locally_administered(mac)
