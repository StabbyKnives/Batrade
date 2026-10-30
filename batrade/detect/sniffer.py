"""Sniffer pasivo con scapy (sólo modo live).

Requiere CAP_NET_RAW. En esta VM no está disponible, por eso el proyecto separa
la conversión paquete->observación en ``scenarios.observation_from_packet``, que
se prueba con pcaps sin necesidad de privilegios.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Callable

from batrade.detect.observation import Observation
from batrade.detect.scenarios import observation_from_packet

log = logging.getLogger("batrade.sniffer")

# ARP + DHCP + SYN. Un BPF demasiado amplio tiraría la CPU del hogar.
DEFAULT_FILTER = "arp or udp port 67 or udp port 68 or (tcp and tcp[tcpflags] & tcp-syn != 0)"


def sniff_observations(iface: str, on_observation: Callable[[Observation], None],
                       stop_event: threading.Event,
                       bpf: str = DEFAULT_FILTER) -> None:
    """Bucle de captura que respeta ``stop_event`` y no acumula paquetes."""
    try:
        from scapy.all import sniff
    except Exception as exc:  # noqa: BLE001
        log.error("scapy no disponible: %s", exc)
        return

    packets = 0

    def handle(pkt) -> None:
        nonlocal packets
        packets += 1
        try:
            obs = observation_from_packet(pkt, int(time.time() * 1000))
        except Exception:  # noqa: BLE001
            log.exception("no se pudo convertir un paquete")
            return
        if obs is not None:
            try:
                on_observation(obs)
            except Exception:  # noqa: BLE001
                log.exception("fallo procesando la observación")

    while not stop_event.is_set():
        try:
            # store=False es obligatorio: acumular paquetes rompe el KPI de memoria.
            sniff(iface=iface, filter=bpf, prn=handle, store=False, timeout=2)
        except PermissionError:
            log.error("sin CAP_NET_RAW: sniffer deshabilitado")
            return
        except OSError as exc:
            log.warning("error de captura (%s); reintentando en 5 s", exc)
            if stop_event.wait(5):
                return
        except Exception as exc:  # noqa: BLE001
            log.exception("sniffer detenido por error: %s", exc)
            return
    log.info("sniffer detenido tras %d paquetes", packets)
