"""Verificación activa de un binding ARP (RF-11, decisión C2).

No bloquea la alerta: el sensor emite el Crítico con la evidencia local y lanza
esta comprobación en paralelo para confirmar o rebajar el evento.
"""
from __future__ import annotations

import logging

log = logging.getLogger("batrade.verify")


def probe_binding(ip: str, iface: str | None = None, timeout: float = 1.5) -> set[str] | None:
    """Pregunta por la MAC de ``ip`` y devuelve las MACs que respondieron.

    ``None`` significa "no se pudo verificar" (sin privilegios o scapy ausente),
    que es distinto de "respondió una sola MAC".
    """
    try:
        from scapy.all import ARP, Ether, srp
    except Exception:  # noqa: BLE001
        log.info("scapy no disponible: verificación ARP omitida")
        return None
    try:
        answered, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            timeout=timeout, iface=iface, verbose=0,
        )
    except PermissionError:
        return None
    except Exception as exc:  # noqa: BLE001
        log.warning("verificación ARP falló para %s: %s", ip, exc)
        return None
    macs = set()
    for _sent, received in answered:
        try:
            macs.add(str(received[ARP].hwsrc).lower())
        except (KeyError, AttributeError):
            continue
    return macs


def interpret(macs: set[str] | None, expected: str | None) -> tuple[bool | None, str]:
    """Traduce la respuesta a (confirmado, explicación legible)."""
    if macs is None:
        return None, "No se pudo verificar (sin CAP_NET_RAW): alerta basada sólo en la evidencia pasiva."
    if not macs:
        return None, "La IP no respondió al sondeo de verificación; puede estar inactiva."
    if len(macs) > 1:
        return True, f"Verificado: respondieron {len(macs)} MACs distintas a la misma IP ({', '.join(sorted(macs))})."
    only = next(iter(macs))
    if expected and only == expected:
        return False, f"Sólo respondió la MAC esperada ({only}): posible falso positivo."
    return False, f"Sólo respondió una MAC ({only}), distinta de la esperada ({expected})."


# Estados del bloque ``detalle_json.verificacion``. Distinguen "no verificado"
# de "no verificable": en el primer caso nunca hubo intento, en el segundo el
# sensor no pudo intentarlo (sin CAP_NET_RAW).
ESTADO_NO_VERIFICABLE = "no_verificable"
ESTADO_SIN_RESPUESTA = "sin_respuesta"
ESTADO_CONFIRMADO = "confirmado"
ESTADO_DESCARTADO = "descartado"


def estado_verificacion(macs: set[str] | None, confirmado: bool | None) -> str:
    """Estado legible de la comprobación a partir de lo que respondió la red."""
    if macs is None:
        return ESTADO_NO_VERIFICABLE
    if not macs:
        return ESTADO_SIN_RESPUESTA
    return ESTADO_CONFIRMADO if confirmado else ESTADO_DESCARTADO
