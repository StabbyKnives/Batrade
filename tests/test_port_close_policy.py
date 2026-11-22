"""Cierre de puertos por perfil: `quick` no puede cerrar lo que no exploró.

`quick` usa `-F` (≈100 puertos TCP) y `standard` el top 1000. Si el reescaneo
periódico `quick` cerrase todo lo que no ve, un puerto fuera de esos 100 se
cerraría y volvería a abrirse en el `standard` semanal, generando `port_new`
(warn, notificable) en cada ciclo.
"""
from __future__ import annotations

from batrade import store

TOP_POR_DEFECTO = {"port": 23, "protocol": "tcp", "state": "open", "service": "telnet"}
FUERA_DEL_TOP = {"port": 8000, "protocol": "tcp", "state": "open", "service": "http-alt"}


def _device(conn) -> int:
    return int(store.upsert_device(conn, mac="3c:22:fb:11:22:33", ip="10.10.10.50",
                                   ts=1000)["device_id"])


def _estado(conn, did: int) -> dict[int, str]:
    return {int(p["puerto"]): str(p["estado"]) for p in store.list_ports(conn, did)}


def test_ciclo_standard_quick_standard_no_cierra_ni_reabre(conn, cfg):
    """El puerto 8000 (fuera de -F) no debe parpadear entre perfiles."""
    did = _device(conn)
    riego = cfg.scan.risky_ports

    # 1) `standard` descubre 23 y 8000.
    primero = store.apply_scan_ports(conn, did, [TOP_POR_DEFECTO, FUERA_DEL_TOP],
                                     1000, riego, protocolos={"tcp"}, perfil="standard")
    assert {p["port"] for p in primero["new_ports"]} == {8000}

    # 2) `quick` sólo ve el top-100: 8000 no puede quedar cerrado.
    segundo = store.apply_scan_ports(conn, did, [TOP_POR_DEFECTO],
                                     2000, riego, protocolos={"tcp"}, perfil="quick")
    assert segundo["disappeared"] == []
    assert _estado(conn, did)[8000] == "open"

    # 3) El `standard` semanal vuelve a verlo: no es un puerto nuevo.
    tercero = store.apply_scan_ports(conn, did, [TOP_POR_DEFECTO, FUERA_DEL_TOP],
                                     3000, riego, protocolos={"tcp"}, perfil="standard")
    assert tercero["new_ports"] == []
    assert tercero["new_risky"] == []
    assert tercero["disappeared"] == []


def test_standard_si_cierra_un_puerto_que_desaparece(conn, cfg):
    did = _device(conn)
    riego = cfg.scan.risky_ports
    store.apply_scan_ports(conn, did, [TOP_POR_DEFECTO, FUERA_DEL_TOP], 1000, riego,
                           protocolos={"tcp"}, perfil="standard")

    cierre = store.apply_scan_ports(conn, did, [TOP_POR_DEFECTO], 2000, riego,
                                    protocolos={"tcp"}, perfil="standard")
    assert [p["port"] for p in cierre["disappeared"]] == [8000]
    assert _estado(conn, did)[8000] == "closed"


def test_un_puerto_que_reaparece_tras_cierre_real_es_senal(conn, cfg):
    """Si `standard` lo cerró de verdad, volver a verlo sí es un puerto nuevo."""
    did = _device(conn)
    riego = cfg.scan.risky_ports
    store.apply_scan_ports(conn, did, [TOP_POR_DEFECTO, FUERA_DEL_TOP], 1000, riego,
                           protocolos={"tcp"}, perfil="standard")
    store.apply_scan_ports(conn, did, [TOP_POR_DEFECTO], 2000, riego,
                           protocolos={"tcp"}, perfil="standard")

    reabre = store.apply_scan_ports(conn, did, [TOP_POR_DEFECTO, FUERA_DEL_TOP], 3000,
                                    riego, protocolos={"tcp"}, perfil="standard")
    assert [p["port"] for p in reabre["new_ports"]] == [8000]


def test_vuln_tambien_puede_cerrar(conn, cfg):
    did = _device(conn)
    riego = cfg.scan.risky_ports
    store.apply_scan_ports(conn, did, [TOP_POR_DEFECTO, FUERA_DEL_TOP], 1000, riego,
                           protocolos={"tcp"}, perfil="standard")
    cierre = store.apply_scan_ports(conn, did, [], 2000, riego,
                                    protocolos={"tcp"}, perfil="vuln")
    assert {p["port"] for p in cierre["disappeared"]} == {23, 8000}


def test_perfil_desconocido_no_cierra(conn, cfg):
    """Ante un perfil no contemplado, la opción conservadora es no cerrar."""
    did = _device(conn)
    riego = cfg.scan.risky_ports
    store.apply_scan_ports(conn, did, [TOP_POR_DEFECTO, FUERA_DEL_TOP], 1000, riego,
                           protocolos={"tcp"}, perfil="standard")
    raro = store.apply_scan_ports(conn, did, [], 2000, riego,
                                  protocolos={"tcp"}, perfil="inventado")
    assert raro["disappeared"] == []


def test_sin_perfil_mantiene_el_comportamiento_historico(conn, cfg):
    """Sin `perfil` (llamadores internos y tests antiguos) se sigue cerrando."""
    did = _device(conn)
    riego = cfg.scan.risky_ports
    store.apply_scan_ports(conn, did, [TOP_POR_DEFECTO, FUERA_DEL_TOP], 1000, riego)
    cierre = store.apply_scan_ports(conn, did, [TOP_POR_DEFECTO], 2000, riego)
    assert [p["port"] for p in cierre["disappeared"]] == [8000]


def test_quick_sigue_limitado_a_protocolos_explorados(conn, cfg):
    """Un `quick` sin pasada UDP no cierra puertos UDP conocidos."""
    did = _device(conn)
    riego = cfg.scan.risky_ports
    store.apply_scan_ports(conn, did,
                           [{"port": 1900, "protocol": "udp", "state": "open"}],
                           1000, riego, protocolos={"tcp", "udp"}, perfil="standard")
    sin_udp = store.apply_scan_ports(conn, did, [TOP_POR_DEFECTO], 2000, riego,
                                     protocolos={"tcp"}, perfil="quick")
    assert sin_udp["disappeared"] == []
    assert _estado(conn, did)[1900] == "open"
