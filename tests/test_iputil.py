"""Utilidades de IP/MAC: la base de toda la normalización de datos."""
from __future__ import annotations

import pytest

from batrade.net.iputil import (default_gateway, interface_ipv4, ip_in_cidr,
                           is_locally_administered, is_multicast_mac,
                           normalize_mac, oui_prefix, valid_ipv4)


@pytest.mark.parametrize("raw,expected", [
    ("AA:BB:CC:00:11:22", "aa:bb:cc:00:11:22"),
    ("aa-bb-cc-00-11-22", "aa:bb:cc:00:11:22"),
    ("aabb.cc00.1122", "aa:bb:cc:00:11:22"),
    ("aabbcc001122", "aa:bb:cc:00:11:22"),
    ("  AA:BB:CC:00:11:22  ", "aa:bb:cc:00:11:22"),
])
def test_normalize_mac_variants(raw, expected):
    assert normalize_mac(raw) == expected


@pytest.mark.parametrize("bad", ["", None, "aa:bb:cc", "zz:zz:zz:zz:zz:zz",
                                 "aa:bb:cc:00:11:22:33"])
def test_normalize_mac_rejects(bad):
    assert normalize_mac(bad) is None


def test_locally_administered_bit():
    assert is_locally_administered("aa:bb:cc:00:11:22")     # 0xaa & 0x02
    assert is_locally_administered("02:42:ac:11:00:02")     # veth de Docker
    assert not is_locally_administered("00:50:56:c0:00:13")  # VMware
    assert not is_locally_administered(None)


def test_multicast_and_prefix():
    assert is_multicast_mac("01:00:5e:00:00:01")
    assert not is_multicast_mac("00:50:56:c0:00:13")
    assert oui_prefix("00:50:56:c0:00:13") == "005056"


def test_ip_validation_and_cidr():
    assert valid_ipv4(" 10.0.0.5 ") == "10.0.0.5"
    assert valid_ipv4("10.0.0.300") is None
    assert ip_in_cidr("10.10.10.5", "10.10.10.0/24")
    assert not ip_in_cidr("10.10.11.5", "10.10.10.0/24")
    assert not ip_in_cidr("no-es-ip", "10.10.10.0/24")
    assert not ip_in_cidr("10.10.10.5", "cidr-roto")


def test_host_helpers_do_not_crash():
    # No se asume una red concreta: sólo que devuelven algo plausible.
    assert default_gateway() is None or valid_ipv4(default_gateway()) is not None
    assert interface_ipv4("lo") is None or valid_ipv4(interface_ipv4("lo")) is not None
    assert interface_ipv4("iface-inexistente") is None
