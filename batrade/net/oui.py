"""Resolución de fabricante por OUI con base local, sin internet (RF-02).

Formatos soportados:
  - nmap:      ``000569 VMware``
  - arp-scan:  ``00:00:0C<TAB>Cisco Systems, Inc``
"""
from __future__ import annotations

from pathlib import Path

from batrade.net.iputil import normalize_mac, oui_prefix

CANDIDATE_FILES = (
    "/usr/share/nmap/nmap-mac-prefixes",
    "/usr/share/arp-scan/ieee-oui.txt",
    "/usr/share/wireshark/manuf",
)


class OuiDB:
    """Mapa prefijo(6 hex) -> fabricante. Se carga una sola vez por proceso."""

    def __init__(self, mapping: dict[str, str] | None = None, source: str | None = None):
        self._map = mapping or {}
        self.source = source

    def __len__(self) -> int:
        return len(self._map)

    def lookup(self, mac: str | None) -> str | None:
        prefix = oui_prefix(mac)
        if not prefix:
            return None
        vendor = self._map.get(prefix)
        if vendor:
            return vendor
        # Fallback: algunos registros son MA-M/MA-S (7 hex); probar 36 bits.
        return self._map.get(prefix[:6])

    @classmethod
    def load(cls, path: str | Path | None = None) -> "OuiDB":
        candidates = [Path(path)] if path else [Path(p) for p in CANDIDATE_FILES]
        for candidate in candidates:
            if not candidate.exists():
                continue
            try:
                mapping = _parse(candidate)
            except OSError:
                continue
            if mapping:
                return cls(mapping, str(candidate))
        return cls({}, None)

    @classmethod
    def empty(cls) -> "OuiDB":
        return cls({}, None)


def _parse(path: Path) -> dict[str, str]:
    mapping: dict[str, str] = {}
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not line or line.startswith("#"):
                continue
            line = line.rstrip("\n")
            if "\t" in line:
                prefix, _, vendor = line.partition("\t")
            elif " " in line:
                prefix, _, vendor = line.partition(" ")
            else:
                continue
            key = prefix.strip().replace(":", "").replace("-", "").upper()
            if len(key) < 6 or len(key) > 9:
                continue
            vendor = vendor.strip()
            if not vendor:
                continue
            base = key[:6]
            # El primer registro gana; los MA-M/MA-S añaden precisión y se
            # conservan aparte para no romper el lookup por OUI de 24 bits.
            if len(key) == 6:
                mapping.setdefault(base, vendor)
            else:
                mapping.setdefault(key, vendor)
    return mapping


def vendor_for(oui: OuiDB, mac: str | None) -> str | None:
    normalized = normalize_mac(mac)
    if not normalized:
        return None
    return oui.lookup(normalized)
