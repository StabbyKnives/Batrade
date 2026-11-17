"""Resolución de fabricante por OUI con base local, sin internet (RF-02).

Formatos soportados:
  - nmap:      ``000569 VMware``
  - arp-scan:  ``00:00:0C<TAB>Cisco Systems, Inc``
"""
from __future__ import annotations

from pathlib import Path

from batrade.net.iputil import normalize_mac, oui_prefix

CANDIDATE_FILES = (
    "/usr/share/nmap/nmap-mac-prefixes",          # Debian, Ubuntu, Kali, Parrot,
                                                  # Fedora, Arch, openSUSE
    "/usr/share/arp-scan/ieee-oui.txt",           # arp-scan en todas las distros
    "/usr/share/ieee-data/oui.txt",               # Debian/Ubuntu (paquete ieee-data)
    "/usr/share/wireshark/manuf",                 # Wireshark/TShark
    "/usr/share/nmap-mac-prefixes",               # instalaciones desde fuente
    "/usr/local/share/nmap/nmap-mac-prefixes",    # nmap compilado
    "/opt/homebrew/share/nmap/nmap-mac-prefixes", # Linuxbrew/Homebrew en Linux
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
        """Carga la primera base OUI utilizable.

        La ruta configurada es una preferencia, no un requisito: si no existe
        (por ejemplo nmap instalado por snap o una distro sin ese fichero) se
        prueban las ubicaciones habituales de Debian/Kali, Fedora, Arch y
        openSUSE. Sin base OUI el sensor sigue funcionando, sólo pierde el
        nombre del fabricante.
        """
        candidates: list[Path] = []
        if path:
            candidates.append(Path(path))
        for fallback in CANDIDATE_FILES:
            if Path(fallback) not in candidates:
                candidates.append(Path(fallback))
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
            # ieee-data/oui.txt usa "00-00-0C   (hex)   Cisco Systems, Inc".
            if "(hex)" in vendor:
                vendor = vendor.split("(hex)", 1)[1].strip()
            if "(base 16)" in vendor:
                vendor = vendor.split("(base 16)", 1)[1].strip()
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
