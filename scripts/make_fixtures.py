#!/usr/bin/env python3
"""Genera los .pcap de fixture para el modo replay y para las pruebas manuales.

No requiere privilegios: sólo construye paquetes y los escribe a disco.

    python3 scripts/make_fixtures.py [destino]
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from batrade.config import load  # noqa: E402
from batrade.detect.scenarios import SCENARIO_NAMES, write_pcap  # noqa: E402


def main() -> int:
    dest = Path(sys.argv[1] if len(sys.argv) > 1 else "fixtures/pcaps")
    dest.mkdir(parents=True, exist_ok=True)
    cfg = load("config.yaml")
    for name in SCENARIO_NAMES:
        path = dest / f"{name}.pcap"
        write_pcap(name, str(path), cfg)
        print(f"  {name:<14} {path}  ({path.stat().st_size} bytes)")
    print(f"\n{len(SCENARIO_NAMES)} fixtures en {dest.resolve()}")
    print("Reproducir: python3 -m batrade sensor --mode replay --scenario arp_spoof")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
