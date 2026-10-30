#!/usr/bin/env bash
# Batrade Home-SOC — instalación y verificación en Kali Linux.
# No instala paquetes sin avisar: comprueba, informa y deja el sistema listo.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${PYTHON:-python3}"
INSTALL_SYSTEMD=0

for arg in "$@"; do
  case "$arg" in
    --systemd) INSTALL_SYSTEMD=1 ;;
    -h|--help) sed -n '2,6p' "$0"; exit 0 ;;
  esac
done

echo "== Batrade · instalación =="
cd "$ROOT"

# 1. Python
if ! "$PY" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
  echo "ERROR: se requiere Python 3.11 o superior" >&2
  exit 1
fi
echo "  python      : $("$PY" -V)"

# 2. Dependencias de sistema (solo se comprueban)
missing=()
for bin in nmap arp-scan; do
  command -v "$bin" >/dev/null 2>&1 || missing+=("$bin")
done
if ((${#missing[@]})); then
  echo "  faltan      : ${missing[*]}"
  echo "  instalar con: sudo apt install -y ${missing[*]}"
else
  echo "  herramientas: nmap y arp-scan presentes"
fi

# 3. Dependencias de Python
"$PY" - <<'PY'
import importlib, sys
need = {"yaml": "python3-yaml", "flask": "python3-flask", "requests": "python3-requests",
        "defusedxml": "python3-defusedxml", "scapy": "python3-scapy"}
missing = [pkg for mod, pkg in need.items()
           if importlib.util.find_spec(mod) is None]
if missing:
    print("  faltan módulos Python:", ", ".join(missing))
    print("  instalar con: sudo apt install -y " + " ".join(missing))
    sys.exit(3)
print("  módulos Python: completos")
PY

# 4. Directorios, base de datos y configuración inicial
mkdir -p var/scans var/log
chmod 700 var/scans 2>/dev/null || true
if [[ ! -f .env ]]; then
  cp .env.example .env
  chmod 600 .env
  echo "  .env        : creado desde .env.example (permisos 600)"
else
  chmod 600 .env
  echo "  .env        : existente"
fi

# 5. Inicializar esquema y verificar capacidades
"$PY" -m batrade init
"$PY" -m batrade doctor | sed 's/^/  /'

# 6. Unidades systemd (opcionales)
if ((INSTALL_SYSTEMD)); then
  if [[ $EUID -ne 0 ]]; then
    echo "  systemd     : se necesita root para instalar unidades" >&2
    exit 1
  fi
  install -m 644 deploy/batrade-sensor.service /etc/systemd/system/
  install -m 644 deploy/batrade-dashboard.service /etc/systemd/system/
  systemctl daemon-reload
  echo "  systemd     : unidades instaladas (no habilitadas)"
  echo "                systemctl enable --now batrade-sensor batrade-dashboard"
else
  echo "  systemd     : omitido (usa --systemd para instalar las unidades)"
fi

echo
echo "Listo. Siguiente paso:"
echo "  python3 -m batrade demo && python3 -m batrade dashboard   # ver el panel"
echo "  python3 -m batrade sensor                            # arrancar el sensor"
