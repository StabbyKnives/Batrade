#!/usr/bin/env bash
# Batrade Home-SOC — instalación y verificación multi-distribución.
#
# Cubre el ecosistema Debian/Ubuntu/Kali/Parrot (apt), Fedora/RHEL/Rocky/Alma
# (dnf), Arch/BlackArch (pacman), openSUSE (zypper) y Alpine (apk).
#
# Opciones:
#   --install-deps  instala nmap, arp-scan e iproute2 con el gestor detectado
#   --venv          crea .venv e instala ahí las dependencias Python
#   --systemd       instala las unidades de systemd (requiere root)
#   --link          enlaza `batrade` en ~/.local/bin (o /usr/local/bin)
#
# No hace nada destructivo: comprueba, informa e inicializa la base de datos.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${PYTHON:-python3}"
INSTALL_DEPS=0
USE_VENV=0
INSTALL_SYSTEMD=0
LINK_BIN=0

for arg in "$@"; do
  case "$arg" in
    --install-deps) INSTALL_DEPS=1 ;;
    --venv) USE_VENV=1 ;;
    --systemd) INSTALL_SYSTEMD=1 ;;
    --link) LINK_BIN=1 ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "opción desconocida: $arg" >&2; exit 2 ;;
  esac
done

echo "== Batrade · instalación =="
cd "$ROOT"

# --------------------------------------------------------------------------- #
# 1. Distribución y gestor de paquetes
# --------------------------------------------------------------------------- #
DISTRO="Linux"
DISTRO_IDS=""
if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  DISTRO="${PRETTY_NAME:-${NAME:-Linux}}"
  DISTRO_IDS="${ID:-}${ID_LIKE:+ $ID_LIKE}"
fi

# El gestor se decide por la distribución (ID/ID_LIKE) antes que por binarios
# sueltos: en Fedora puede existir `apt` instalado a mano y no ser el correcto.
PM=""
case " ${DISTRO_IDS} " in
  *" debian "*|*" ubuntu "*|*" kali "*|*" parrot "*|*" linuxmint "*|*" pop "*) PM=apt ;;
  *" fedora "*|*" rhel "*|*" centos "*|*" rocky "*|*" almalinux "*) PM=dnf ;;
  *" arch "*|*" archlinux "*|*" blackarch "*|*" manjaro "*) PM=pacman ;;
  *" opensuse "*|*" suse "*|*" sles "*) PM=zypper ;;
  *" alpine "*) PM=apk ;;
esac

pm_binary() {
  case "$1" in
    apt) echo apt-get ;; dnf) echo dnf ;; pacman) echo pacman ;;
    zypper) echo zypper ;; apk) echo apk ;; *) echo "" ;;
  esac
}

if [[ -z "$PM" || -z "$(command -v "$(pm_binary "$PM")" 2>/dev/null || true)" ]]; then
  PM=""
  for candidate in apt dnf pacman zypper apk; do
    if command -v "$(pm_binary "$candidate")" >/dev/null 2>&1; then
      PM="$candidate"
      break
    fi
  done
fi

case "$PM" in
  apt)
    PKGS="nmap arp-scan iproute2 python3 python3-venv python3-yaml python3-flask python3-requests python3-defusedxml python3-scapy"
    INSTALL_CMD=(apt-get install -y) ;;
  dnf)
    PKGS="nmap arp-scan iproute python3 python3-pyyaml python3-flask python3-requests python3-defusedxml python3-scapy"
    INSTALL_CMD=(dnf install -y) ;;
  pacman)
    PKGS="nmap arp-scan iproute2 python python-pyyaml python-flask python-requests python-defusedxml python-scapy"
    INSTALL_CMD=(pacman -S --needed --noconfirm) ;;
  zypper)
    PKGS="nmap arp-scan iproute2 python3 python3-PyYAML python3-Flask python3-requests python3-defusedxml python3-scapy"
    INSTALL_CMD=(zypper --non-interactive install) ;;
  apk)
    PKGS="nmap arp-scan iproute2 python3 py3-yaml py3-flask py3-requests py3-defusedxml py3-scapy"
    INSTALL_CMD=(apk add) ;;
  *)
    PKGS="" ;;
esac

echo "  distro      : $DISTRO"
echo "  gestor      : ${PM:-no detectado}"

run_root() {
  if [[ $EUID -eq 0 ]]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    echo "ERROR: se necesita root o sudo para: $*" >&2
    return 1
  fi
}

# --------------------------------------------------------------------------- #
# 2. Dependencias de sistema (nmap, arp-scan, iproute2)
# --------------------------------------------------------------------------- #
missing=()
for bin in nmap arp-scan ip; do
  command -v "$bin" >/dev/null 2>&1 || missing+=("$bin")
done
if ((${#missing[@]})); then
  echo "  faltan      : ${missing[*]}"
  if [[ -n "$PKGS" ]]; then
    echo "  instalar con: sudo ${INSTALL_CMD[*]} $PKGS"
    if ((INSTALL_DEPS)); then
      echo "  instalando dependencias de sistema..."
      # $PKGS se expande sin comillas a propósito: son paquetes separados.
      if ! run_root "${INSTALL_CMD[@]}" $PKGS; then
        echo "  aviso       : la instalación automática falló; instala nmap, arp-scan" >&2
        echo "                e iproute2 a mano y usa --venv para las dependencias Python" >&2
      fi
    else
      echo "  (usa --install-deps para instalarlas automáticamente)"
    fi
  else
    echo "  instala nmap, arp-scan e iproute2 con el gestor de tu distribución"
  fi
else
  echo "  herramientas: nmap, arp-scan e iproute2 presentes"
fi

# --------------------------------------------------------------------------- #
# 3. Python: versión, venv opcional y módulos
# --------------------------------------------------------------------------- #
if ! "$PY" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
  echo "ERROR: se requiere Python 3.11 o superior (detectado: $("$PY" -V 2>&1))" >&2
  exit 1
fi
PY_BIN="$(command -v "$PY")"
echo "  python      : $("$PY" -V)"

if ((USE_VENV)); then
  if [[ ! -x "$ROOT/.venv/bin/python" ]]; then
    if ! "$PY" -m venv "$ROOT/.venv"; then
      echo "ERROR: no se pudo crear el venv; instala python3-venv (apt) o python3 (dnf)" >&2
      exit 3
    fi
  fi
  PY_BIN="$ROOT/.venv/bin/python"
  "$PY_BIN" -m pip install --quiet --upgrade pip >/dev/null 2>&1 || true
  if ! "$PY_BIN" -m pip install --quiet -e "$ROOT"; then
    echo "ERROR: pip no pudo instalar las dependencias del proyecto" >&2
    exit 3
  fi
  echo "  venv        : $ROOT/.venv"
fi

if ! "$PY_BIN" - <<'PY'
import importlib.util
import sys

need = {"yaml": "PyYAML", "flask": "Flask", "requests": "requests",
        "defusedxml": "defusedxml", "scapy": "scapy"}
missing = [pkg for mod, pkg in need.items()
           if importlib.util.find_spec(mod) is None]
if missing:
    print("  faltan módulos Python:", ", ".join(missing))
    sys.exit(3)
PY
then
  echo "  sugerencia  : bash install.sh --venv   (todo en .venv, sin tocar el sistema)"
  exit 3
fi
echo "  módulos     : completos"

# --------------------------------------------------------------------------- #
# 4. Directorios, .env y base de datos
# --------------------------------------------------------------------------- #
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

"$PY_BIN" -m batrade init
"$PY_BIN" -m batrade interfaces | sed 's/^/  /'
"$PY_BIN" -m batrade doctor | sed 's/^/  /'

# --------------------------------------------------------------------------- #
# 5. Unidades systemd (opcionales)
# --------------------------------------------------------------------------- #
if ((INSTALL_SYSTEMD)); then
  if [[ $EUID -ne 0 ]]; then
    echo "  systemd     : se necesita root para instalar las unidades" >&2
    exit 1
  fi
  if [[ "$ROOT" == /home/* ]]; then
    echo "  aviso       : ProtectHome=true impide leer $ROOT desde systemd;" >&2
    echo "                instala el proyecto en /opt/batrade para el servicio" >&2
  fi
  # Usuario de servicio sin shell (Debian/Kali, Fedora/RHEL, Arch, openSUSE).
  if ! id -u batrade >/dev/null 2>&1; then
    if command -v useradd >/dev/null 2>&1; then
      useradd -r -s /usr/sbin/nologin batrade
      echo "  usuario     : batrade creado (sin shell)"
    else
      echo "  aviso       : crea un usuario 'batrade' sin shell para el servicio" >&2
    fi
  fi
  chown -R batrade:batrade "$ROOT/var" 2>/dev/null || true
  sed -e "s|/opt/batrade|$ROOT|g" \
      -e "s|^ExecStart=.*batrade sensor.*|ExecStart=$PY_BIN -m batrade sensor --mode auto|" \
      deploy/batrade-sensor.service > /etc/systemd/system/batrade-sensor.service
  sed -e "s|/opt/batrade|$ROOT|g" \
      -e "s|^ExecStart=.*batrade dashboard.*|ExecStart=$PY_BIN -m batrade dashboard --host 127.0.0.1 --port 8000|" \
      deploy/batrade-dashboard.service > /etc/systemd/system/batrade-dashboard.service
  chmod 644 /etc/systemd/system/batrade-*.service
  systemctl daemon-reload
  echo "  systemd     : unidades instaladas (no habilitadas)"
  echo "                systemctl enable --now batrade-sensor batrade-dashboard"
else
  echo "  systemd     : omitido (usa --systemd para instalar las unidades)"
fi

# --------------------------------------------------------------------------- #
# 6. Comando `batrade` en el PATH (opcional)
# --------------------------------------------------------------------------- #
if ((LINK_BIN)); then
  SCRIPT="$ROOT/.venv/bin/batrade"
  if [[ ! -x "$SCRIPT" ]]; then
    echo "  enlace      : no existe .venv/bin/batrade; ejecuta --venv primero" >&2
  else
    if [[ $EUID -eq 0 ]]; then
      BIN_DIR="${BATRADE_BIN_DIR:-/usr/local/bin}"
    else
      BIN_DIR="${BATRADE_BIN_DIR:-$HOME/.local/bin}"
    fi
    mkdir -p "$BIN_DIR"
    ln -sfn "$SCRIPT" "$BIN_DIR/batrade"
    echo "  enlace      : $BIN_DIR/batrade -> $SCRIPT"
    case ":$PATH:" in
      *":$BIN_DIR:"*) ;;
      *) echo "  aviso       : añade $BIN_DIR al PATH para usar 'batrade'" >&2 ;;
    esac
  fi
fi

echo
echo "Listo. Siguiente paso:"
echo "  $PY_BIN -m batrade demo && $PY_BIN -m batrade dashboard   # ver el panel"
echo "  $PY_BIN -m batrade sensor --mode degraded                # arrancar el sensor"
echo "  $PY_BIN -m batrade interfaces                           # Ethernet/Wi-Fi detectadas"
