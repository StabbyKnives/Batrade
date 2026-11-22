#!/usr/bin/env bash
# Sincroniza el árbol del repositorio a un prefijo de instalación.
#
#   bash scripts/sync_tree.sh ORIGEN DESTINO [--dry-run]
#
# Nunca copia `.git`, `var/`, `.venv` ni `.env`, y trata `config.yaml` aparte:
# si el destino ya tiene uno, se conserva (es configuración del operador). El
# resultado es idempotente: se puede repetir en cada actualización sin destruir
# los datos ni la configuración local.
set -euo pipefail

SRC="${1:-}"
DST="${2:-}"
DRY_RUN=0
if [[ "${3:-}" == "--dry-run" ]]; then
    DRY_RUN=1
fi

if [[ -z "$SRC" || -z "$DST" ]]; then
    echo "uso: $0 ORIGEN DESTINO [--dry-run]" >&2
    exit 2
fi
if [[ ! -d "$SRC" ]]; then
    echo "ERROR: el origen no existe: $SRC" >&2
    exit 2
fi
SRC="$(cd "$SRC" && pwd -P)"

say() { echo "  sync       : $*"; }

if ((DRY_RUN)); then
    say "[dry-run] copiaría $SRC -> $DST (sin .git, var/, .venv, .env)"
    [[ -d "$DST" ]] && say "[dry-run] conservaría lo existente en $DST (config.yaml, .env, var/)"
    exit 0
fi

mkdir -p "$DST"
DST="$(cd "$DST" && pwd -P)"
if [[ "$SRC" == "$DST" ]]; then
    echo "ERROR: origen y destino son el mismo directorio" >&2
    exit 2
fi
case "$DST/" in
    "$SRC"/*)
        echo "ERROR: el destino ($DST) está dentro del origen ($SRC)" >&2
        exit 2
        ;;
esac

# --delete limpia código viejo, pero rsync no borra las rutas excluidas: var/,
# .env, config.yaml y .venv sobreviven a una reinstalación.
if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete \
        --exclude '.git' --exclude 'var' --exclude '.venv' --exclude '.env' \
        --exclude 'config.yaml' --exclude '__pycache__' --exclude '.pytest_cache' \
        --exclude '*.egg-info' --exclude '*.pyc' --exclude '*.db' \
        --exclude '*.db-wal' --exclude '*.db-shm' \
        "$SRC"/ "$DST"/
else
    # Sin rsync: tar conserva permisos y enlaces; no poda archivos obsoletos.
    tar -C "$SRC" -cf - \
        --exclude=./.git --exclude=./var --exclude=./.venv --exclude=./.env \
        --exclude=./config.yaml --exclude='*/__pycache__' --exclude='./.pytest_cache' \
        --exclude='*.egg-info' --exclude='*.pyc' --exclude='*.db' \
        --exclude='*.db-wal' --exclude='*.db-shm' . | tar -C "$DST" -xf -
fi

# Primera instalación: el destino aún no tiene configuración, se copia la del
# repositorio. En las siguientes no se toca.
if [[ ! -f "$DST/config.yaml" ]]; then
    cp "$SRC/config.yaml" "$DST/config.yaml"
    say "config.yaml copiado (primera instalación)"
else
    say "config.yaml existente conservado"
fi

say "código sincronizado en $DST"
