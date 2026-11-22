# Reporte de instalación de sistema, reset y pruebas en VM

Rama: `chore/vm-install-reset` (parte de `chore/saneamiento-v0.2` @ `35efdc3`)
Base del proyecto: `3675a39` · Fecha: 2026-11-22
Referencias: `Batrade_CONTEXTO.md` (actualizado) y el código.

---

## 1. Resumen ejecutivo

Se cerraron los dos riesgos detectados en la revisión: `quick` ya no cierra puertos que no
explora (sólo `standard`/`vuln` lo hacen) y la pasada UDP usa `-sV --version-light` con
`scan.udp_timeout` configurable, que es lo que convierte `open|filtered` en `open` cuando el
servicio responde. Se añadió una instalación de sistema reproducible
(`install.sh --system`, `/opt/batrade` + wrapper en `/usr/local/bin`, `--dry-run`,
`--uninstall`/`--purge`) y el comando `batrade reset-db`, que exige root y sensor detenido,
pide confirmación escrita y hace copia previa. El CLI resuelve la raíz con
`--root` > `BATRADE_ROOT` > paquete instalado, así que funciona desde cualquier directorio, y
se niega a arrancar si el servicio systemd está activo. La suite pasó de 201 a **273 tests
en verde**, el contexto y el README quedaron sincronizados, y todo se probó con prefijos y
bases temporales: nada se instaló en `/opt`, `/usr/local` ni `/etc`, y `var/batrade.db` no se
tocó. Quedan pendientes la validación UDP real en la VM y las decisiones de licencia y versión.

## 2. Estado inicial vs. final

| | Inicial | Final |
|---|---|---|
| Rama | `chore/saneamiento-v0.2` (`35efdc3`) | `chore/vm-install-reset` |
| Tests | 201 passed | **273 passed, 2 skipped** (`shellcheck` no instalado) |
| Esquema | v2 (sin cambios) | v2 (sin cambios: no se añadió ninguna migración) |
| CLI | dependía del directorio actual | `--root` > `BATRADE_ROOT` > paquete |
| Instalación | sólo desde el repo | `install.sh --system` + `--uninstall` |
| Limpieza de datos | manual, borrando el archivo | `batrade reset-db` con guardas |

Commits de esta iteración (uno por fase):

| Fase | Commit | Mensaje |
|---|---|---|
| 1 | `1b7385a` | Cerrar puertos solo desde perfiles que cubren el rango |
| 2 | `5619ed0` | Hacer efectiva la pasada UDP con detección de versión |
| 3 | `198391c` | Instalar Batrade a nivel de sistema con un solo comando |
| 4 | `bf181bf` | Impedir dos sensores y mostrar usuario y modo reales |
| 5 | `5adf27e` | Añadir reset-db para limpiar la base con privilegios |
| 6 | `38feb43` | Guiar la prueba real en VM y avisar en doctor |
| 7 | `b8fc674` | Sincronizar el contexto y validar los metadatos del proyecto |

El commit `35efdc3` (*ignore a context file*, previo a esta iteración) añadió
`CONTEXT.md` y `REPORTE_SANEAMIENTO.md` a `.gitignore`.

## 3. Tabla por fase

| Fase | Estado | Archivos modificados | Tests añadidos | Commit |
|---|---|---|---|---|
| 1 · Cierre por perfil | completada | `batrade/store.py`, `batrade/sensor.py`, `README.md`, `tests/test_port_close_policy.py` | 7 | `1b7385a` |
| 2 · Eficacia UDP | completada | `batrade/net/nmap_scan.py`, `batrade/config.py`, `config.yaml`, `tests/conftest.py`, `tests/test_udp_scan.py`, `tests/test_scan_profiles.py`, `fixtures/nmap/udp_scan_versioned.xml`, `README.md` | 6 | `5619ed0` |
| 3 · Instalación de sistema | completada | `install.sh`, `scripts/sync_tree.sh`, `batrade/cli.py`, `.env.example`, `README.md`, `tests/test_install_system.py` | 18 (+2 omitidos) | `198391c` |
| 4 · CLI/root/systemd | completada | `batrade/daemon.py`, `batrade/cli.py`, `tests/test_daemon.py`, `tests/test_runtime_guards.py`, `README.md` | 13 | `bf181bf` |
| 5 · `reset-db` | completada | `batrade/store.py`, `batrade/db.py`, `batrade/cli.py`, `README.md`, `Batrade_CONTEXTO.md`, `tests/test_reset_db.py` | 20 | `5adf27e` |
| 6 · Guía VM y diagnóstico | completada | `batrade/cli.py`, `README.md`, `tests/test_doctor.py` | 4 | `38feb43` |
| 7 · Documentación y consistencia | completada | `Batrade_CONTEXTO.md`, `tests/test_project_metadata.py` | 4 | `b8fc674` |

## 4. Detalle de cambios por fase

### Fase 1 — Cierre de puertos sólo desde perfiles que cubren el rango

`store.apply_scan_ports` acepta `perfil`. El cierre de puertos se ejecuta únicamente para
`standard` y `vuln`; `quick` sólo inserta y actualiza. Sin `perfil` (llamadores internos y
tests de diff) se conserva el comportamiento histórico de cerrar, para no romper el contrato.
Además, un puerto que estaba `closed` y vuelve a aparecer cuenta como novedad: genera
`port_new` y, si está en el catálogo, `port_risky`.

Al reproducir el ciclo con el código anterior apareció un matiz que el enunciado suponía
distinto: el evento `port_new` **no** se repetía, porque la fila del puerto sobrevive como
`closed` y la condición era `prev is None`. El fallo real medido era el parpadeo de estado
(el panel mostraba `closed` un servicio abierto). Se corrigió igualmente la política y se
añadió la reapertura como señal, que es lo que pedía la especificación. Documentado en
README y en §15 del contexto, junto a la contrapartida: un cierre real puede tardar hasta el
siguiente `standard` (semanal por defecto).

### Fase 2 — Eficacia real de la pasada UDP

`build_udp_argv` incluye ahora `-sV --version-light` (la sonda de servicio es la que hace que
SSDP/mDNS pasen de `open|filtered` a `open`), toma `--host-timeout` de `scan.udp_timeout`
(60 s por defecto, validado ≥ 5) y el proceso recibe ese valor + 30 s
(`udp_timeouts(cfg)`), de modo que nmap siempre tiene margen para escribir el XML.
`open|filtered` sigue sin generar evento. Fixture nuevo `udp_scan_versioned.xml` con un mDNS
`open` obtenido por detección de versión (producto y versión guardados) y un SSDP
`open|filtered` que no debe aparecer. README con la verificación manual (VM, `CAP_NET_RAW`,
dispositivo con SSDP/mDNS, resultado esperado en `/events`).

### Fase 3 — Instalación de sistema

`install.sh` pasa a tener tres modos (repositorio, `--system`, `--uninstall`) con
`--prefix`, `--start`, `--dry-run`, `--purge` y `--yes`, manteniendo intactos `--venv`,
`--link` y `--systemd`. La copia la hace `scripts/sync_tree.sh`, que excluye `.git`, `var/`,
`.venv`, `.env`, `__pycache__`, `*.egg-info` y bases; usa `rsync --delete` con esas
exclusiones (o `tar` si no hay rsync) y copia `config.yaml` sólo si el destino no tiene uno.
El instalador exige root (con `BATRADE_TEST_FAKE_ROOT=1` reservado a las pruebas), crea el
venv en el prefix, instala editable, genera `.env` (600) si falta, ejecuta `init`,
`interfaces` y `doctor`, y escribe un wrapper que fija `BATRADE_ROOT`.

`cli.py` gana `package_root()` y `resolve_root()`; `--root` manda, luego `BATRADE_ROOT`, luego
el directorio del paquete. `_config_file` usa la misma función, así que `start` lanza hijos con
una ruta absoluta coherente. `BATRADE_ROOT` se documenta por nombre en `.env.example`.

### Fase 4 — Convivencia CLI/root/systemd

`daemon.systemd_unit_active()` consulta `systemctl is-active --quiet` sin `shell=True` y
tolera su ausencia; `ensure_no_systemd()` se ejecuta al principio de `start_component`, de modo
que `start` y `restart` se niegan con un mensaje que ofrece `systemctl restart|stop`. `status`
y `doctor` muestran el usuario efectivo (`whoami()`), el modo real y la pista de `sudo` cuando
falta `CAP_NET_RAW`. `doctor` avisa si root trabaja sobre un `var/` de otro usuario; **no** se
hace `chown` automático (decisión pendiente razonada). Los tests de `start` existentes se
aislaron con `systemd_unit_active → False` para no invocar systemctl real.

### Fase 5 — `batrade reset-db`

`store.reset_all` y `store.reset_keep_devices` vacían las tablas en una única transacción
(orden hijo→padre por las claves foráneas), reinician `sqlite_sequence` si existe y dejan
`store.vacuum()` para después, fuera de transacción. `db.backup_tagged` generaliza la copia
`<db>.bak-<tag>` sin sobrescribir.

`cmd_reset_db` exige `geteuid() == 0`, se niega con el sensor vivo (PID del CLI o unidad
systemd activa), resume ruta, tamaño y filas, pide escribir `REINICIAR` (aborta sin TTY y sin
`--yes`), crea `<db>.bak-reset-<epoch_ms>` (600) salvo `--no-backup`, vacía los datos y
re-ejecuta la lógica de `init` (aprendizaje activo, sin línea base). Después borra los XML de
`paths.scans_dir` con `safe_unlink_scan` (contención de rutas, symlinks fuera ignorados) y
vacía `alerts.log` a 600; `--keep-logs` conserva ambos. `--keep-devices` limita el borrado a
eventos, puertos, escaneos, cola, solicitudes y `tool_status`. La operación se registra en
`var/log/batrade.log` con alcance, filas, copia y usuario (`SUDO_USER`), sin datos del
inventario. El comando no existe en el panel.

### Fase 6 — Guía de prueba en VM y diagnóstico

README con la sección «Real test on a VM»: requisitos, red en puente y modo promiscuo, aviso
de que NAT limita la visibilidad, instalación con
`sudo bash install.sh --system --install-deps --start`, comprobaciones (`status`, `doctor`,
`interfaces`, `/health`), flujo de línea base, `demo` + `reset-db`, verificación UDP manual y
desinstalación. `doctor` añade un bloque informativo «prueba en VM» con modo efectivo,
`CAP_NET_RAW`, si la interfaz parece de hipervisor (heurística por nombre y prefijo MAC de
VMware/VirtualBox/Hyper-V/QEMU) y la pista de `sudo`. No cambia el comportamiento del sensor.

### Fase 7 — Documentación y consistencia

- `Batrade_CONTEXTO.md` §5.1: la fila de `db.py` ya refleja `SCHEMA_VERSION` derivada de
  `MIGRATIONS` (v2), no `SCHEMA_VERSION = 1`.
- Recuento de commits corregido en la cabecera: **17 commits hasta `b8fc674` (14 de código y 3
  de documentación)**; el commit de este reporte es el 18. Antes decía «seis».
- Rama base aclarada: el trabajo parte de `dev`, que apunta al mismo commit que `main` y que
  `origin/main` (`3675a39`); el saneamiento anterior nunca se fusionó.
- `REPORTE_SANEAMIENTO.md`: se revisó el inicio del archivo y **no contiene** el texto
  residual `[text](REPORTE_SANEAMIENTO.md)`; el título está limpio. No hubo nada que borrar.
- `pyproject.toml` ya define el extra `dev` (`pytest>=8`) que usa el workflow; se añadió un
  test que fija el extra, las dependencias de ejecución y el YAML del CI (matriz 3.11/3.12/
  3.13, `pip install -e ".[dev]"`, `pytest`).
- Contexto actualizado además en §10 (el panel no reinicia la base), §11 (`udp_timeout`), §12
  (`BATRADE_ROOT`), §15 (UDP con `-sV`, política de cierre), §16.1 (`--system`/`--uninstall`),
  §19 (deuda viva), §22 (`*.bak-reset-*`), Anexos A y B.

## 5. Cambios de comportamiento o de configuración

| Cambio | Default | ¿Rompe compatibilidad? |
|---|---|---|
| `scan.udp_timeout` (nueva) | 60 s (mín. 5) | **No**: clave nueva con default; el proceso UDP pasa de 90 s fijos a `valor + 30` |
| Pasada UDP con `-sV --version-light` | activa con `CAP_NET_RAW` | **No** en API; cambia lo observable: más puertos UDP pasan a `open` (y generan `port_risky`) y cada escaneo UDP tarda más |
| `quick` ya no cierra puertos | — | **No** rompe contratos, pero cambia el panel: un puerto fuera del top 100 deja de figurar `closed` tras un `quick`; el cierre real llega con el siguiente `standard` |
| Un puerto que reaparece tras cierre real genera `port_new`/`port_risky` | — | Sí en cuanto a eventos: pueden aparecer avisos nuevos cuando un servicio vuelve. Es la señal que pedía la especificación |
| `BATRADE_ROOT` (nueva variable de entorno) | vacío | **No**; se documenta sólo por nombre en `.env.example` |
| Raíz por defecto = paquete instalado (antes: directorio actual) | — | **Sí, para usos raros**: quien lanzara `batrade` desde otro directorio esperando el `config.yaml` local debe usar `--root` o `BATRADE_ROOT`. Desde el repo el resultado es idéntico |
| `install.sh --system`, `--prefix`, `--start`, `--dry-run`, `--uninstall`, `--purge`, `--yes` | — | **No**: el flujo sin opciones y `--venv`/`--link`/`--systemd` se mantienen |
| `batrade start`/`restart` se niegan si la unidad systemd está activa | — | **No** rompe nada seguro: antes se podían crear dos sensores. Un script que arrancase ambos caminos ahora recibe un error explícito |
| `status` y `doctor` añaden líneas (usuario, modo, pista, bloque VM) | — | **No** funcional; sí para un parser que cuente líneas exactas |
| `batrade reset-db` (nuevo) | — | **No**: comando nuevo, sólo CLI, sólo root |
| `.env.example` añade `BATRADE_ROOT` | — | **No** |

Sin migraciones nuevas: el esquema sigue en v2 y las bases existentes no se tocan.

## 6. Cómo verificar

### Ya verificado por el agente (en esta máquina, sin privilegios)

```bash
cd /home/techxicn_/code/Batrade

# Suite completa
.venv/bin/python -m pytest -p no:cacheprovider        # 273 passed, 2 skipped

# Diagnóstico y configuración (código 2 legible)
.venv/bin/python -m batrade doctor
.venv/bin/python -m batrade --root /tmp --config /tmp/no-existe.yaml doctor; echo $?   # 2

# Instalador: plan completo sin tocar nada
TMP=$(mktemp -d)
BATRADE_TEST_FAKE_ROOT=1 BATRADE_BIN_DIR=$TMP/bin \
  bash install.sh --system --dry-run --prefix $TMP/opt/batrade
find $TMP -maxdepth 2        # sólo el directorio temporal: no se creó el prefix

# Desinstalación sobre un prefijo temporal (conserva datos y configuración)
bash install.sh --uninstall --dry-run --prefix $TMP/opt/batrade

# Raíz desde un directorio ajeno
cd /tmp && /home/techxicn_/code/Batrade/.venv/bin/python -m batrade doctor | head -1

# reset-db sin root: se niega con código 1
.venv/bin/python -m batrade reset-db --yes; echo $?    # "ejecuta con sudo", 1
```

También se ejecutaron `sensor --mode degraded`, `--mode replay` con
`fixtures/pcaps/mixed.pcap` y `--mode simulate --scenario mixed` contra una copia temporal,
y `reset-db` completo (con backup 600, `--keep-devices`, `--keep-logs`, contención de rutas y
negativa con sensor vivo) mediante la suite, que simula root con `os.geteuid`.

### A verificar por el usuario en la VM

```bash
# 1. Instalación real (root, escribe en /opt y /usr/local/bin)
sudo bash install.sh --system --install-deps --start

# 2. Comprobaciones
batrade status
batrade doctor                 # debe decir "efectivo: live" y CAP_NET_RAW: sí
batrade interfaces
curl -s http://127.0.0.1:8000/health

# 3. Flujo de uso
#    revisar /devices → anotar alias y confianza → /learning → aprobar
sudo batrade approve-baseline

# 4. Demo y limpieza
batrade stop && batrade demo && batrade dashboard
sudo batrade reset-db --yes              # o --keep-devices

# 5. Verificación UDP manual (README, «Verifying UDP detection by hand»)
#    dispositivo con SSDP/mDNS → escaneo standard → port_risky 1900/udp o 5353/udp

# 6. Desinstalación
sudo bash install.sh --uninstall         # conserva var/, .env, config.yaml
```

**Validación real pendiente en VM**: la pasada UDP con `-sV` contra un dispositivo que
responda a SSDP/mDNS, y el ciclo completo de instalación/desinstalación con root real.

## 7. Decisiones pendientes

1. **LICENSE — sigue sin elegirse** (no se creó el archivo). Recomendación: MIT si quieres que
   otros lo reutilicen; sin licencia permisiva si no. Decidirlo antes de publicar.
2. **Versión `0.2.0` — no aplicada** (`0.1.0` en `__init__.py` y `pyproject.toml`).
   Recomendación: subirla en un commit propio cuando cierres la validación en VM.
3. **Propiedad de archivos en `var/` cuando el CLI corre como root sobre un `var/` de otro
   usuario.** Se eligió la opción conservadora: aviso en `doctor` y ninguna escritura de
   propiedad. Recomendación: mantenerlo; si molesta en la VM, ejecutar siempre con el mismo
   usuario (root sin systemd) o añadir un `chown` explícito documentado, nunca automático.
4. **`Batrade_CONTEXTO.md` está ahora versionado.** Se hizo así para que la documentación
   viaje con el repo, tras comprobar que no contiene MAC ni IP reales (sólo rutas locales,
   nombres de interfaz y direcciones de ejemplo). Recomendación: mantenerlo versionado y
   anonimizar cualquier salida real que se pegue en él.
5. **Respaldo sin `rsync`.** El fallback con `tar` no poda archivos obsoletos en una
   reinstalación. Recomendación: aceptar (el prefix se puede recrear) o exigir `rsync` en
   `--system` si quieres actualizaciones perfectamente limpias.
6. **`BATRADE_TEST_FAKE_ROOT`** existe únicamente para probar el instalador sin root.
   Recomendación: dejarlo documentado como tal y no usarlo en producción.

## 8. Riesgos y deuda restante

- **La verificación UDP real no se ha hecho**: en el laboratorio no hay `CAP_NET_RAW` ni un
  dispositivo que responda. El código y los fixtures están probados, pero la eficacia en una
  red real depende del dispositivo (un servicio que ignore las sondas seguirá `open|filtered`).
- **Cierres de puerto diferidos**: sin `quick` cerrando, un servicio apagado puede figurar
  `open` hasta el `standard` semanal.
- **Instalación de sistema probada con `--dry-run` y prefijos temporales**: el camino con root
  real (venv en `/opt`, wrapper en `/usr/local/bin`, `secure_path`) no se ha ejecutado aquí.
- **`reset-db` probado con root simulado**: la ruta real (`sudo`, `SUDO_USER`, permisos del
  `var/` del servicio) queda para la VM.
- **Propiedad de `var/`** sin resolver automáticamente (aviso en `doctor`).
- **Un solo sensor por base**: el CLI detecta la unidad systemd, pero dos CLI en máquinas
  distintas contra la misma base siguen siendo responsabilidad del operador.
- **Sin `LICENSE`** y con versión sin subir: el paquete no declara términos de uso.

## 9. Confirmación de invariantes

1. **Solo detección:** ningún cambio bloquea, inyecta ni remedia; el reset borra datos propios
   y las pasadas nuevas sólo leen respuestas. ✔
2. **Timestamps en ms UTC:** `reset-db` usa `now_ms()`/`store_now()` para la etiqueta de la
   copia; no se introdujo `datetime.now()` para persistir. ✔
3. **Todo el SQL en `store.py`:** `reset_all`, `reset_keep_devices`, `table_counts` y
   `vacuum` viven allí; `db.py` sólo añade `_write_backup`/`backup_tagged` (API de backup,
   sin SQL de datos). ✔
4. **Reglas puras:** `detect/rules.py` no se tocó; el motor sigue sin escribir. ✔
5. **Escrituras del dashboard:** intactas (alias/confianza, `scan_requests`,
   `events.disposicion`). El reset **no** se expone en el panel. ✔
6. **Un único escritor:** el sensor sigue siendo el único escritor en caliente; `reset-db` y
   `install --system` son acciones manuales del CLI y `reset-db` exige el sensor detenido. ✔
7. **Estado en memoria acotado:** no se añadió estado en memoria nuevo; el pool y las colas
   conservan sus topes. ✔
8. **Sin `shell=True`; objetivo validado; XML con `defusedxml`:** `systemctl` y nmap se
   invocan con listas de argumentos; `build_udp_argv` valida contra el CIDR; el parseo sigue
   con `defusedxml`. ✔
9. **Secretos sólo en `.env`, por nombre:** no se añadieron secretos; sólo se documenta
   `BATRADE_ROOT`. ✔
10. **Degradar, no morir:** sin privilegios el sensor arranca en `degraded`, omite UDP y el
    CLI sólo avisa (no falla) por la falta de `CAP_NET_RAW`. ✔
11. **Migraciones aditivas; reset manual:** no hay migración nueva (esquema v2 intacto) y el
    reset es explícito, con confirmación, nunca automático. ✔
12. **Idioma:** dominio en español, infraestructura en inglés; comentarios, mensajes, commits
    y este reporte en español. ✔
13. **Tests offline, sin red y deterministas:** instalador con `--dry-run`/prefijos
    temporales y `BATRADE_TEST_FAKE_ROOT`, `reset-db` con `os.geteuid` simulado, systemd y
    `subprocess` sustituidos; ningún test llama a `systemctl`, `chown` ni abre red. ✔
