# Reporte de saneamiento — Batrade Home-SOC (v0.1.0 → v0.2.0, versión sin subir)

Rama: `chore/saneamiento-v0.2` · Base: `3675a39` · Fecha: 2026-11-22
Documento de referencia: `Batrade_CONTEXTO.md` (actualizado) y el código.

---

## 1. Resumen ejecutivo

Se cerró la deuda técnica de las siete fases: runner de migraciones versionadas con copia
previa, claves de escaneo que ahora se usan de verdad, pasada UDP real del catálogo,
distinción entre «no verificado» y «no verificable» en ARP, retención completa (cola de
notificación y XML), pool acotado de sondas ARP, CI en tres versiones de Python y pulido de
diagnóstico/documentación. La suite pasó de 134 a 201 tests en verde, sin red ni
privilegios, y el esquema evolucionó de v1 a v2 de forma aditiva y reversible mediante el
backup automático. No se tocaron los invariantes: sigue siendo solo detección, un único
escritor de SQLite y todo el SQL en `store.py`. Quedaron explícitamente pendientes la
licencia y la subida de versión a `0.2.0`, por decisión del propietario.

## 2. Estado inicial vs. final

| | Inicial | Final |
|---|---|---|
| Rama | `dev` | `chore/saneamiento-v0.2` |
| Tests | 134 passed | **201 passed** |
| Esquema | v1 (`PRAGMA user_version = 1`, sin runner) | **v2** con `MIGRATIONS` y copia `.bak-v1` |
| CI | inexistente | GitHub Actions 3.11 / 3.12 / 3.13 |
| `batrade doctor` | funciona, latido en epoch ms | funciona, schema v2 + latido legible |

Commits (uno por fase):

| Fase | Commit | Mensaje |
|---|---|---|
| 1 | `341a6a5` | Añadir runner de migraciones versionadas con copia de seguridad |
| 2 | `d1f3ba1` | Cablear las claves de escaneo que nunca se usaban |
| 3 | `2078059` | Escanear de verdad los puertos UDP del catálogo |
| 4 | `abe203b` | Distinguir no verificado de no verificable en la verificación ARP |
| 5 | `39db855` | Completar la retención: cola de notificación y XML de escaneos |
| 6 | `71d060e` | Acotar las sondas ARP y añadir integración continua |
| 7 | `3f9488f` | Pulir diagnóstico y documentación (código, tests y README; el reporte va en el commit de documentación posterior) |

Base: `3675a39` *Add network auto-detection and daemon lifecycle support*.

## 3. Tabla por fase

| Fase | Estado | Archivos modificados | Tests añadidos | Commit |
|---|---|---|---|---|
| 1 · Migraciones versionadas | completada | `batrade/db.py`, `batrade/cli.py`, `tests/test_migrations.py` | 9 | `341a6a5` |
| 2 · Claves de escaneo | completada | `batrade/config.py`, `batrade/net/nmap_scan.py`, `batrade/sensor.py`, `batrade/store.py`, `tests/test_scan_schedule.py`, `tests/test_scan_profiles.py` | 18 | `d1f3ba1` |
| 3 · UDP real | completada | `batrade/net/nmap_scan.py`, `batrade/sensor.py`, `batrade/store.py`, `batrade/dashboard/app.py`, `templates/health.html`, `fixtures/nmap/udp_scan.xml`, `tests/test_udp_scan.py` | 13 | `2078059` |
| 4 · Verificación ARP | completada | `batrade/net/verify.py`, `batrade/sensor.py`, `batrade/dashboard/app.py`, `templates/events.html`, `templates/device.html`, `static/style.css`, `tests/test_verification.py` | 11 | `abe203b` |
| 5 · Retención | completada | `batrade/store.py`, `batrade/sensor.py`, `tests/test_retention.py` | 7 | `39db855` |
| 6 · Despliegue y operación | completada (LICENSE omitida) | `batrade/sensor.py`, `install.sh`, `.github/workflows/tests.yml`, `tests/test_verify_pool.py` | 4 | `71d060e` |
| 7 · Pulido y documentación | completada | `batrade/cli.py`, `batrade/dashboard/app.py`, `batrade/detect/scenarios.py`, `README.md`, `tests/test_doctor.py`, `CONTEXT.md` (ignorado), `Batrade_CONTEXTO.md` (fuera del repo), este reporte | 5 | `3f9488f` + commit de documentación |

## 4. Detalle de cambios por fase

### Fase 1 — Runner de migraciones versionadas

`db.py` dejó de tener un `SCHEMA` monolítico que solo hacía `CREATE IF NOT EXISTS`. Ahora
hay `MIGRATIONS = [(1, SCHEMA_V1), (2, _migration_v2_notification_index)]` y
`SCHEMA_VERSION` se deriva de la última entrada. El runner lee `PRAGMA user_version`, aplica
solo las pendientes y ejecuta cada una en su propia transacción junto con el avance de
versión, de modo que un fallo hace `ROLLBACK` del esquema y de la versión a la vez. Como
`executescript` provoca un COMMIT implícito, los scripts se dividen en sentencias completas
con `sqlite3.complete_statement` y se ejecutan una a una. Antes de tocar una base existente
con datos se crea `<db>.bak-v<N>` con la API de backup de SQLite (incluye el WAL), permisos
600 y sin sobrescribir copias previas (`-2`, `-3`…). Una base nueva recibe todas las
migraciones y termina en v2; una base más nueva que el código se deja intacta con aviso.
`init` y `doctor` muestran la versión almacenada.

### Fase 2 — Configuración de escaneo

`profile_timeout(cfg, perfil)` sustituye al cálculo inline: `quick` usa `scan.quick_timeout`,
`standard` mantiene el tope histórico (`min(300, standard_timeout)`) y `vuln` sigue fijo en
900 s. `_schedule_scans` ya no usa la constante `QUICK_RESCAN_MS` (eliminada): lee
`quick_periodic_hours`, y añade la rama RF-10 para equipos `confiable` cuyo último escaneo
`standard` correcto —consultado con el nuevo `store.last_scan_ts`— supera
`weekly_rescan_days`. Esa rama se escalona: como máximo `max_concurrent` altas por barrido y
ordenadas de la más atrasada a la más reciente, descontando solo las que se encolaron de
verdad para que los duplicados no consuman presupuesto. `config.py` valida los tres valores
≥ 1. Los defaults (120 s, 24 h, 7 d) conservan el comportamiento previo.

### Fase 3 — Escaneo UDP

Con `CAP_NET_RAW`, tras el escaneo TCP se ejecuta una segunda invocación
`nmap -sU -Pn -p U:<catálogo> -T3 --host-timeout 30s --max-retries 1 -oX <xml> <target>`
(`build_udp_argv`). Se parsea con el mismo `parse_xml` (defusedxml, solo `state == "open"`) y
los puertos se marcan `protocolo = "udp"`; `apply_scan_ports` genera `port_risky` porque el
catálogo está indexado por `(protocolo, puerto)`. `ScanResult.protocols` registra qué se
exploró de verdad y el cierre de puertos lo respeta: sin raw, los UDP conocidos no pasan a
`closed`. La nota «UDP no verificable sin CAP_NET_RAW…» se registra a nivel `info` una vez por
escaneo y se muestra como banner en `/health`. El XML temporal de la pasada UDP se borra tras
volcar sus puertos para no quedar fuera de la retención. Un fallo UDP no invalida el
resultado TCP.

### Fase 4 — Verificación ARP

`detalle_json.verificacion` distingue ahora tres formas: texto plano (formato histórico,
cuando la sonda confirmó o descartó), y bloque `{"estado": ..., "motivo": ...}` con
`no_verificable` o `sin_respuesta`. Sin `CAP_NET_RAW` el evento se persiste con
`no_verificable` y su motivo; si la sonda se ejecutó y no hubo respuesta, `sin_respuesta`.
`verified` conserva su significado y la alerta se encola igual (C2). El panel añade un filtro
Jinja `verif` que traduce el bloque a etiqueta (`no verificable`, `sin respuesta`) en
`/events` y en el detalle del equipo, sin inventar estado cuando no hay bloque.

### Fase 5 — Retención completa

`store.purge` devuelve ahora también `notifications` y `scan_xml`, y borra las filas de
`notification_queue` en estado `enviado`/`agotado` —nunca `pendiente`— antes que los eventos
para que el contador sea informativo pese al `ON DELETE CASCADE`. El sensor
(`Sensor._purge_retention`) elimina los XML asociados con `safe_unlink_scan`, que resuelve la
ruta real, exige extensión `.xml`, comprueba contención en `paths.scans_dir` y tolera
archivos inexistentes; una ruta manipulada o un symlink que escapa se ignora y se registra.

### Fase 6 — Despliegue y operación

Las verificaciones ARP pasan por un pool fijo de 4 hilos (`VERIFY_WORKERS`) con cola acotada
(`VERIFY_QUEUE_MAX = 64`), creado una sola vez y registrado en `_threads` para que `stop` lo
cierre; si la cola se llena, el evento ya está guardado y solo se pierde la comprobación. El
instalador avisa con claridad de que `ProtectHome=true` impide ejecutar desde `/home` y
sugiere `/opt/batrade` o `batrade start/stop` (las unidades no se relajaron). CI ejecuta
`pytest` en 3.11, 3.12 y 3.13 tras `pip install -e ".[dev]"`.

### Fase 7 — Pulido y documentación

`Config` pasa a `TYPE_CHECKING` en `dashboard/app.py` (la anotación sigue siendo válida por
`from __future__ import annotations`), se elimina la variable `net` sin uso de
`scenarios._arp_sweep` y `doctor` imprime el latido como `YYYY-MM-DD HH:MM:SS (hace N s)` con
aviso cuando supera `heartbeat_interval × 3`. README actualizado (escaneo y UDP, retención,
migraciones, layout, CI, despliegue desde `/home`). `CONTEXT.md` —ignorado por git— lleva
cabecera que lo declara histórico y enumera sus desfases, con la corrección `meta` →
`heartbeat`. `Batrade_CONTEXTO.md` se actualizó en su ubicación original (fuera del repo;
ver §7).

## 5. Cambios de comportamiento o de configuración

| Cambio | Default | ¿Rompe compatibilidad? |
|---|---|---|
| Esquema v2: índice `idx_nq_estado_ts` | — | **No**. Aditivo; se aplica solo al arrancar cualquier comando, con copia `.bak-v1` previa |
| `scan.quick_timeout` pasa a ser el límite del perfil `quick` | 120 s | No (el default reproduce el valor fijo anterior) |
| `scan.quick_periodic_hours` sustituye a la constante de 24 h | 24 h | No con el valor por defecto; si alguien lo había cambiado «sin efecto», ahora sí manda |
| `scan.weekly_rescan_days` provoca reescaneo `standard` de equipos `confiable` | 7 d | **No rompe**, pero es comportamiento nuevo: en una instalación existente con equipos confiables habrá escaneos `standard` periódicos (escalonados a `max_concurrent` por barrido) |
| Pasada UDP `-sU` del catálogo | activa solo con `CAP_NET_RAW` | No. Sin raw el comportamiento es el de antes más la nota en `/health` |
| Cierre de puertos limitado a protocolos explorados | — | No. Evita marcar como `closed` puertos UDP no escaneados |
| `detalle_json.verificacion` puede ser bloque `{estado, motivo}` | — | No para panel ni BD. **Sí para un consumidor externo** que asumiera que `verificacion` es siempre una cadena: debe aceptar también el objeto |
| Retención purga `notification_queue` (`enviado`/`agotado`) y XML de escaneos | 90 d | No altera datos vigentes, pero **borra archivos que antes se acumulaban** |
| Pool de 4 sondas ARP simultáneas | 4 | No; si se satura, el evento queda sin verificar y se registra |
| `doctor`: latido legible | — | Solo cosmético (cambia el formato de una línea) |
| CI y aviso de instalación | — | No afecta a la ejecución |

No hay variables de entorno nuevas ni cambios en `.env.example`. Ninguna clave nueva en
`config.yaml`: las tres existentes pasan a tener efecto.

## 6. Cómo verificar

```bash
cd /home/techxicn_/code/Batrade
git log --oneline 3675a39..chore/saneamiento-v0.2

# 1. Suite completa (offline, sin privilegios)
.venv/bin/python -m pytest -p no:cacheprovider          # 201 passed

# 2. Diagnóstico y versión de esquema
.venv/bin/python -m batrade doctor                      # "schema v2", latido legible

# 3. Error de configuración legible y código 2
.venv/bin/python -m batrade --root /tmp/x --config /tmp/x/config.yaml doctor; echo $?

# 4. init sobre una COPIA de una base v1 (nunca sobre var/batrade.db)
#    genera una v1 sintética con db.SCHEMA_V1, guárdala en un directorio temporal,
#    apunta paths.db a ella y ejecuta:
.venv/bin/python -m batrade --root <tmp> --config <tmp>/config.yaml init
#    -> "schema v2", datos intactos, y <tmp>/var/*.db.bak-v1 con permisos 600

# 5. Modo degraded, replay y simulación
.venv/bin/python -m batrade sensor --mode degraded --duration 5
.venv/bin/python -m batrade sensor --mode replay --pcap fixtures/pcaps/mixed.pcap --duration 5
.venv/bin/python -m batrade sensor --mode simulate --scenario mixed --duration 5

# 6. Panel
.venv/bin/python -m batrade dashboard        # /health debe mostrar "Cobertura UDP incompleta"
curl -s http://127.0.0.1:8000/health | grep -o "UDP no verificable sin CAP_NET_RAW"
curl -s http://127.0.0.1:8000/events | grep -o "no verificable"
```

Verificado durante el saneamiento: 201 tests, `doctor` con schema v2, `init` sobre una v1
sintética con migración y backup 600, `degraded` (sin raw, barrido por `ip neigh`), `replay`
del fixture `mixed.pcap`, `simulate --scenario mixed` (202 observaciones), `/health` y
`/events` con el banner y las etiquetas nuevas, y `ConfigError` con código de salida 2.

## 7. Decisiones pendientes

1. **LICENSE — omitida por indicación expresa.** No se ha elegido licencia ni creado el
   archivo; el README sigue remitiendo a él. Recomendación: MIT si el objetivo es que otros
   lo reutilicen, o «source-available» (sin licencia permisiva) si no se quiere permitir
   redistribución; decidirlo antes de publicar el repositorio.
2. **Subida de versión a `0.2.0` — no aplicada.** `batrade/__init__.py` y `pyproject.toml`
   siguen en `0.1.0`. Recomendación: subirla en un commit propio (`Subir versión a 0.2.0`)
   junto con una nota de cambios, ya que el saneamiento está completo y probado.
3. **`Batrade_CONTEXTO.md` vive fuera del repositorio** (`~/Escritorio`). Se actualizó allí
   para no versionar un documento que describe la red del operador. Recomendación: mantenerlo
   fuera de git o moverlo a `docs/` con las direcciones anonimizadas.
4. **Ubicación del reporte.** El repo no tenía `docs/`, así que se guardó en la raíz. Si se
   crea `docs/`, moverlo allí.
5. **Escalonado semanal por `max_concurrent`.** Se eligió ese presupuesto para no lanzar
   ráfagas; con muchas decenas de equipos, el primer reescaneo completo puede tardar varios
   barridos. Recomendación: mantenerlo y, si molesta, exponer un presupuesto propio en
   `scan` en una fase posterior.
6. **El XML de la pasada UDP se descarta** tras volcar sus puertos (la fila de `scans` admite
   un solo XML). Recomendación: mantenerlo; si se quiere conservar como evidencia, haría
   falta una columna o una tabla nueva y una migración v3.

## 8. Riesgos y deuda restante

- **UDP solo es verificable con `CAP_NET_RAW`.** En modo degradado no hay pasada UDP; la
  limitación se anuncia en `/health`, pero la cobertura real sigue dependiendo de privilegios.
- **Un `quick` solo explora 100 puertos TCP** (`-F`): un puerto descubierto por `standard`
  fuera de esa lista pasa a `closed` en el siguiente `quick`. Es comportamiento histórico,
  no se cambió para no alterar el contrato del diff.
- **Un solo sensor por base de datos** y **un solo interfaz IPv4**; sin IPv6 ni multiusuario.
- **`approve_baseline` sigue excluyendo MAC aleatorias** por diseño (C7).
- **Wi-Fi en modo managed** limita la captura pasiva por física, no por código.
- **Sin `LICENSE`** y con la versión sin subir: el paquete tal cual se distribuye no declara
  términos de uso.
- **`Batrade_CONTEXTO.md` no está versionado**: puede volver a desincronizarse sin aviso.

## 9. Confirmación de invariantes

1. **Solo detección:** ninguna ruta bloquea, inyecta ni remedia; el escaneo UDP y las sondas
   ARP solo leen respuestas. ✔
2. **Timestamps en milisegundos UTC:** todo lo nuevo (`purge`, `last_scan_ts`, estados de
   verificación) usa `now_ms()` o la columna `ts` existente; no se introdujo `datetime.now()`
   para persistir (`notify._ts_str` y `doctor` solo formatean). ✔
3. **Todo el SQL en `store.py`:** las únicas sentencias nuevas están en `store.last_scan_ts`,
   `store.purge` y el `apply_scan_ports` ampliado; `db.py` solo añade el runner y su
   `PRAGMA user_version`. ✔
4. **Reglas puras:** `detect/rules.py` no se tocó; el motor sigue sin I/O ni escritura. ✔
5. **Escrituras del dashboard:** solo `devices.alias/estado_confianza`, `scan_requests` y
   `events.disposicion`; los cambios de panel son de lectura y presentación. ✔
6. **Un único escritor:** el sensor sigue siendo el único que escribe eventos, puertos, cola
   y ahora también borra archivos; cada hilo abre su conexión (pool incluido). ✔
7. **Estado en memoria acotado:** las colas nuevas tienen tope (`VERIFY_QUEUE_MAX`) y los
   estados de reglas no cambiaron. ✔
8. **Sin `shell=True`; objetivo validado; XML con `defusedxml`:** la pasada UDP reutiliza
   `build_udp_argv` con `ip_in_cidr` y `parse_xml`. ✔
9. **Secretos solo en `.env`, por nombre de variable:** no se añadieron secretos ni variables;
   `.env.example` no cambió. ✔
10. **Degradar, no morir:** sin privilegios el sensor arranca en `degraded`, omite UDP y
    marca la verificación como `no_verificable`; los fallos de la pasada UDP no invalidan el
    escaneo TCP. ✔
11. **Migraciones aditivas:** v2 solo crea un índice; el runner nunca borra ni altera
    columnas y hace copia antes de tocar datos. ✔
12. **Idioma:** dominio en español, infraestructura en inglés; comentarios, mensajes, commits
    y este reporte en español. ✔
13. **Tests offline, sin red y deterministas:** los nuevos usan bases temporales, fixtures
    sintéticos y `probe_binding`/`subprocess.run` sustituidos; ninguno abre sockets ni sale a
    la red. ✔
