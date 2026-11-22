# Batrade Home-SOC — Documento de contexto para un agente externo

> **Para qué sirve este documento.** Es el traspaso completo de contexto del proyecto
> Batrade: qué es, cómo está construido, cómo se ejecuta, qué contratos respeta y qué
> deuda técnica queda. Está escrito para que un agente de IA (o una persona) que
> **nunca ha visto el repositorio** pueda trabajar sobre él sin preguntar lo básico.
>
> **Qué NO contiene.** No contiene credenciales, tokens, webhooks, contraseñas ni
> direcciones MAC/IP de equipos reales del operador. Las variables de entorno se citan
> **solo por nombre**.

| Dato | Valor |
|---|---|
| Proyecto | Batrade Home-SOC (`batrade`), versión `0.1.0` (subida a `0.2.0` pendiente de aprobación) |
| Ruta local del repo | `/home/techxicn_/code/Batrade` |
| Rama de trabajo | `chore/saneamiento-v0.2` (6 commits de código sobre `dev`/`3675a39`) |
| Commit base | `3675a39` — *Add network auto-detection and daemon lifecycle support* |
| Estado del árbol | limpio (solo artefactos ignorados: `var/`, `.venv/`, `__pycache__/`) |
| Lenguaje | Python ≥ 3.11 (verificado con 3.14.10 en `.venv`; CI en 3.11/3.12/3.13) |
| Framework web | Flask ≥ 3.0 |
| Persistencia | SQLite en modo WAL (un solo archivo), esquema v2 con migraciones versionadas |
| Pruebas | 196+ tests en verde, sin red ni privilegios, con CI por matriz de Python |
| Host de referencia | Fedora Linux 44, GNOME/Wayland, interfaz Wi-Fi `wlp2s0` |
| Documento actualizado | 2026-11-22 (saneamiento v0.2) |

---

## Índice

1. [Resumen ejecutivo](#1-resumen-ejecutivo)
2. [Estado actual verificado](#2-estado-actual-verificado)
3. [Puesta en marcha en 5 minutos](#3-puesta-en-marcha-en-5-minutos)
4. [Arquitectura y flujo de datos](#4-arquitectura-y-flujo-de-datos)
5. [Mapa de módulos y contratos](#5-mapa-de-módulos-y-contratos)
6. [Modelo de datos](#6-modelo-de-datos)
7. [Catálogo de detecciones](#7-catálogo-de-detecciones)
8. [Inventario, confianza y modo aprendizaje](#8-inventario-confianza-y-modo-aprendizaje)
9. [Notificaciones](#9-notificaciones)
10. [Dashboard web](#10-dashboard-web)
11. [Referencia de configuración](#11-referencia-de-configuración)
12. [Variables de entorno](#12-variables-de-entorno)
13. [Modos del sensor y capacidades](#13-modos-del-sensor-y-capacidades)
14. [Autodetección de red](#14-autodetección-de-red)
15. [Escaneo de puertos con nmap](#15-escaneo-de-puertos-con-nmap)
16. [Instalación y despliegue](#16-instalación-y-despliegue)
17. [Pruebas y fixtures](#17-pruebas-y-fixtures)
18. [Convenciones e invariantes](#18-convenciones-e-invariantes)
19. [Limitaciones conocidas y deuda técnica](#19-limitaciones-conocidas-y-deuda-técnica)
20. [Guía de intervención para el agente](#20-guía-de-intervención-para-el-agente)
21. [Glosario de requisitos](#21-glosario-de-requisitos)
22. [Manejo seguro de datos sensibles](#22-manejo-seguro-de-datos-sensibles)

---

## 1. Resumen ejecutivo

**Batrade es un IDS doméstico de solo detección.** Vigila una red local (LAN), mantiene
un inventario de dispositivos, detecta patrones de ataque conocidos y avisa al operador
por Telegram, Discord o un log local. **Nunca bloquea tráfico, nunca inyecta paquetes y
no hace remediación activa.** Esa restricción es una decisión de producto, no una
limitación pendiente.

Objetivos concretos:

- Inventariar cada dispositivo de la LAN (MAC, IP, fabricante, hostname, estado de confianza).
- Detectar en tiempo casi real: ARP spoofing, barrido ARP, escaneo SYN, DHCP rogue,
  reinicio/cambio de router, dispositivos nuevos o no autorizados, puertos riesgosos.
- Avisar con un mensaje accionable (qué pasó, por qué importa, qué hacer).
- Exponer un panel web de revisión (dispositivos, alertas, línea base, salud).
- Correr en un solo equipo pequeño (Raspberry Pi, mini-PC, VM) sin dependencias de nube.
- Arrancar sin editar la configuración en cualquier distro moderna y tanto por Ethernet
  como por Wi-Fi.

No objetivos explícitos: bloquear tráfico, inyectar paquetes, telemetría a la nube,
remediación automática, almacenar contenido de paquetes.

**Idea clave del diseño:** el motor de detección no sabe de dónde viene un evento. Todo
se normaliza a una `Observation`, venga del sniffer real, de un `.pcap` reproducido, de
tráfico sintético o de la tabla de vecinos del kernel. Eso es lo que permite demostrar
y probar las detecciones en una máquina sin privilegios (`CAP_NET_RAW`).

---

## 2. Estado actual verificado

Comprobado ejecutando comandos en esta máquina, no inferido de la documentación:

| Comprobación | Resultado |
|---|---|
| `python -m pytest` en `.venv` | **196 passed** (base previa: 134) |
| Versión del paquete | `batrade 0.1.0` (renombrado a `0.2.0` pendiente de aprobación) |
| Python del venv | 3.14.10 |
| Dependencias importables | `flask 3.1.3`, `scapy 2.8.0`, `PyYAML`, `requests`, `defusedxml` |
| `nmap` / `arp-scan` / `ip` | instalados en `/usr/bin/` |
| `tshark` | no instalado (opcional, no se usa) |
| Consola `batrade` | enlazada en `~/.local/bin/batrade` |
| Base de datos local | `var/batrade.db`, esquema v2 (migrada desde v1 con copia previa) |
| Modo efectivo registrado | `degraded` (heartbeat `state=stopped`, sin `CAP_NET_RAW`) |
| Línea base | `learning_complete=1`, aprobada; gateway aprendido; interfaz `wlp2s0` |
| Integración continua | `.github/workflows/tests.yml` (pytest en 3.11, 3.12 y 3.13) |

Notas de estado:

- El proyecto **está instalado y funcionando** en esta máquina, no es solo código fuente.
- `var/` está ignorado por git y contiene datos del operador (inventario real de su LAN,
  eventos, XML de nmap, y ahora también copias `batrade.db.bak-v*`). Es información
  privada.
- Existe un `CONTEXT.md` en la raíz, **ignorado por git**, con una cabecera que lo
  declara histórico y enumera sus desfases con el código (tabla `heartbeat` en lugar de
  `meta`, migraciones versionadas, UDP, retención). Este documento es la referencia.
- Hay CI (GitHub Actions) desde v0.2. Sigue sin `LICENSE` (decisión pendiente), sin
  `Dockerfile` y sin changelog. No hay PRD dentro del repo: solo se citan
  identificadores de requisitos (`RF-xx`, `RNF-xx`, `Cx`) en comentarios.

---

## 3. Puesta en marcha en 5 minutos

Todas las formas de invocar son equivalentes: `batrade ...`, `.venv/bin/batrade ...`,
`python3 -m batrade ...`.

```bash
cd /home/techxicn_/code/Batrade

# 1. Comprobar entorno: interfaz elegida, subred, gateway, modo efectivo, capacidades
.venv/bin/python -m batrade doctor
.venv/bin/python -m batrade interfaces      # alias: ifaces

# 2. Sembrar datos de demostración (no toca la red, no necesita privilegios)
.venv/bin/python -m batrade demo

# 3. Panel web en primer plano -> http://127.0.0.1:8000
.venv/bin/python -m batrade dashboard

# 4. O los dos componentes en segundo plano
.venv/bin/python -m batrade start
.venv/bin/python -m batrade status
.venv/bin/python -m batrade stop
```

Flujo de trabajo del sensor (en primer plano, para depurar):

```bash
.venv/bin/python -m batrade sensor                 # modo de config.yaml (auto)
.venv/bin/python -m batrade sensor --mode degraded # sin privilegios
.venv/bin/python -m batrade sensor --mode replay --scenario arp_spoof
.venv/bin/python -m batrade sensor --mode simulate --scenario mixed --speed 5
.venv/bin/python -m batrade sensor --duration 120  # se detiene solo
```

Comprobación del panel sin navegador:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8000/health
```

**Orden correcto de arranque en un equipo real:** `init` (lo hace el instalador) →
`sensor` → `dashboard` → revisar `/devices` → `approve-baseline` cuando el inventario
esté completo. Antes de aprobar, los equipos nuevos se registran como `info` y no se
notifican (modo aprendizaje).

Advertencia operativa: **el sensor y el dashboard comparten el mismo SQLite.** No se
deben ejecutar dos sensores contra la misma base. Sí se pueden ejecutar dashboard y CLI
en paralelo con el sensor (WAL, lectores concurrentes).

---

## 4. Arquitectura y flujo de datos

### 4.1 Vista de procesos

```
                    +-------------------------------+
   LAN  --------->  |  batrade sensor (1 proceso)   |
                    |  hilos:                       |
                    |   main, sweep, neigh, sniff,  |
                    |   scan-0..N, notify, verify*  |
                    +---------------+---------------+
                                    |
                              SQLite WAL
                          var/batrade.db (1 escritor)
                                    |
                    +---------------+---------------+
                    |                               |
          batrade dashboard (proceso)        batrade CLI / cron
          Flask, lecturas + 3 escrituras      doctor, export, etc.
```

- **Un solo proceso de sensor, varios hilos.** Cada hilo abre **su propia** conexión
  SQLite (la librería no es segura entre hilos).
- **El dashboard es otro proceso** y solo lee, salvo tres escrituras acotadas.
- **WAL** permite lectores concurrentes; el escritor está serializado por
  `busy_timeout=5000`. No ejecutar dos sensores.

### 4.2 Hilos del sensor (`batrade/sensor.py`)

Se arrancan en `Sensor.start()` según el modo:

| Hilo | Cuándo | Qué hace |
|---|---|---|
| `batrade-main` | siempre | Tick de 1 s: sincroniza flag de aprendizaje, reclama `scan_requests`, poda estado del motor cada 30 s, purga por retención cada hora, escribe heartbeat cada `heartbeat_interval` (15 s), aplica `--duration`. |
| `batrade-notify` | siempre | Vacía `notification_queue` con backoff. |
| `batrade-sweep` | `live`, `degraded` | Barrido de descubrimiento cada `sweep_interval` (30 s). |
| `batrade-neigh` | `live`, `degraded` + `neighbor_watch` | Vigila la tabla de vecinos: netlink (`RTMGRP_NEIGH`) y, si falla, sondeo cada 2 s. |
| `batrade-sniff` | solo `live` | Captura pasiva con scapy (BPF: ARP + DHCP + SYN). |
| `batrade-scan-N` | `live`, `degraded` + `scan.enabled` | `max_concurrent` trabajadores que ejecutan nmap de la cola. |
| `batrade-feed` | `replay`, `simulate` | Alimenta el motor desde `.pcap` o escenarios sintéticos. Sustituye a sweep/sniff/scan. |
| `batrade-verify` | efímero | Sonda ARP activa para confirmar un spoofing (solo si hay `CAP_NET_RAW`). |

Comunicación: `queue.Queue` (máx. 64) para trabajos de escaneo; todo lo demás va por SQLite.

### 4.3 Ciclos de datos

**(a) Barrido periódico (`_sweep_loop`)**

```
Discovery.sweep()  ->  {ip: mac}
  -> Inventory.apply_sweep()   (altas, reconexiones, ausencias por misses)
  -> persist_findings()        (eventos + cola de notificación)
  -> _learn_gateway()          (fija gateway_mac la primera vez)
  -> _schedule_scans()         (primer escaneo "standard"; luego "quick" cada 24 h)
```

Detalle importante: **los hallazgos del barrido no pasan por el motor de reglas**, solo
por el inventario. Las reglas ARP se evalúan sobre tráfico observado (sniffer, netlink,
replay), no sobre el resultado del barrido.

**(b) Sniffer pasivo (`_sniff_loop`, solo `live`)**

```
paquete scapy -> observation_from_packet() -> Observation
  -> Engine.observe()          (reglas + throttle)
  -> si es ARP: Inventory.observe_host()
  -> persist_findings()
```

**(c) Vecinos del kernel (`_on_neighbor`)**

```
netlink RTM_NEWNEIGH (o sondeo de `ip neigh`)
  -> filtra fuera de CIDR y el propio sensor
  -> Engine.observe()  +  Inventory.observe_host() si event in (new, change)
  -> persist_findings()
```

**(d) Replay / simulación (`_feed_loop`)**

Genera `Observation` con timestamps reajustados al "ahora" y alimenta el mismo motor.
Es la vía para demostrar detecciones sin privilegios y la que usan los tests.

### 4.4 Camino de persistencia (`batrade/events.py`)

```
Finding
  -> si learning y tipo == "device_new": severidad = info, notificar = False
  -> store.add_event(...)  (dedupe por clave + cooldown)
  -> si is_new y severidad warn/crit y notificar: enqueue(event_id) por cada canal
  -> si is_new y finding.needs_verify y detect.arp_verify: hilo de verificación ARP
```

`persist_findings` devuelve `[(finding, event_id, is_new)]` para que el llamador lance
verificaciones sin volver a consultar la base. Una cola rota se registra pero **nunca
pierde el evento**: el evento ya está en la base.

---

## 5. Mapa de módulos y contratos

Todo el código está en español en nombres de dominio (tablas, estados, tipos de evento)
y en inglés en nombres de infraestructura (clases, funciones de librería). Mantener esa
convención.

### 5.1 Núcleo

| Archivo | Responsabilidad | Contrato |
|---|---|---|
| `batrade/__init__.py` | `__version__ = "0.1.0"` | — |
| `batrade/__main__.py` | `python -m batrade` → `cli.main()` | — |
| `batrade/cli.py` | Subcomandos y salida humana | Único punto de entrada. `export` lee SQL directo; `reset-db` (sólo root) escribe a través de `store`. Resuelve la raíz como `--root` > `BATRADE_ROOT` > paquete instalado. |
| `batrade/config.py` | Carga `.env` + `config.yaml`, resuelve red, valida, emite `warnings` | Lanza `ConfigError(errors: list[str])` con **todos** los problemas; no arranca a medias. |
| `batrade/logging_setup.py` | JSONL rotado (2 MB × 5) + consola legible | Idempotente por componente. |
| `batrade/db.py` | Esquema SQLite, `connect()`, runner de `migrate()`, copias `backup`/`backup_tagged`, `recover_interrupted()`, `get_meta`/`set_meta`, `is_learning` | `SCHEMA_VERSION` derivada de `MIGRATIONS` (hoy 2); `PRAGMA user_version`. |
| `batrade/store.py` | **Todo** el SQL de lectura/escritura | Ninguna otra capa escribe SQL. Sin ORM. Devuelve `sqlite3.Row`/`dict`. |
| `batrade/events.py` | Persistencia común de `Finding` + hallazgos de fallo de herramienta | Único camino demo/replay/sensor. |
| `batrade/inventory.py` | Altas, reconexiones, ausencias, confianza, línea base | `observe_host`, `apply_sweep`, `approve_baseline`, `review_candidates`, `status`. |
| `batrade/notify.py` | Cola, formato y envío por canal | `Notifier.enqueue/run/process_once`; backoff; `LocalSink` a `var/alerts.log`. |
| `batrade/daemon.py` | `start/stop/restart/status` sin systemd | PID files en `var/`, logs en `var/log/`, valida `/proc/<pid>/cmdline` antes de señalizar. |
| `batrade/sensor.py` | Orquestador de hilos | `Sensor.run()/stop()`, `ScanJob`, `_persist`. |
| `batrade/demo.py` | Siembra escenarios + puertos de ejemplo | No toca la red; fuerza canales `local`. |

### 5.2 Detección (`batrade/detect/`)

| Archivo | Responsabilidad |
|---|---|
| `observation.py` | `Observation` y `Finding` (datos puros, sin efectos). |
| `engine.py` | Orquesta reglas, throttle de emisión, aislamiento de errores, `snapshot()`. |
| `rules.py` | 5 reglas puras + tupla global `RULES`. |
| `state.py` | `TimeWindow`, `SynTracker`, `Binding`, `Baseline`, `EngineState` con cotas. |
| `scenarios.py` | Escenarios sintéticos, escritura/lectura de `.pcap`, `observation_from_packet`. |
| `sniffer.py` | Captura scapy (`store=False` obligatorio), respeta `stop_event`. |

### 5.3 Red (`batrade/net/`)

| Archivo | Responsabilidad |
|---|---|
| `caps.py` | Sondea `AF_PACKET`, `AF_NETLINK`, `arp-scan`, `nmap`, `ip`, `scapy`, `tshark`; `resolve_mode()` nunca falla por privilegios. |
| `ifaces.py` | Lista interfaces IPv4 vía `ip -j`/`ip -o` + `/sys/class/net`; `pick()` implementa la prioridad. Sin privilegios. |
| `discovery.py` | `arp-scan` si hay privilegios; si no, sondeo TCP + `ip neigh`. `SweepResult(hosts, backend, degraded, duration_ms)`. |
| `neigh.py` | Lectura de `ip -4 neigh`, `probe_cidr()` (connect no bloqueante), parser netlink y `NeighborWatcher`. |
| `nmap_scan.py` | Perfiles, ejecución sin shell, parseo XML con `defusedxml`, `udp_risky_ports()`. |
| `verify.py` | `probe_binding()` (ARP con scapy) e `interpret()` → `(confirmado|None, explicación)`. |
| `oui.py` | Base OUI local con 7 rutas candidatas; sin internet. |
| `iputil.py` | Normalización MAC/IP, bit local/multicast, `now_ms()`, `default_gateway()`, `ip_in_cidr()`. |

### 5.4 Dashboard (`batrade/dashboard/`)

`app.py` (rutas, auth, CSRF, filtros Jinja), `templates/*.html` (9 plantillas),
`static/style.css` (303 líneas, sin frameworks JS).

---

## 6. Modelo de datos

Un único archivo SQLite (`var/batrade.db`), WAL, `foreign_keys=ON`, `synchronous=NORMAL`,
`wal_autocheckpoint=512`, `busy_timeout=5000`.

**Convenciones globales**

- **Todos los timestamps son epoch en milisegundos UTC (INTEGER).**
- Estados de confianza: `confiable` | `desconocido` | `no_autorizado`.
- Severidades: `info` | `warn` | `crit`.
- Disposición de evento: `sin_evaluar` | `tp` | `fp`.
- Estados de escaneo: `pendiente` | `ejecutando` | `ok` | `error` | `interrumpido`.
- Estados de solicitud de escaneo: `pendiente` | `ejecutando` | `hecho` | `error` | `descartado`.
- Estados de notificación: `pendiente` | `enviado` | `agotado`.

### Tablas

**`identities`** — agrupación lógica de un equipo que cambia de MAC.
`id`, `key` (UNIQUE, `"mac:<mac>"` o `"hostname:<host>"`), `kind`, `label`, `first_seen`, `last_seen`.

**`devices`** — una fila por MAC única.
`id`, `identity_id`, `mac` (UNIQUE), `mac_aleatoria` (0/1), `ip_actual`, `fabricante`,
`hostname`, `alias`, `estado_confianza` (CHECK), `first_seen`, `last_seen`, `en_linea`,
`misses`, `last_scan_ts`, `last_scan_profile`, `notes`.
Índices por `last_seen DESC`, `estado_confianza`, `ip_actual`.

**`device_history`** — `id`, `device_id`, `ts`, `ip`, `evento` (`conexion`|`desconexion`|`cambio_ip`), `detalle`.

**`ports`** — PK compuesta `(device_id, protocolo, puerto)`; `estado`, `servicio`, `version`,
`riesgoso`, `first_seen`, `last_seen`.

**`scans`** — cada ejecución de nmap: `device_id`, `tipo`, `perfil`, `inicio`, `fin`,
`estado`, `ruta_xml`, `cmd`, `exit_code`, `error`.

**`events`** — `id`, `ts`, `first_ts`, `last_ts`, `severidad` (CHECK), `tipo`, `ip_origen`,
`mac_origen`, `ip_destino`, `detalle_json`, `clave_dedupe`, `repeat_count`, `notificado`,
`ts_notificado`, `disposicion` (CHECK), `verified`.
Índices por `ts`, `(severidad, ts)`, `(tipo, ts)`, `(clave_dedupe, last_ts)`, `(disposicion, ts)`.

**`notification_queue`** — `event_id`, `canal`, `intentos`, `proximo_intento`, `estado`,
`last_error`, `ts`. Índice `(estado, proximo_intento)` y, desde el esquema v2,
`(estado, ts)` para la purga por antigüedad. UNIQUE implícito por
`(event_id, canal)` comprobado en código.

**`scan_requests`** — `objetivo`, `perfil`, `solicitado_por`, `estado`, `ts`, `ts_fin`, `error`.
Índice único parcial `(objetivo, perfil) WHERE estado='pendiente'` (coalescing).

**`heartbeat`** — `componente` (PK), `ts`, `detalle` (JSON con modo, estado, capacidades,
snapshot del motor, cola, contadores de notificación).
El dashboard marca "sensor sin latido" cuando el último late más de
`heartbeat_interval × 3000` ms (45 s con el valor por defecto).

**`network_baseline`** — clave/valor (`k` PK, `v`, `updated_ts`). Claves usadas:
`gateway_ip`, `gateway_mac`, `dhcp_server_ip`, `sensor_mode`, `interface`,
`learning_complete`, `baseline_approved_ts`.

**`tool_status`** — `herramienta` (PK, p. ej. `sweep:arp-scan`, `sweep:neigh`, `nmap`),
`ts`, `ok`, `exit_code`, `error`, `fallos_consecutivos`.

### Esquema y migraciones

`db.migrate()` es un **runner de migraciones versionadas**. La lista ordenada
`MIGRATIONS = [(versión, pasos), ...]` vive en `db.py`; cada entrada puede ser un script
SQL, una secuencia de sentencias o una función `fn(conn)`. Reglas: sólo aditivas
(`ALTER TABLE ADD COLUMN` protegido con comprobación de existencia, `CREATE ... IF NOT
EXISTS`), idempotentes y nunca destructivas. `SCHEMA_VERSION` se deriva de la última
entrada, así que hay una única fuente de verdad.

Funcionamiento:

1. lee `PRAGMA user_version` y aplica **sólo** las versiones pendientes;
2. cada migración corre en su propia transacción (`BEGIN IMMEDIATE` … `COMMIT`) y el
   avance de `user_version` va dentro de esa misma transacción: si algo falla se hace
   `ROLLBACK` y la base queda como estaba (ni columnas nuevas ni versión avanzada). Las
   sentencias se ejecutan una a una porque `executescript` hace COMMIT implícito;
3. antes de migrar una base existente **con datos** escribe una copia
   `<db>.bak-v<N>` (permisos 600) usando la API de backup de SQLite —incluye lo que aún
   esté en el WAL— y nunca sobrescribe una copia previa (añade `-2`, `-3`…);
4. una base nueva recibe todas las migraciones y termina en la última versión.

Versiones actuales: **v1** = esquema inicial (tablas e índices del MVP); **v2** =
índice `idx_nq_estado_ts` sobre `notification_queue(estado, ts)` para la purga por
antigüedad. `batrade init` y `batrade doctor` muestran la versión realmente almacenada
en el archivo y avisan si está pendiente.

`db.recover_interrupted()` se ejecuta al arrancar el sensor: marca `scans` en
`ejecutando` como `interrumpido` y devuelve `scan_requests` a `pendiente`, para que el
panel no mienta tras un reinicio.

---

## 7. Catálogo de detecciones

### 7.1 Tipos de `Observation`

`kind` ∈ `arp` | `syn` | `dhcp` | `neigh`. Campos: `ts`, `iface`, `ip_src`, `mac_src`,
`ip_dst`, `mac_dst`, `port_dst`, `op`, `extra`. Propiedades: `gratuitous` (`extra.gratuitous`),
`flags` (`extra.flags`).

### 7.2 `Finding`

`tipo`, `severidad`, `clave` (clave de dedupe), `ip_origen`, `mac_origen`, `ip_destino`,
`detalle` (dict con `resumen`, `por_que`, `accion` + campos extra), `notificar`,
`verified`, `needs_verify` (IP a verificar de forma asíncrona).
`finding.notify` ⇔ `notificar and severidad in (warn, crit)`.

### 7.3 Reglas (en orden de evaluación)

**`ArpBindingRule`** — `kind ∈ {arp, neigh}`, `op ∈ {None, request, reply}`.
Ignora multicast y el propio sensor. Aprende binding `IP→MAC` (`EngineState.bindings`,
máx. 4096).

- Binding nuevo: se guarda; si es el gateway y no hay `gateway_mac`, se adopta.
- Cambio de MAC en IP no-gateway:
  - si el binding previo tiene más de **1 h** (`BINDING_REUSE_MS`): `info` / `arp_ip_reuse`;
  - si no: `warn` / `arp_ip_mac_change`.
- Cambio de MAC en la **IP del gateway**: `crit` / `arp_gateway_mac_change` y
  `needs_verify = ip` (dispara sonda ARP activa).
- Una misma MAC reclamando ≥2 IPs distintas en la ventana (`mac_claims`, máx. 40/IP):
  `crit` si una de ellas es el gateway o el sensor; si no `warn`. Tipo
  `arp_mac_multiple_ips`. Se omite para MACs en `detect.arp_exceptions`.

Clave de dedupe: `arp:bind:<ip>:<mac>` / `arp:multiip:<mac>`.

**`ArpSweepRule`** — solo `arp` con `op=request`. Cuenta IPs destino distintas por MAC
origen en la ventana. Ignora MAC del gateway (sondea constantemente), del sensor y las
excepciones. Umbral `arp_sweep_ips` (30) → `warn`; 3× (90) → `crit`. Tipo `arp_sweep`,
clave `arp:sweep:<mac>`.

**`ArpFloodRule`** — solo `arp` con `op=reply`. Cuenta respuestas por MAC (`ARP_FLOOD_MIN = 20`)
y **exige al menos un conflicto de binding** en la ventana de conflictos (3× ventana).
Sin conflicto no alerta: un reinicio de router no dispara críticos. Tipo `arp_flood`
(`warn`), clave `arp:flood:<mac>`.

**`SynScanRule`** — solo `syn`, `flags` contiene `S` y no contiene `A` ni `R`.
Excluye el sensor (IP o MAC). Cuenta puertos distintos por `(src, dst)` y destinos
distintos por `src` en la ventana:

- `syn_ports_crit` (100) → `crit` / `scan_ports_aggressive`
- `syn_ports_warn` (15) → `warn` / `scan_ports_moderate`
- `syn_dsts_crit` (25) → `crit` / `scan_hosts_aggressive`

Claves: `scan:ports:<src>:<dst>`, `scan:hosts:<src>`.

**`DhcpRogueRule`** — solo `dhcp` con `op=offer`. Si no hay servidor esperado, aprende el
primero y calla. Cualquier otro servidor → `crit` / `dhcp_rogue`, clave `dhcp:rogue:<server>`.

La tupla `RULES` al final de `rules.py` es lo que el motor carga por defecto; los tests
pueden inyectar un subconjunto pasando `rules=` al `Engine`.

### 7.4 Motor (`detect/engine.py`)

- Ejecuta cada regla dentro de `try/except`: una regla rota no tumba el sensor; se
  registra `rule_error:<regla>` en `stats`.
- **Throttle de emisión:** como máximo 1 hallazgo por segundo por
  `(tipo, clave, severidad)`. La severidad forma parte de la clave a propósito: una
  escalada `warn → crit` no queda silenciada.
- No hace I/O. No escribe en la base ni envía alertas.
- `set_learning()`, `register_sensor(ip, mac)`, `prune()`, `snapshot()`.

### 7.5 Estado acotado (`detect/state.py`)

Memoria acotada por diseño (KPI de memoria a 24 h):

- `TimeWindow(span_ms, max_per_key, max_keys)`: `deque(maxlen)`, poda por tiempo y por
  número de claves (baja al 80 % de `max_keys`).
- `mac_claims`: 40 por MAC, 2048 claves. `arp_requests`/`arp_replies`: 200 por clave,
  2048 claves. `conflicts`: ventana 3×, 40 por clave, 1024 claves.
- `SynTracker`: `max_per_key=600`, `max_keys=4000` para ambos mapas.
- `bindings`: máx. 4096; se expulsa el más antiguo; poda a 1 h mínimo.
- `prune()` se llama cada 30 s desde el hilo principal.

### 7.6 Tabla resumen de eventos

| `tipo` | Severidad | Origen | `clave_dedupe` | ¿Notifica? |
|---|---|---|---|---|
| `arp_gateway_mac_change` | crit | regla ARP | `arp:bind:<ip>:<mac>` | sí (+ verificación) |
| `arp_ip_mac_change` | warn | regla ARP | `arp:bind:<ip>:<mac>` | sí |
| `arp_ip_reuse` | info | regla ARP | `arp:bind:<ip>:<mac>` | no |
| `arp_mac_multiple_ips` | crit/warn | regla ARP | `arp:multiip:<mac>` | sí |
| `arp_sweep` | warn/crit | regla ARP | `arp:sweep:<mac>` | sí |
| `arp_flood` | warn | regla ARP | `arp:flood:<mac>` | sí |
| `scan_ports_moderate` | warn | regla SYN | `scan:ports:<src>:<dst>` | sí |
| `scan_ports_aggressive` | crit | regla SYN | `scan:ports:<src>:<dst>` | sí |
| `scan_hosts_aggressive` | crit | regla SYN | `scan:hosts:<src>` | sí |
| `dhcp_rogue` | crit | regla DHCP | `dhcp:rogue:<server>` | sí |
| `device_new` | warn (info en learning) | inventario | `device:new:<mac>` | sí (no en learning) |
| `device_mac_rotated` | info | inventario | `device:new:<mac>` | no |
| `device_online` | info | inventario | `device:online:<id>` | no |
| `device_offline` | info | inventario | `device:offline:<mac>` | no |
| `device_unauthorized_online` | crit | inventario | `device:unauth:<id>` | sí |
| `port_risky` | warn | escaneo | `port:risky:<dev>:<proto>:<port>` | sí |
| `port_new` | warn | escaneo (solo equipos `confiable`) | `port:new:<dev>:<proto>:<port>` | sí |
| `tool_failure` | warn | sensor (≥3 fallos seguidos) | `tool:fail:<tool>` | sí |

### 7.7 Deduplicación y escalada (`store.add_event`)

- Busca el último evento con la misma `clave_dedupe`.
- Si está dentro de `detect.cooldown_s` (300 s por defecto) **y** la severidad nueva no es
  mayor, incrementa `repeat_count` y actualiza `last_ts` (no inserta, no notifica).
- Si hay escalada (`warn → crit`), inserta un evento nuevo: merece su propia notificación.
- `verified` se actualiza después, de forma asíncrona, junto con `detalle_json`.

---

## 8. Inventario, confianza y modo aprendizaje

### 8.1 Transiciones

`upstream.store.upsert_device()` devuelve `{device_id, created, identity_created,
ip_changed, prev_ip, came_online, en_linea, estado_confianza}` y registra historial
(`conexion`, `cambio_ip`, `desconexion`).

`Inventory.observe_host()` genera:

| Situación | Evento | Severidad |
|---|---|---|
| MAC nueva, misma identidad (MAC rotada) | `device_mac_rotated` | info, no notifica |
| MAC nueva | `device_new` | info en learning; warn fuera |
| Equipo conocido vuelve estando `no_autorizado` | `device_unauthorized_online` | crit |
| Equipo conocido vuelve | `device_online` | info, no notifica |
| Equipo en línea no aparece en `presence_misses` (3) barridos | `device_offline` | info, no notifica |

### 8.2 Identidad

`_identity_key()`: solo agrupa por hostname cuando la MAC es **localmente administrada**
y el hostname no es genérico (`localhost`, `android`, `unknown`, `?`, `-`, `none`, vacío)
y tiene más de 2 caracteres. En el resto de casos la identidad es la MAC. Esto agrupa
teléfonos que rotan MAC por red sin fusionar equipos distintos.

### 8.3 Confianza y aprobación

- Todo equipo nuevo entra como `desconocido`.
- `approve_baseline(include_random_mac=False)` marca `confiable` a los `desconocido`
  **excepto** los de MAC localmente administrada, que quedan para revisión individual
  (aprobarlos en lote legitimaría a cualquiera que ya estuviera conectado). Fija
  `learning_complete=1` y `baseline_approved_ts`.
- `review_candidates()` lista equipos `desconocido` con MAC aleatoria, sin hostname o sin
  fabricante: los que no deberían aprobarse a ciegas.
- `begin_learning()` vuelve a activar el aprendizaje (no expuesto en CLI ni dashboard).
- Una MAC localmente administrada **no** tiene OUI significativo: no se consulta el
  fabricante y se marca `mac_aleatoria=1`. El bit 0x02 es un **indicio**, no una prueba
  (también lo llevan veth de Docker, QEMU, NICs virtuales).

### 8.4 Qué cambia en modo aprendizaje

Solo dos efectos:

1. `device_new` se degrada a `info` y no se notifica (`events.persist_findings`).
2. `Inventory` nace con `learning=True` y `_new_device_finding` usa `info`.

El resto de reglas (ARP, SYN, DHCP, puertos) alerta igual desde el primer minuto. El
banner del panel y la página `/learning` lo recuerdan.

---

## 9. Notificaciones

Cola persistente en `notification_queue`, una fila por `(evento, canal)`. El hilo
`batrade-notify` llama a `process_once()` cada segundo.

Canales (`notify.channels` en `config.yaml`):

| Canal | Requiere | Comportamiento |
|---|---|---|
| `local` | nada | Añade a `var/alerts.log` (texto plano, con separador de fecha; permisos 600). Nunca falla. |
| `telegram` | `TELEGRAM_TOKEN`, `TELEGRAM_CHAT_ID` | `POST https://api.telegram.org/bot<token>/sendMessage`, `parse_mode=HTML`, todo el texto escapado con `html.escape`. |
| `discord` | `DISCORD_WEBHOOK` | `POST` del webhook con un `embed` (título, descripción ≤ 3900 chars, color por severidad). |

Formato del mensaje (exigencia de producto): **qué pasó, por qué importa, qué hacer**,
más evento, cuándo, origen/destino y repeticiones acumuladas.

Reintentos: backoff `min(5 × 2^n, 300)` s → 5, 10, 20, 40, 80, 160, 300… hasta
`notify.max_attempts` (8); después el estado pasa a `agotado`. Un fallo de red **no borra**
la fila ni el evento: el evento sigue visible en el panel.

Solo se encolan eventos `warn`/`crit` con `is_new = True` (no las repeticiones
deduplicadas). `notificado` y `ts_notificado` se actualizan al enviar.

---

## 10. Dashboard web

Flask con sesión y CSRF. Escucha en `dashboard.host:port` (por defecto
`127.0.0.1:8000`). Si `host` no es loopback, la configuración **exige**
`DASHBOARD_TOKEN` o no arranca.

### Rutas

| Método | Ruta | Contenido |
|---|---|---|
| GET/POST | `/login` | Token de sesión (solo si hay `auth_token`) |
| GET | `/` | Resumen: dispositivos, en línea, desconocidos/no autorizados, alertas de hoy por severidad, FP de hoy, últimos 8 eventos, salud |
| GET | `/devices` | Inventario con filtros `estado`, `q`, `online=1` |
| GET | `/devices/<id>` | Detalle: puertos, historial, eventos, últimos 10 escaneos, formulario de escaneo |
| POST | `/devices/<id>` | Cambia `alias` y/o `estado_confianza` |
| GET | `/events` | Historial con filtros `severidad`, `tipo` (300 últimos) |
| POST | `/events/<id>/disposicion` | Marca `tp` / `fp` / `sin_evaluar` |
| GET | `/learning` | Estado de línea base, candidatos a revisión, todos los equipos |
| POST | `/learning/approve` | Aprueba la línea base (`include_random=1` opcional) |
| POST | `/scan` | Encola escaneo manual; `vuln` exige `confirm=1`; objetivo validado contra el CIDR |
| GET | `/health` | Heartbeat, capacidades, modo efectivo, herramientas, tamaño de BD, últimas 20 solicitudes |

### Escrituras permitidas (decisión de diseño C1)

Solo tres, deliberadamente acotadas:

1. `devices.alias` / `devices.estado_confianza`.
2. `scan_requests` (botón de escaneo).
3. `events.disposicion`.

El sensor es el único que escribe eventos, puertos y la cola de notificación.

**El panel no puede reiniciar la base.** `reset-db` existe sólo en la CLI, exige root y un
sensor detenido: es una acción manual y explícita, nunca automática y nunca accesible desde
la web.

### Seguridad del panel

- `SECRET_KEY` = SHA-256 del token si existe; si no, `secrets.token_hex(16)` por proceso.
- Cookie `SameSite=Strict`, `HttpOnly`.
- Todo `POST` exige token CSRF (`session["csrf"]`, comparación con `hmac.compare_digest`).
- Login con `hmac.compare_digest` contra el token.
- Todas las consultas SQL son parametrizadas; los hostnames de la red se tratan como no
  confiables (se limpian a caracteres imprimibles, máx. 63).
- No hay API JSON: las rutas devuelven HTML. Para datos, usar `batrade export`.

---

## 11. Referencia de configuración

`config.yaml` es el único archivo de configuración. **Los secretos van solo en `.env`.**
Todas las rutas son relativas a la raíz del proyecto.

### `network`

| Clave | Default | Descripción | Validación |
|---|---|---|---|
| `interface` | `auto` | Interfaz a vigilar. `auto`/`any`/`detect`/`detectar`/vacío = autodetección; si no, nombre real (`eth0`, `enp3s0`, `wlp2s0`, `vmnet19`…). | Debe existir en el sistema. |
| `cidr` | `auto` | Subred. `auto` = derivada de IP/máscara. | `/16`…`/30` y **normalizada** (`192.168.0.0/24`, no `192.168.0.5/24`). |
| `gateway_ip` | `null` | Gateway. Vacío = ruta por defecto, adoptada solo si pertenece al CIDR. | IPv4 dentro del CIDR. |
| `dhcp_server_ip` | `null` | Servidor DHCP autoritativo. Vacío = se aprende el primero. | IPv4 dentro del CIDR. |

### `sensor`

| Clave | Default | Validación |
|---|---|---|
| `mode` | `auto` | `auto`\|`live`\|`degraded`\|`replay`\|`simulate` |
| `sweep_interval` | 30 | 15…300 s |
| `presence_misses` | 3 | ≥ 1 |
| `heartbeat_interval` | 15 | ≥ 5 s |
| `retention_days` | 90 | ≥ 1 |
| `neighbor_watch` | true | — |

### `scan`

| Clave | Default | Notas |
|---|---|---|
| `enabled` | true | — |
| `max_concurrent` | 2 | Se fuerza ≥ 1. |
| `timing` | `-T3` | Plantilla de timing de nmap. |
| `standard_timeout` | 300 | Límite del perfil `standard` (tope histórico de 300 s). Valida ≥ 1. |
| `quick_timeout` | 120 | Límite del perfil `quick` (`profile_timeout`). Valida ≥ 1. |
| `udp_timeout` | 60 | `--host-timeout` de la pasada UDP; el proceso recibe este valor + 30 s. Valida ≥ 5. |
| `quick_periodic_hours` | 24 | Horas tras las que un equipo recibe un reescaneo `quick` (RF-07). Valida ≥ 1. |
| `weekly_rescan_days` | 7 | Días tras los que un equipo `confiable` recibe un `standard` (RF-10). Valida ≥ 1. |
| `risky_ports` | catálogo de 10 puertos | Lista de `{port, protocol, service, reason}`; `protocol` obligatorio (`tcp`/`udp`). |

Catálogo por defecto: FTP 21, Telnet 23, Telnet-alt 2323, NetBIOS 139, SMB 445, RDP 3389,
VNC 5900, RTSP 554 (todos TCP), UPnP/SSDP 1900 y mDNS 5353 (UDP).

Los tres plazos de escaneo se usan de verdad desde v0.2; los valores por defecto
(120 s, 24 h, 7 d) reproducen el comportamiento anterior. Ver §15 para la programación
y la pasada UDP.

### `detect`

| Clave | Default | Validación |
|---|---|---|
| `window_s` | 10 | 2…600 s |
| `syn_ports_warn` | 15 | ≥ 1 y **menor** que `syn_ports_crit` |
| `syn_ports_crit` | 100 | ≥ 1 |
| `syn_dsts_crit` | 25 | ≥ 1 |
| `arp_sweep_ips` | 30 | ≥ 1 (crítico a 3×) |
| `arp_verify` | true | Sonda ARP activa antes de confirmar |
| `arp_verify_timeout` | 1.5 | segundos |
| `arp_exceptions` | `[]` | MACs exentas (proxy ARP, failover), en minúsculas |
| `cooldown_s` | 300 | ≥ 0 |

### `notify`

| Clave | Default | Validación |
|---|---|---|
| `channels` | `[{type: local}]` | Solo `local`, `telegram`, `discord` |
| `timeout_s` | 8 | 0.5…60 |
| `max_attempts` | 8 | ≥ 1 |

Canales con credenciales: `{type: telegram, token_env: TELEGRAM_TOKEN, chat_id_env: TELEGRAM_CHAT_ID}`
y `{type: discord, webhook_env: DISCORD_WEBHOOK}`. Los nombres de variable son
configurables; los valores, no.

### `dashboard`

| Clave | Default | Validación |
|---|---|---|
| `host` | `127.0.0.1` | Fuera de loopback exige token |
| `port` | 8000 | 1…65535 |
| `auth_token_env` | `DASHBOARD_TOKEN` | Nombre de la variable |

### `paths`

| Clave | Default |
|---|---|
| `db` | `var/batrade.db` |
| `scans_dir` | `var/scans` |
| `log_dir` | `var/log` |
| `alerts_log` | `var/alerts.log` |
| `oui_file` | `/usr/share/nmap/nmap-mac-prefixes` |

`oui_file` es una **preferencia**, no un requisito: si no existe se prueban
`/usr/share/arp-scan/ieee-oui.txt`, `/usr/share/ieee-data/oui.txt`,
`/usr/share/wireshark/manuf`, `/usr/share/nmap-mac-prefixes`,
`/usr/local/share/nmap/nmap-mac-prefixes` y la ruta de Linuxbrew. Sin base OUI solo se
pierden los nombres de fabricante.

### Resolución de red y avisos

`config.load_config()` resuelve `interface`/`cidr`/`gateway_ip` **antes** de validar y
acumula mensajes legibles en `Config.warnings` (interfaz autodetectada y por qué, subred
derivada, gateway adoptado o ignorado, aviso de Wi-Fi). Esos avisos se imprimen en
`doctor`, se registran en el log del sensor y se muestran en `/health`.

`ConfigError` agrupa **todos** los errores; el CLI los imprime y sale con código 2.

---

## 12. Variables de entorno

Se cargan desde `.env` en la raíz con un parser mínimo (`KEY=VALUE`, ignora `#`, no
sobreescribe variables ya presentes en el entorno, tolera `.env` ilegible). `.env` está
en `.gitignore` y el instalador lo crea con permisos 600.

| Variable | Consumidor | Efecto |
|---|---|---|
| `TELEGRAM_TOKEN` | `notify.py` | Token del bot. |
| `TELEGRAM_CHAT_ID` | `notify.py` | Chat/canal destino. |
| `DISCORD_WEBHOOK` | `notify.py` | URL completa del webhook. |
| `DASHBOARD_TOKEN` | `dashboard/app.py`, `config.py` | Exigido si el panel no escucha en loopback. |
| `BATRADE_ROOT` | `cli.py` | Raíz del proyecto cuando se lanza desde otro directorio. La fija el wrapper de `install.sh --system`; `--root` tiene prioridad. |

En esta máquina el archivo `.env` existe con las cinco claves declaradas pero **vacías**
(no hay credenciales configuradas), por lo que el único canal activo es `local`. Ese es
también el estado del repo: `.env.example` documenta las claves y `.env` está ignorado.
Cuando el operador las rellene, **no deben copiarse a documentos, prompts, commits ni
tickets**. Si el agente necesita probar notificaciones, que use `{type: local}` y
`var/alerts.log`.

---

## 13. Modos del sensor y capacidades

`net/caps.probe()` sondea sin privilegios: `AF_PACKET`, `AF_NETLINK` (`RTMGRP_NEIGH`),
`arp-scan`, `nmap`, `ip`, `scapy`, `tshark`, `is_root`. `resolve_mode()` mapea lo
solicitado a lo posible **sin lanzar excepción** (salvo `replay`/`simulate` sin scapy).

| Modo | Requiere | Qué hace | Cuándo se elige |
|---|---|---|---|
| `live` | `CAP_NET_RAW` + `arp-scan` | Descubrimiento ARP + sniffer pasivo + netlink + nmap `-sS` | `auto` con ambas capacidades |
| `degraded` | nada extra | Sondeo TCP + `ip neigh` + netlink + nmap `-sT` | `auto` sin raw, o `live` imposible |
| `replay` | scapy | Alimenta el motor desde `.pcap` | explícito |
| `simulate` | scapy | Escenarios sintéticos | explícito |
| `auto` | — | Decide en cada arranque | por defecto |

Si se pide `live` sin capacidades, arranca en `degraded` y lo dice en el log, en
`doctor` y en `/health` con una nota explicando qué falta. **El sensor nunca muere por
falta de privilegios** (excepto `replay`/`simulate` sin scapy).

`scan_style()`: `-sS` con raw, `-sT` sin él. Con `CAP_NET_RAW` se añade además una
pasada UDP acotada a los puertos UDP del catálogo; sin raw no se ejecuta, `udp_risky_ports()`
devuelve la nota "UDP no verificable sin CAP_NET_RAW", el sensor la registra una vez por
escaneo y `/health` la muestra (ver §15).

---

## 14. Autodetección de red

Objetivo: `config.yaml` no se toca al cambiar de equipo o de red.

**Selección de interfaz** (`ifaces.pick`), en orden:

1. La configurada explícitamente (`network.interface`).
2. La que lleva la ruta IPv4 por defecto, **si no es loopback ni virtual**.
3. Candidatas con IPv4, no virtuales y `up`; ordenadas por
   `(wireless, no_rfc1918, nombre)` → primero cableada con IP privada.
4. Cualquier interfaz no virtual con IPv4 (aunque esté `down` si no hay mejor).

Prefijos virtuales ignorados: `docker`, `veth`, `virbr`, `br-`, `tap`, `tun`, `vnet`,
`cni`, `flannel`, `kube`, `podman`, `tailscale`, `zt`.
**`vmnet*` y `vmbr*` se conservan a propósito**: pueden ser la LAN de un laboratorio.

**Subred:** `IfaceInfo.cidr` deriva `ip/prefixlen` normalizado con `strict=False`.
`cidr: auto` en modo `replay`/`simulate` sin IPv4 cae a `192.168.1.0/24` con aviso, para
que la demo funcione en cualquier sitio.

**Gateway:** `gateway_ip: null` adopta la ruta por defecto **solo** si pertenece al CIDR;
si no, se deja vacío y se avisa (el panel lo muestra). El sensor prioriza para la línea
base: valor guardado en `network_baseline` → `config.yaml` → ruta por defecto.

**Wi-Fi:** en modo managed la captura pasiva solo ve el tráfico del propio equipo y
broadcast/multicast. Descubrimiento y netlink siguen funcionando. Para visibilidad
completa hace falta puerto espejo cableado o modo monitor. `config` y `doctor` avisan.

**Diagnóstico:** `batrade interfaces` imprime `INTERFAZ / TIPO / ESTADO / IP-CIDR / MAC / RUTA`
con la interfaz de la ruta por defecto marcada.

---

## 15. Escaneo de puertos con nmap

Perfiles (`nmap_scan.PROFILES`):

| Perfil | Argumentos | Timeout proceso | `--host-timeout` | Uso |
|---|---|---|---|---|
| `quick` | `-F --version-light` | `scan.quick_timeout` (120 s) | 60 s | Reescaneo periódico (`quick_periodic_hours`, 24 h) |
| `standard` | `-sV --top-ports 1000 --version-light` | `min(300, scan.standard_timeout)` | 120 s | Primer escaneo y reescaneo semanal (RF-10) |
| `vuln` | `-sV --script vuln` | 900 s | 300 s | Bajo demanda, intrusivo, confirmación explícita |

Comando TCP real: `nmap {-sS|-sT} -Pn <perfil> -T3 --host-timeout <t> -oX <xml> <target>`.
`profile_timeout(cfg, perfil)` centraliza el límite de proceso para que las claves
`scan.quick_timeout` y `scan.standard_timeout` manden de verdad.

**Pasada UDP (solo con `CAP_NET_RAW`).** Después del escaneo TCP se ejecuta una segunda
invocación acotada:

```
nmap -sU -sV --version-light -Pn -p U:<puertos udp del catálogo> -T3 \
     --host-timeout <scan.udp_timeout>s --max-retries 1 -oX <xml> <target>
```

- `-sV --version-light` es obligatorio en la práctica: sin la sonda de servicio, SSDP y mDNS
  se quedan casi siempre en `open|filtered` y la pasada no produciría ningún hallazgo real.
  Con ella, un servicio que responde pasa a `open` y se guarda versión y producto.
- `scan.udp_timeout` (60 s por defecto, mínimo 5) es el `--host-timeout`; el proceso de nmap
  recibe ese valor **+ 30 s** de margen para alcanzar a escribir el XML.

- Sólo se guardan los puertos en estado `open`. `open|filtered` es el resultado normal de
  UDP sin respuesta y **nunca** genera evento (evita falsos positivos).
- `ports.protocolo = "udp"` y `store.apply_scan_ports` genera `port_risky` igual que con
  TCP, porque el catálogo está indexado por `(protocolo, puerto)`.
- `ScanResult.protocols` indica qué protocolos se exploraron de verdad. La fase de cierre
  de puertos respeta ese conjunto: **un protocolo no escaneado no puede marcar sus puertos
  como cerrados** (sin raw, los UDP conocidos se quedan como estaban).
- Un fallo de la pasada UDP no invalida el resultado TCP: se anota en `result.notes`.
- Sin raw no se ejecuta; la nota "UDP no verificable sin CAP_NET_RAW: los puertos […] no
  se evalúan en modo degradado" se registra a nivel `info` una vez por ejecución y se
  muestra como banner en `/health`.
- El XML de la pasada UDP se elimina tras volcar sus puertos: la fila de `scans` sólo
  referencia un XML y así no quedan artefactos fuera de la retención.

Garantías:

- **Sin `shell=True`**: argumentos en lista, objetivo validado con `ip_in_cidr`.
- XML a `var/scans/scan-<perfil>-<ip>-<epoch>.xml`, directorio `700`, archivo `600`.
- Parseo con **`defusedxml`**; se elimina el `DOCTYPE` por regex antes de parsear.
- Solo se guardan puertos `open` (protocolo, servicio, versión concatenada).
- Un fallo de nmap no mata el hilo: se registra en `scans`, en `tool_status` y, tras 3
  fallos consecutivos, genera `tool_failure` (`warn`).

Programación automática (`_schedule_scans`, tras cada barrido):

1. primer avistamiento (sin `last_scan_ts`) → `standard`;
2. equipo `confiable` cuyo último `standard` correcto (`store.last_scan_ts`) supera
   `weekly_rescan_days` → `standard` (RF-10). Se **escalona**: como mucho
   `max_concurrent` por barrido y del más atrasado al más reciente, para que una red que
   estuvo días apagada no lance una ráfaga de nmap;
3. cualquier equipo cuyo último escaneo supera `quick_periodic_hours` → `quick`;
4. nada que hacer → no se encola nada.

El coalescing lo hacen `_pending` (una IP+perfil en vuelo) y el índice único parcial de
`scan_requests`. Los escaneos manuales del panel entran por `scan_requests` y los reclama
el hilo principal.

Al aplicar resultados (`store.apply_scan_ports(..., protocolos=..., perfil=...)`) se calcula el
diff y se generan:

- `port_risky` (`warn`) para puertos del catálogo nuevos, que pasan a riesgosos o que
  **reaparecen tras un cierre real** (TCP y UDP).
- `port_new` (`warn`) solo si el equipo es `confiable` y el puerto no estaba (o estaba
  cerrado y ha vuelto).
- Los puertos que desaparecen de un protocolo **explorado** pasan a `closed` (sin evento).

**Cerrar un puerto es una afirmación y sólo la hacen `standard` y `vuln`.** `quick` usa `-F`
(≈100 puertos TCP): su silencio sobre el resto no es evidencia de cierre, así que únicamente
abre y actualiza. Sin esta regla se formaba el ciclo `standard → quick → standard`, en el que
un puerto fuera del top 100 se marcaba `closed` en cada `quick` y volvía a abrirse después
(el panel mentía; el evento `port_new` no se repetía porque `new_ports` exigía que no hubiera
fila previa). Contrapartida asumida: un cierre real puede tardar hasta el siguiente
`standard` (semanal por defecto) en reflejarse. Sin perfil explícito —llamadores internos y
tests de diff— se conserva el comportamiento histórico de cerrar.

---

## 16. Instalación y despliegue

### 16.1 Instalador (`install.sh`)

Multi-distro, sin código específico de distribución. Lee `/etc/os-release` y elige
gestor por `ID`/`ID_LIKE` (apt, dnf, pacman, zypper, apk); si no reconoce, usa el
primer gestor presente.

```bash
bash install.sh                  # comprueba entorno, crea var/, .env (600), BD, doctor
bash install.sh --install-deps   # instala nmap/arp-scan/iproute2 y módulos Python
bash install.sh --venv           # crea .venv e instala el paquete ahí (PEP 668)
bash install.sh --systemd        # unidades systemd (root)
bash install.sh --venv --link    # enlaza `batrade` en ~/.local/bin (o /usr/local/bin)
```

Hace, en orden: distro/gestor → herramientas del sistema → Python ≥ 3.11 → venv opcional
→ verifica `yaml, flask, requests, defusedxml, scapy` → directorios + `.env` → `batrade init`
→ `interfaces` → `doctor` → systemd opcional → enlace opcional. No es destructivo.

**Instalación de sistema (`--system`)**, pensada para una VM de pruebas:

```bash
sudo bash install.sh --system                       # destino /opt/batrade
sudo bash install.sh --system --prefix /srv/batrade --dry-run
sudo bash install.sh --system --install-deps --start
sudo bash install.sh --uninstall [--purge --yes] [--dry-run]
```

- Exige root (`id -u == 0`); si no, dice «ejecuta con sudo» y sale con 1.
- Copia el repo con `scripts/sync_tree.sh`, que excluye `.git`, `var/`, `.venv` y `.env` y
  **no pisa** `config.yaml`, `.env` ni `var/` en una reinstalación (rsync con `--delete`
  limitado por exclusiones; sin rsync usa `tar`, que no poda archivos obsoletos).
- Crea `.venv` dentro del prefix, instala el paquete editable, genera `.env` (600) si falta,
  ejecuta `init`, `interfaces` y `doctor`, y escribe un **wrapper** en `$BATRADE_BIN_DIR`
  (por defecto `/usr/local/bin`) que fija `BATRADE_ROOT=<prefix>` y hace `exec` del binario
  del venv: así funciona desde cualquier directorio y también con instalaciones no editables.
  Avisa si ese directorio no está en `PATH` (sudo suele usar `secure_path`).
- `--dry-run` imprime el plan sin crear ni modificar nada. `--start` arranca sensor y panel.
- `--uninstall` se niega si hay un componente vivo, quita el wrapper y el código y conserva
  `var/`, `.env` y `config.yaml`; `--purge` los borra tras exigir la palabra `BORRAR`
  (`--yes` para automatizar).
- `BATRADE_TEST_FAKE_ROOT=1` sólo existe para las pruebas del propio instalador: evita la
  comprobación de root sin tocar nada del sistema.

### 16.2 systemd

`deploy/batrade-sensor.service`:

- `User=batrade`, sin shell, `WorkingDirectory=/opt/batrade`.
- `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN`, `NoNewPrivileges=false`.
- `ProtectSystem=strict`, `ProtectHome=true`, `ReadWritePaths=/opt/batrade/var`.
- `Restart=on-failure`, `RestartSec=5`, `TimeoutStopSec=20`.

`deploy/batrade-dashboard.service`: sin capabilities, `NoNewPrivileges=true`, mismas
protecciones, `After=batrade-sensor.service`.

El instalador reescribe `WorkingDirectory`, `ReadWritePaths` y `ExecStart` con la ruta y
el intérprete reales, crea el usuario `batrade` si falta y le da `var/`. **No habilita**
las unidades: hay que `systemctl enable --now batrade-sensor batrade-dashboard`.

`ProtectHome=true` implica que el servicio **no puede** ejecutarse desde `/home`; la ruta
recomendada es `/opt/batrade`. Con el proyecto en `/home`, usar el control por CLI
(`batrade start/stop`) o moverlo.

### 16.3 Control sin systemd (`batrade/daemon.py`)

`start` lanza `python -m batrade <sensor|dashboard>` con `start_new_session=True`,
stdin `/dev/null` y stdout/stderr a `var/log/<componente>.out`; PID en
`var/<componente>.pid`.

- `pid_of()` valida que el PID esté vivo (ignora zombis) y que `/proc/<pid>/cmdline`
  contenga `batrade` y el nombre del componente → nunca mata un PID reciclado.
- `stop` envía SIGTERM al **grupo** si el proceso es líder de sesión (así muere un nmap
  hijo), espera 8 s y escala a SIGKILL.
- `start` es idempotente y, si el hijo muere en 0,6 s, imprime las últimas líneas del log.
- El sensor instala manejadores de SIGTERM/SIGINT para cerrar ordenadamente (heartbeat
  `stopped`, SQLite cerrado).

---

## 17. Pruebas y fixtures

```bash
.venv/bin/python -m pytest          # 196 tests, ~5 s, offline y sin privilegios
.venv/bin/python -m pytest tests/test_rules.py -v
```

Configuración (`pyproject.toml`): `pythonpath = ["."]`, `testpaths = ["tests"]`,
`addopts = "-q"`, `DeprecationWarning` ignorado. Con `-q` dos veces no se imprime el
resumen; usar `-p no:cacheprovider` o quitar `-q` para verlo. CI:
`.github/workflows/tests.yml` ejecuta la misma suite en Python 3.11, 3.12 y 3.13.

| Archivo | Cubre |
|---|---|
| `test_engine.py` | Bucle de observación, throttle, aislamiento de reglas |
| `test_rules.py` | Cada regla con observaciones sintéticas (positivas y negativas) |
| `test_scenarios.py` | Generación de escenarios y pipeline de replay |
| `test_inventory.py` | Upsert, transiciones de confianza, approve-baseline |
| `test_store.py` | Todas las funciones del repositorio sobre SQLite en memoria |
| `test_notify.py` | Canales, reintentos, dedupe |
| `test_dashboard.py` | Rutas Flask, autenticación, escrituras |
| `test_config.py` / `test_config_netauto.py` | Carga, validación, autodetección de red |
| `test_ifaces.py` | Parseo `ip` JSON/texto, orden de selección, bridges virtuales |
| `test_oui.py` | Fallbacks y formatos arp-scan/ieee-data |
| `test_daemon.py` | PID files, rechazo de PIDs ajenos/obsoletos, ciclo start/stop |
| `test_sensor_stop.py` | Parada idempotente y cierre de la base |
| `test_parsers.py` | Parseo de salida arp-scan y XML de nmap |
| `test_iputil.py` | Normalización/validación de IP y MAC |
| `test_migrations.py` | Runner de migraciones: v1→v2 con datos, idempotencia, copia, fallo atómico |
| `test_scan_schedule.py` | `_schedule_scans`: primer avistamiento, quick, semanal, escalonado |
| `test_scan_profiles.py` | `quick_timeout`/`standard_timeout` y validación de rangos |
| `test_udp_scan.py` | argv UDP con y sin raw, fixture XML, `open|filtered`, `port_risky` UDP |
| `test_verification.py` | Estados `no_verificable` / `sin_respuesta` / confirmado / descartado |
| `test_verify_pool.py` | Cota de concurrencia del pool de verificación ARP |
| `test_retention.py` | Purga de la cola y XML, contención de rutas y symlinks |
| `test_doctor.py` | Versión de esquema y latido legible en `doctor` |

`tests/conftest.py` ofrece: `cfg` (YAML mínimo con `interface: lo`, `cidr 10.10.10.0/24`,
`scan.enabled: false`, `arp_verify: false`), `conn`, `oui`, `baseline`, `engine`,
constructores `arp(...)` y `syn(...)`, y constantes `/10.10.10.x/` coherentes con los
escenarios.

`fixtures/pcaps/`: `arp_spoof`, `arp_sweep`, `dhcp_rogue`, `router_reboot`, `syn_scan`,
`mixed`. Se regeneran sin privilegios con `python3 scripts/make_fixtures.py` (usan
`simulate` + scapy `wrpcap`).

**Cómo añadir una regla:** clase con `name` y `evaluate(obs, state, baseline, cfg)`;
añadirla a `RULES`; añadir tests positivos y negativos; si necesita estado, meterlo en
`EngineState` con cota explícita.

---

## 18. Convenciones e invariantes

Si algo de esta lista se rompe, se rompe el diseño (y probablemente tests):

1. **Solo detección.** Nada de bloquear, inyectar ni remediar.
2. **Timestamps en milisegundos UTC** en toda la base y en memoria (`now_ms()`).
3. **Todo el SQL vive en `store.py`.** `db.py` solo define esquema y conexión.
4. **Las reglas son puras:** sin I/O, sin base, sin red. Reciben y devuelven datos.
5. **El motor no escribe en la base ni notifica.** Solo evalúa, limita y devuelve.
6. **El dashboard solo escribe** alias/confianza, `scan_requests` y `disposicion`.
7. **Un solo escritor del SQLite** (el sensor). WAL para lectores.
8. **Cada hilo, su conexión** (`threading.local` en el sensor, `g` en Flask).
9. **Estado en memoria siempre acotado** (`max_per_key`, `max_keys`, `max_bindings`).
10. **Sin `shell=True`** en subprocess; objetivos validados contra el CIDR.
11. **XML externo siempre con `defusedxml`.**
12. **Secretos solo en `.env`**, referenciados por nombre de variable desde YAML.
13. **Degradar, no morir:** la falta de privilegios nunca impide arrancar (salvo
    replay/simulate sin scapy).
14. **Migraciones aditivas**; nunca destructivas automáticas.
15. **Idioma:** dominio en español (`dispositivo`, `confianza`, `severidad`, `disparo`),
    infraestructura en inglés. Comentarios y mensajes de usuario en español.
16. **Tests offline**, sin red, sin privilegios, deterministas (`BASE_TS` fijo).

---

## 19. Limitaciones conocidas y deuda técnica

Estado tras el saneamiento v0.2 y la iteración de instalación/reset. Lo resuelto se marca
como tal; lo abierto sigue abierto.

**Resuelto en v0.2**

1. ~~Los puertos UDP del catálogo nunca se escanean~~ → pasada `-sU -sV --version-light`
   acotada con `CAP_NET_RAW`, sólo `open`, `port_risky` también para UDP y nota en `/health`
   sin raw (§15).
2. ~~Tres claves de configuración muertas~~ → `quick_timeout`, `quick_periodic_hours`,
   `weekly_rescan_days` y ahora `udp_timeout` están cableadas y validadas (§11, §15).
3. ~~En `degraded` el evento quedaba `verified=0` sin bloque `verificacion`~~ → ahora se
   guarda `{"estado": "no_verificable", "motivo": …}` y, si la sonda no obtuvo respuesta,
   `{"estado": "sin_respuesta"}`; el panel muestra etiquetas distintas.
4. ~~No hay migraciones reales~~ → runner versionado con `PRAGMA user_version`, una
   transacción por migración y copia `<db>.bak-v<N>` previa (§6).
5. ~~La retención no cubría la cola ni los XML~~ → purga `enviado`/`agotado` (nunca
   `pendiente`) y los XML de escaneos purgados, con contención de ruta.
6. ~~Un hilo efímero por verificación ARP~~ → pool fijo de `VERIFY_WORKERS = 4` con cola
   acotada (`VERIFY_QUEUE_MAX = 64`); la alerta nunca se pierde.
7. ~~`quick` cerraba puertos que no había explorado~~ → sólo `standard` y `vuln` cierran;
   `quick` abre y actualiza. Un puerto que reaparece tras un cierre real sí genera evento
   (§15).
8. ~~No había forma segura de limpiar la base tras sembrar simulaciones~~ → `reset-db`
   (sólo CLI y root, sensor parado, confirmación escrita, copia previa, `--keep-devices` y
   `--keep-logs`). No está expuesto en el panel y nunca es automático.
9. ~~Instalación sólo desde el repositorio y dependiente del directorio actual~~ →
   `install.sh --system` + `scripts/sync_tree.sh` y resolución de raíz
   `--root` > `BATRADE_ROOT` > paquete instalado (§16.1).
10. ~~Pulido menor~~ → `doctor` imprime el latido legible, el usuario efectivo y un bloque
    «Prueba en VM»; se eliminaron el import sin uso de `Config` y la variable `net`.
11. ~~`CONTEXT.md` desincronizado sin aviso~~ → lleva cabecera que lo declara histórico.

**Funcionalidad con matices**

12. **`approve_baseline` deja fuera las MAC aleatorias** por diseño; el panel lo indica con
    `pendientes` (C7).
13. **UDP sólo es verificable con `CAP_NET_RAW`, y sólo es fiable con `-sV`.** Un servicio
    que ignore las sondas de versión seguirá apareciendo `open|filtered` y, por diseño, no
    genera evento. La validación real contra un equipo con SSDP/mDNS está pendiente en la VM.
14. **Un cierre real tarda hasta el siguiente `standard`** (semanal por defecto) en
    reflejarse: `quick` ya no cierra puertos. Es el precio de no marcar como cerrado lo que
    no se ha explorado.
15. **La instalación de sistema no hace `chown` de `var/`.** Si el CLI corre como root
    sobre un `var/` de otro usuario (p. ej. el del servicio), los archivos nuevos quedan a
    nombre de root; `doctor` lo advierte. Decisión: no tocar la propiedad automáticamente.

**Cobertura y visibilidad**

16. **Un solo interfaz y solo IPv4.** Sin IPv6 ni multi-interfaz. Fuera de alcance.
17. **Wi-Fi en modo managed:** el sniffer solo ve tráfico propio y broadcast/multicast. Es
    una limitación física; `doctor` avisa también si la interfaz parece de hipervisor.
18. **El barrido no alimenta el motor:** `_sweep_loop` pasa por inventario, no por reglas.

**Modelo de datos y mantenimiento**

19. **No se guarda tráfico.** Solo hallazgos y metadatos; no hay retención de `.pcap`.
20. **Sin API JSON.** El panel devuelve HTML. Para integraciones, `batrade export`.
21. **Sin `LICENSE`.** Decisión pendiente del propietario; el README remite a él.
22. **Versión del paquete en `0.1.0`.** La subida a `0.2.0` sigue pendiente de aprobación.

**Operación**

23. **Un solo sensor por base de datos.** El CLI se niega a arrancar si la unidad systemd
    está activa, pero dos CLI en máquinas distintas contra la misma base siguen siendo
    responsabilidad del operador (`busy_timeout` lo mitiga, no lo resuelve).
24. **`stop` espera 8 s por componente** y luego SIGKILL; un nmap `vuln` en curso puede
    quedar cortado (la fila se marca `interrumpido` al siguiente arranque).
25. **Sin autenticación por usuario** en el panel: un token compartido y sesión.
26. **`ProtectHome=true`** en las unidades impide ejecutar desde `/home`; tanto el
    instalador como el README lo avisan y ofrecen `/opt/batrade` o `batrade start/stop`.
27. **Sin rsync, la reinstalación no poda archivos obsoletos** (`tar` no tiene `--delete`).
    Funcional, pero un archivo retirado del repo puede quedarse en el prefix.

---

## 20. Guía de intervención para el agente

### 20.1 Antes de tocar nada

1. `git status` y `git log -3`: el árbol debe estar limpio; el saneamiento vive en la
   rama `chore/saneamiento-v0.2`, un commit por fase.
2. `.venv/bin/python -m pytest` → **196 verdes** (línea base histórica: 134). Si no,
   no es tu cambio.
3. `batrade doctor` para conocer el entorno (interfaz, CIDR, modo efectivo, capacidades,
   versión de esquema y edad del latido).
4. Leer `CONTEXT.md` **solo como histórico**; contrastar siempre con el código.
5. No leer, imprimir ni copiar `.env`, `var/batrade.db`, `var/batrade.db.bak-*`,
   `var/alerts.log` ni `var/scans/*.xml` a conversaciones, prompts o commits.

### 20.2 Dónde tocar según la tarea

| Quiero… | Archivos |
|---|---|
| Añadir/cambiar una detección | `detect/rules.py` + `detect/state.py` (si hay estado) + `tests/test_rules.py` |
| Cambiar umbrales por defecto | `config.yaml` + defaults en `config.py` + `tests/conftest.py` si afecta tests |
| Cambiar el mensaje de alerta | `detect/rules.py` o `inventory.py` (`resumen`/`por_que`/`accion`) y `notify.py` (formato) |
| Añadir un canal de notificación | `notify.py` (`send_*`, `_deliver`), validación en `config.py`, `.env.example`, README |
| Cambiar el esquema | `db.py` (nueva entrada en `MIGRATIONS`) + `store.py` + tests en `test_migrations.py` |
| Añadir una ruta al panel | `dashboard/app.py` + plantilla en `templates/` + `static/style.css` |
| Cambiar la selección de interfaz | `net/ifaces.py` + `test_ifaces.py` + `test_config_netauto.py` |
| Cambiar descubrimiento | `net/discovery.py`, `net/neigh.py`, `test_parsers.py` |
| Cambiar escaneo/perfiles | `net/nmap_scan.py` + `tests/test_parsers.py` |
| Cambiar ciclo de vida | `daemon.py` + `cli.py` + `tests/test_daemon.py` |
| Cambiar installer/distro | `install.sh`, `deploy/*.service`, README |
| Demo/datos de ejemplo | `demo.py`, `detect/scenarios.py`, `scripts/make_fixtures.py` |

### 20.3 Checklist antes de dar algo por terminado

- [ ] `pytest` sigue en verde (y añadiste test para lo nuevo).
- [ ] Si tocaste configuración: `doctor` sigue funcionando y los errores son legibles.
- [ ] Si tocaste la BD: `init` sobre una base existente no rompe (probarlo con copia).
- [ ] Si tocaste la red: probado en modo `degraded` (sin privilegios) y con `replay`.
- [ ] Si tocaste mensajes: siguen respondiendo "qué pasó / por qué / qué hacer".
- [ ] Sin secretos nuevos en el repo; `.env.example` actualizado por nombre.
- [ ] `README.md` actualizado si cambia el uso; no hace falta tocar `CONTEXT.md`.
- [ ] Comentarios y mensajes en español, coherentes con el resto.

### 20.4 Trampas concretas

- **No metas lógica de base de datos fuera de `store.py`.** Rompe el contrato y complica
  los tests.
- **No hagas que una regla lance.** El motor la captura, pero el test debe demostrar el
  camino feliz.
- **No uses `datetime.now()` para persistir.** Todo va en `now_ms()` (epoch ms).
- **No ordenes por `ts` cuando quieras "lo más reciente":** en `events` lo correcto es
  `last_ts` (el evento se fusiona y avanza).
- **No añadas estado sin cota.** El diseño asume memoria estable 24 h.
- **No cambies la severidad de un tipo sin revisar `events.persist_findings`**, que
  decide notificación y modo aprendizaje.
- **`network.cidr` debe venir normalizado**; `192.168.0.5/24` es un error de configuración.
- **`op` en ARP es `request`/`reply`**, no `1`/`2` (eso es scapy).
- **El panel no debe escribir eventos**; si necesitas algo así, va por `scan_requests` o
  por el sensor.

---

## 21. Glosario de requisitos

El código referencia un PRD que **no está en el repositorio**. Traducción de los
identificadores que aparecen en comentarios:

| ID | Tema |
|---|---|
| RF-01 | Descubrimiento periódico de la subred (barrido) |
| RF-02 | Identificación de fabricante por OUI, sin internet |
| RF-04 | Línea base / modo aprendizaje |
| RF-05 | Detección de presencia y ausencia de equipos |
| RF-06 | Identidad de equipos con MAC aleatoria |
| RF-07 | Perfiles de escaneo (rápido / estándar) |
| RF-08 | Catálogo de puertos riesgosos |
| RF-09 | Escaneo de vulnerabilidades bajo demanda |
| RF-10 | Reescaneo periódico de equipos confiables |
| RF-11 | Verificación activa de ARP spoofing |
| RF-12 | Detección de ARP spoofing, barrido ARP y escaneo SYN |
| RF-13 | Detección de DHCP rogue |
| RF-15 | Notificaciones (Telegram/Discord/local) |
| RF-16 | Deduplicación y cooldown de alertas |
| RF-17 | Panel web de revisión |
| RNF-01 | Concurrencia limitada de nmap |
| RNF-02 | Memoria acotada en ejecuciones largas |
| RNF-03 | Nada hardcodeado: todo configurable |
| RNF-05 | Seguridad: SQL parametrizado, sin shell, XML endurecido, token si se expone |
| RNF-06 | Retención de datos |
| RNF-07 | Logging estructurado con rotación |
| RNF-09 | Reproducibilidad: replay/simulate para demostrar sin privilegios |
| C1 | El panel solo escribe tres cosas |
| C2 | La verificación ARP no bloquea la alerta |
| C4 | MAC aleatoria ≠ MAC localmente administrada |
| C6 | La ráfaga ARP exige conflicto real |
| C7 | No aprobar en lote equipos dudosos |
| C9 | Ventanas de estado con cota |
| PA-05 | Falso positivo a evitar: reinicio de router |
| PA-08 | Autoexclusión del propio sensor |

---

## 22. Manejo seguro de datos sensibles

Este proyecto maneja datos de una red doméstica real. Reglas para cualquier agente:

**Nunca** copiar a prompts, documentos, commits, issues o capturas:

- Contenido de `.env` (tokens de Telegram, webhook de Discord, token del panel).
- `var/batrade.db` y sus copias `var/batrade.db.bak-v*` / `var/batrade.db.bak-reset-*`
  (inventario real: MACs, IPs, hostnames, historial). Las copias son tan sensibles como el
  original.
- `var/alerts.log` (eventos con IP/MAC reales).
- `var/scans/*.xml` (puertos y versiones reales de los equipos).
- `var/log/*.log` / `*.out` (pueden incluir IPs, MACs y errores internos).

**Buenas prácticas**

- Citar variables de entorno **solo por nombre**.
- Usar el modo `demo`, `fixtures/pcaps/` y `fixtures/nmap/` (direcciones ficticias
  `10.10.10.x` o `192.168.1.x` de escenario) para ejemplos.
- Si hace falta mostrar salida, anonimizar MACs (`xx:xx:...`) e IPs (`192.168.0.x`).
- Mantener `.env` con permisos `600`; el instalador ya lo hace. Las copias
  `batrade.db.bak-v*` se crean con `600` y no deben copiarse fuera de `var/`.
- No añadir secretos a `config.yaml`: la validación no los lee de ahí y quedarían en git.

**Datos ficticios ya presentes en el repo (seguros):** `tests/conftest.py` usa
`10.10.10.0/24`; `detect/scenarios.py` usa `GW_MAC 00:0c:29:1b:2c:3d`,
`ATTACKER_MAC aa:bb:cc:00:11:22`, `VICTIM_MAC 3c:22:fb:11:22:33`,
`SENSOR_MAC 00:50:56:ee:00:03` y ancla temporal `BASE_TS = 1_760_000_000_000`;
`fixtures/nmap/udp_scan.xml` describe `10.10.10.50` («lab-tv.local») con 1900/udp
`open`, 5353/udp `open|filtered` y 68/udp `closed`.

---

## Anexo A — Referencia rápida de la CLI

```
batrade [--config FILE] [--root DIR] [--version] <comando> [opciones]

  doctor            Diagnóstico: red, modo efectivo, usuario, capacidades, BD, latido
  init              Crea/actualiza BD y directorios; guarda gateway/modo/interfaz
  interfaces|ifaces Lista interfaces IPv4 con tipo, estado, IP/CIDR, MAC y ruta por defecto
  start             Arranca sensor y dashboard en segundo plano
                    --only sensor|dashboard   --mode auto|live|degraded
  stop              Detiene ambos             --only sensor|dashboard
  restart           Reinicia ambos            --only sensor|dashboard
  status            PIDs, latido, usuario efectivo, modo real, URL del panel
  sensor            Demonio en primer plano
                    --mode auto|live|degraded|replay|simulate
                    --scenario arp_spoof|arp_sweep|syn_scan|dhcp_rogue|router_reboot|mixed
                    --pcap FILE   --speed N (def. 5.0)   --duration SEG
  dashboard         Panel en primer plano     --host H   --port P
  demo              Siembra escenarios        --scenarios "mixed,router_reboot"
  approve-baseline  Marca confiables          --include-random-mac
  reset-db          Vacía datos y artefactos (sólo root; sensor detenido)
                    --keep-devices  --keep-logs  --no-backup  --yes
  export            Exporta datos            --what devices|events|ports
                                             --format csv|json   --out FILE
```

`--root` no es obligatorio: la raíz se resuelve como `--root` > `BATRADE_ROOT` >
directorio del paquete instalado, así que el comando funciona desde cualquier directorio
(el wrapper de `/usr/local/bin` que crea `install.sh --system` fija `BATRADE_ROOT`).

Códigos de salida: `0` OK, `1` error de ejecución (daemon/interfaz) o negativa de
`reset-db`, `2` configuración/argumentos inválidos, `130` interrupción por teclado.

## Anexo B — Archivos de runtime

```
var/
  batrade.db, batrade.db-wal, batrade.db-shm   base SQLite (WAL)
  batrade.db.bak-v<N>[, -2, -3...]             copia previa a migrar (600, nunca se pisa)
  batrade.db.bak-reset-<epoch_ms>[-2...]       copia previa a reset-db (600, nunca se pisa)
  sensor.pid, dashboard.pid                    PIDs del control por CLI
  alerts.log                                   alertas locales (600)
  scans/scan-<perfil>-<ip>-<epoch>.xml         salida de nmap (700/600)
  log/batrade.log                              JSONL rotado 2 MB × 5
  log/sensor.out, log/dashboard.out            stdout/stderr de los procesos en background
```

La pasada UDP escribe un `scans/scan-udp-<ip>-<epoch_ms>.xml` temporal que se borra en
cuanto se vuelcan sus puertos: la fila de `scans` sólo referencia el XML del escaneo TCP.
La retención elimina los XML de los escaneos purgados, siempre dentro de `paths.scans_dir`.

## Anexo C — Frases de una línea para orientarse

- "Batrade observa, no toca la red."
- "Todo se normaliza a `Observation`; el motor no sabe de dónde viene."
- "Un hallazgo es un `Finding`; un `Finding` se convierte en evento con dedupe."
- "El sensor escribe; el panel lee y solo toca tres campos."
- "Si faltan privilegios, se degrada y lo dice."
- "Los timestamps son milisegundos desde epoch, siempre."
- "Las reglas son puras; el estado tiene cota; el SQL vive en `store.py`."

---

*Fin del documento. Actualizado tras el saneamiento v0.2 (rama `chore/saneamiento-v0.2`,
seis commits sobre `3675a39`), con verificación de la suite de pruebas (201/201), de
`batrade doctor` y del entorno de ejecución de la máquina de referencia.*
