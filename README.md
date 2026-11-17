# Batrade Home-SOC

Batrade is a passive intrusion detection system for home and small-office networks. It monitors the local LAN, maintains a device inventory, detects known threat patterns, and delivers alerts via Telegram, Discord, or a local log file. It never blocks traffic.

## What it detects

- ARP spoofing (MAC-IP binding conflicts, gateway impersonation)
- ARP sweep / host enumeration
- SYN port scans
- Rogue DHCP servers
- Router reboots (gateway MAC change)
- New or unauthorized devices joining the network
- Risky open ports on known devices (Telnet, RDP, VNC, UPnP, and others)

## Supported distributions

Batrade has no distribution-specific code. It only shells out to `iproute2` (`ip`), `nmap` and, optionally, `arp-scan`, so it runs on any modern Linux. The installer detects the distribution from `/etc/os-release` and picks the matching package manager:

| Family | Distributions | Manager | Packages |
|---|---|---|---|
| Debian | Debian, Ubuntu, Kali, Parrot, Mint, Pop!_OS | `apt` | `nmap arp-scan iproute2 python3 python3-venv python3-yaml python3-flask python3-requests python3-defusedxml python3-scapy` |
| Fedora / RHEL | Fedora, RHEL, CentOS Stream, Rocky, AlmaLinux | `dnf` | `nmap arp-scan iproute python3 python3-pyyaml python3-flask python3-requests python3-defusedxml python3-scapy` |
| Arch | Arch, BlackArch, Manjaro | `pacman` | `nmap arp-scan iproute2 python python-pyyaml python-flask python-requests python-defusedxml python-scapy` |
| openSUSE | Leap, Tumbleweed, SLES | `zypper` | `nmap arp-scan iproute2 python3 python3-PyYAML python3-Flask python3-requests python3-defusedxml python3-scapy` |
| Alpine | Alpine (edge) | `apk` | `nmap arp-scan iproute2 python3 py3-yaml py3-flask py3-requests py3-defusedxml py3-scapy` |

Requirements:

- Python 3.11 or later
- Linux with `nmap` and `iproute2` (`ip` ships with every desktop/server distribution)
- `arp-scan` for full live mode (optional — the sensor degrades gracefully without it)
- Python packages: `PyYAML`, `Flask`, `requests`, `defusedxml`, `scapy`

Python packages can come from the distribution or from a virtualenv. On distributions that mark the system interpreter as externally managed (PEP 668: Fedora, recent Debian/Ubuntu, Arch), use the `--venv` installer flag.

## Installation

```bash
bash install.sh                  # checks the environment and initializes the database
bash install.sh --install-deps   # also installs nmap/arp-scan/iproute2 with the detected manager
bash install.sh --venv           # creates .venv and installs the project there
bash install.sh --systemd        # installs the systemd units (root required)
bash install.sh --venv --link    # also links `batrade` into ~/.local/bin (or /usr/local/bin)
```

The installer:

1. detects the distribution and package manager (apt, dnf, pacman, zypper, apk);
2. reports missing system tools and, with `--install-deps`, installs them;
3. verifies the Python modules (system interpreter or `.venv`);
4. creates `var/`, `.env` (mode 600) and the SQLite database;
5. lists the detected network interfaces and runs `doctor`.

Manual installation is equivalent:

```bash
# Debian / Ubuntu / Kali / Parrot
sudo apt install -y nmap arp-scan iproute2 python3 python3-venv python3-yaml python3-flask python3-requests python3-defusedxml python3-scapy

# Fedora / RHEL / Rocky / Alma
sudo dnf install -y nmap arp-scan iproute python3 python3-pyyaml python3-flask python3-requests python3-defusedxml python3-scapy

# Arch / BlackArch
sudo pacman -S --needed nmap arp-scan iproute2 python python-pyyaml python-flask python-requests python-defusedxml python-scapy

# openSUSE
sudo zypper install nmap arp-scan iproute2 python3 python3-PyYAML python3-Flask python3-requests python3-defusedxml python3-scapy

# Python (cualquier distribución, aislado del sistema)
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
```

## Network auto-detection (Ethernet and Wi-Fi)

The default `config.yaml` needs no editing:

```yaml
network:
  interface: auto   # eth0, enp3s0, wlp2s0, wlan0... chosen at startup
  cidr: auto        # derived from the interface address and netmask
  gateway_ip: null  # taken from the default route
```

Selection order:

1. the interface named in `network.interface`, when set explicitly;
2. the interface carrying the IPv4 default route (unless it is a VPN or virtual bridge);
3. a wired interface with a private IPv4 address, preferring Ethernet over Wi-Fi;
4. any non-virtual interface with IPv4. Docker, libvirt, veth and tailscale bridges are ignored.

`cidr: auto` derives a normalized CIDR (for example `192.168.0.0/24`) from the chosen interface. `gateway_ip: null` adopts the default route only when it belongs to the monitored subnet; otherwise the gateway stays unset and the dashboard says so.

List the interfaces with their kind, address, MAC and whether they carry the default route:

```bash
batrade interfaces
```

```
INTERFAZ      TIPO      ESTADO  IP/CIDR             MAC                RUTA
eth0          ethernet  up      192.168.0.50/24     00:1a:2b:3c:4d:5e  defecto
wlp2s0        wi-fi     up      10.0.0.20/24        aa:bb:cc:00:11:33
vmnet19       ethernet  up      192.168.150.1/24    00:0c:29:1b:2c:3d
lo            loopback  up      127.0.0.1/8         00:00:00:00:00:00
```

To monitor a specific network, set the name explicitly and keep `cidr` automatic:

```yaml
network:
  interface: vmnet19
  cidr: auto
```

For example, `interface: wlp2s0` monitors the wireless LAN even when Ethernet carries the default route; use the wired name (`eth0`, `enp3s0`, `eno1`) when the cable is the network under watch.

Wi-Fi works for discovery and netlink monitoring, but a managed-mode card cannot capture other clients' unicast traffic. Passive sniffing only sees the sensor's own traffic and broadcast/multicast frames; use a wired port mirror or a monitor-mode interface when full packet visibility is required. `doctor` prints a warning when the selected interface is wireless.

## Quick start

Install once with the virtualenv and the PATH link:

```bash
bash install.sh --venv --link
```

This creates `.venv`, installs the package, initializes the database and links `batrade` into `~/.local/bin` (the installer warns if that directory is not in `PATH`). The rest of this section uses plain `batrade`. Without `--link`, activate the environment (`source .venv/bin/activate`) or use `.venv/bin/batrade`; `python3 -m batrade` is equivalent.

**1. Check what will be monitored.**

```bash
batrade interfaces
batrade doctor
```

`interfaces` lists every IPv4 interface with its kind (Ethernet, Wi-Fi, loopback), address and whether it carries the default route. `doctor` shows the interface, subnet, gateway and sensor mode. The installer already initialized the database; `batrade init` is safe to repeat if needed.

**2. Start both components in the background.**

```bash
batrade start
batrade status
```

`start` launches the sensor and the dashboard detached, with PID files in `var/` and logs in `var/log/`. `status` prints both PIDs, the sensor heartbeat age and the panel URL. Open **http://127.0.0.1:8000**:

| Route | Content |
|---|---|
| `/` | Summary: devices online, unknown/unauthorized, alerts today, latest events |
| `/devices` | Inventory with trust state, vendor, hostname, last seen |
| `/events` | Alert history with severity and false-positive marking |
| `/health` | Sensor heartbeat, capabilities, interface/subnet, tool status |
| `/learning` | Baseline review and `approve-baseline` button |

Check it without a browser:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8000/health
```

Stop or restart with `batrade stop` / `batrade restart`. Use `--only sensor` or `--only dashboard` to control one component, and `start --mode degraded` to force a sensor mode. If a component dies immediately (for example because port 8000 is taken), `start` prints the last lines of its log.

**3. Run in the foreground (optional).** Use two terminals; Ctrl+C stops each component.

```bash
batrade sensor       # prints the selected mode and interface
batrade dashboard    # http://127.0.0.1:8000
```

`auto` uses `live` when `CAP_NET_RAW` and `arp-scan` are available, otherwise `degraded` (netlink neighbor table + nmap TCP connect). The dashboard listens only on loopback by default; use `--host` / `--port` to change it, and exposing it beyond loopback requires `DASHBOARD_TOKEN` in `.env` (configuration validation refuses to start otherwise).

Logs live in `var/log/`: `sensor.out` / `dashboard.out` (console copy) and `batrade.log` (JSONL, rotated). Alerts append to `var/alerts.log` when the local channel is enabled and the event is warn/crit.

**4. Try the demo without any privileges** (does not touch the network). Stop the sensor first if it shares the same database:

```bash
batrade stop
batrade demo
batrade dashboard
```

`demo` seeds the database with synthetic detection scenarios so the dashboard shows realistic data without requiring network access.

**What to expect on first run:** devices appear in `/devices` after the first sweep (immediately at startup, then every 30 s by default), new-device events are `info` while learning mode is active, and alerts only start once a `warn`/`crit` pattern is detected. Review the inventory and run `batrade approve-baseline` to end learning mode.

## Sensor modes

| Mode | Requires | Description |
|---|---|---|
| `live` | `CAP_NET_RAW`, `arp-scan` | Passive packet sniffing + active ARP sweep |
| `degraded` | nothing extra | Netlink neighbor table + nmap TCP connect scan |
| `replay` | `scapy` | Feeds the detection engine from a recorded `.pcap` file |
| `simulate` | `scapy` | Feeds the engine with built-in synthetic scenarios |
| `auto` | - | Picks `live` or `degraded` based on available capabilities |

Check what mode will be used and why:

```bash
batrade doctor
```

## CLI reference

```
batrade <command> [options]

Commands:
  doctor            Check environment capabilities and configuration
  init              Create the database and required directories
  interfaces        List detected IPv4 interfaces (alias: ifaces)
  start             Start sensor and dashboard in the background
  stop              Stop both components
  restart           Restart both components
  status            Show PIDs, heartbeat age and dashboard URL
  sensor            Run the monitoring daemon in the foreground
  dashboard         Serve the web dashboard in the foreground
  demo              Seed the database with demonstration scenarios
  approve-baseline  Mark all current devices as trusted
  export            Export devices, events, or ports as CSV or JSON

Global options:
  --config FILE     Path to config.yaml (default: config.yaml)
  --root DIR        Project root (default: current directory)
  --version         Print version and exit
```

The installer links this console script into `PATH` (`--link`); without it, use `.venv/bin/batrade` or `python3 -m batrade`.

## Alerts

The sensor supports three notification channels, configured under `notify.channels` in `config.yaml`:

- `local` — always active; appends plain-text alerts to `var/alerts.log`
- `telegram` — sends a message to a Telegram chat; requires `TELEGRAM_TOKEN` and `TELEGRAM_CHAT_ID` in `.env`
- `discord` — posts to a Discord webhook; requires `DISCORD_WEBHOOK` in `.env`

Copy `.env.example` to `.env`, fill in the credentials you want to use, and restrict permissions:

```bash
cp .env.example .env
chmod 600 .env
```

## Production deployment

The `deploy/` directory contains two systemd unit files:

- `batrade-sensor.service` — runs the sensor daemon with `CAP_NET_RAW` and `CAP_NET_ADMIN`
- `batrade-dashboard.service` — serves the Flask dashboard

Install them with:

```bash
sudo bash install.sh --systemd
```

The installer rewrites `WorkingDirectory`, `ReadWritePaths` and `ExecStart` for the real install path and the Python being used (system or `.venv`). It also creates the `batrade` service user when missing and gives it ownership of `var/`. The recommended install path is `/opt/batrade`; systemd hardening sets `ProtectHome=true`, so a project under `/home` cannot be used by the service.

If the dashboard is exposed beyond loopback, set `DASHBOARD_TOKEN` in `.env` to require token authentication.

## Troubleshooting

- **`network.interface inexistente`** — run `batrade interfaces` and copy a real name, or leave `interface: auto`.
- **No detection at all** — run `batrade doctor`: without `CAP_NET_RAW` the passive sniffer and `arp-scan` are unavailable, so the sensor runs in `degraded` mode. For full mode grant the capability (the systemd unit does) or run as root in a lab VM.
- **Wi-Fi sees little traffic** — expected in managed mode; see the Wi-Fi note above.
- **`externally-managed-environment` from pip** — use `bash install.sh --venv` or `pip install --user`.
- **Fedora/RHEL with SELinux** — a custom unit runs unconfined by default; if you add a policy, allow read access to the install path and write access to `var/`.
- **No vendor names** — Batrade uses a local OUI file and falls back across the usual nmap, arp-scan and Wireshark locations. Install `nmap` or `arp-scan` to populate it; vendor names are cosmetic.
- **Dashboard shows a stale gateway** — the sensor stores the learned gateway in `network_baseline`; rerun `batrade init` after changing networks.

## Running tests

```bash
pip install -e ".[dev]"    # pytest; on distribution-managed systems use a venv
python3 -m pytest
```

Tests cover the detection engine, detection rules, inventory logic, notification queue, database store, dashboard routes, configuration loading, interface auto-detection and network utilities. They run entirely offline using synthetic observations and fixtures from `fixtures/pcaps/`.

## Project layout

```
batrade/           Python package
  cli.py           Entry point and subcommand handlers
  daemon.py        Background start/stop/status of sensor and dashboard
  sensor.py        Monitoring daemon (multi-threaded)
  inventory.py     Device tracking and trust management
  notify.py        Alert dispatch with retry and deduplication
  db.py            SQLite schema and initialization
  store.py         Data access layer
  config.py        Configuration loading and validation
  events.py        Finding persistence helpers
  detect/          Detection subsystem
    engine.py      Rule orchestration and throttling
    rules.py       Stateless detection rules
    state.py       Sliding-window state for the rules
    scenarios.py   Synthetic traffic for tests and demo
    sniffer.py     Passive packet capture (live mode)
    observation.py Normalized packet representation
  net/             Network utilities
    caps.py        Capability detection and mode resolution
    ifaces.py      IPv4 interface discovery (Ethernet/Wi-Fi) and selection
    discovery.py   Host sweep (arp-scan / netlink fallback)
    nmap_scan.py   Port scanning wrapper
    neigh.py       Netlink neighbor table reader
    verify.py      Active ARP binding verification
    oui.py         OUI vendor lookup (multi-distro paths)
    iputil.py      IP/MAC normalization helpers
  dashboard/       Flask web dashboard
    app.py         Routes and view logic
    templates/     Jinja2 HTML templates
    static/        CSS
deploy/            Systemd service units
fixtures/pcaps/    Recorded network captures for tests
scripts/           Development utilities
tests/             pytest test suite
config.yaml        Main configuration
install.sh         Multi-distro installer and environment check
.env.example       Secret variable template
```

## License

See [LICENSE](LICENSE) if present, or contact the author.
