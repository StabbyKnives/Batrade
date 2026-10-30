"""Estado del motor: línea base y ventanas deslizantes acotadas (RNF-02 / C9).

Todas las estructuras tienen cota explícita. Un sniffer que crece sin límite
hunde el KPI de memoria de 24 h, así que aquí no hay listas infinitas.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field


class TimeWindow:
    """Cuenta elementos por clave dentro de una ventana temporal.

    Cada clave guarda como máximo ``max_per_key`` muestras. El número total de
    claves se poda cuando excede ``max_keys``.
    """

    __slots__ = ("span_ms", "max_per_key", "max_keys", "_items", "_last")

    def __init__(self, span_ms: int, max_per_key: int = 400, max_keys: int = 4000):
        self.span_ms = span_ms
        self.max_per_key = max_per_key
        self.max_keys = max_keys
        self._items: dict[str, deque[tuple[int, str | int | None]]] = {}
        self._last: dict[str, int] = {}

    def add(self, key: str, ts: int, value: str | int | None = None) -> int:
        """Añade una muestra y devuelve el número de muestras vigentes."""
        dq = self._items.get(key)
        if dq is None:
            if len(self._items) >= self.max_keys:
                self._trim(ts)
            dq = deque(maxlen=self.max_per_key)
            self._items[key] = dq
        cutoff = ts - self.span_ms
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        dq.append((ts, value))
        self._last[key] = ts
        return len(dq)

    def values(self, key: str, ts: int) -> list[str | int | None]:
        dq = self._items.get(key)
        if not dq:
            return []
        cutoff = ts - self.span_ms
        return [v for t, v in dq if t >= cutoff]

    def distinct(self, key: str, ts: int) -> int:
        return len({v for v in self.values(key, ts) if v is not None})

    def count(self, key: str, ts: int) -> int:
        return len(self.values(key, ts))

    def _trim(self, now_ts: int) -> None:
        """Descarta las claves más antiguas hasta bajar del 80 % de la cota."""
        target = int(self.max_keys * 0.8)
        for key, _ in sorted(self._last.items(), key=lambda kv: kv[1])[: max(1, len(self._last) - target)]:
            self._items.pop(key, None)
            self._last.pop(key, None)
        self._last = {k: v for k, v in self._last.items() if k in self._items}

    def prune(self, now_ts: int, idle_ms: int | None = None) -> int:
        """Elimina claves inactivas. Devuelve cuántas se descartaron."""
        idle = idle_ms if idle_ms is not None else self.span_ms * 4
        cutoff = now_ts - idle
        stale = [k for k, t in self._last.items() if t < cutoff]
        for k in stale:
            self._items.pop(k, None)
            self._last.pop(k, None)
        return len(stale)

    def __len__(self) -> int:
        return len(self._items)


@dataclass(slots=True)
class Binding:
    """Asociación IP -> MAC observada, con su historial mínimo."""

    ip: str
    mac: str
    first_ts: int
    last_ts: int
    count: int = 1
    in_baseline: bool = False

    @property
    def age_ms(self) -> int:  # pragma: no cover - conveniencia
        return self.last_ts - self.first_ts


@dataclass(slots=True)
class Baseline:
    """Contexto de red que las reglas necesitan para distinguir ataque de ruido."""

    gateway_ip: str | None = None
    gateway_mac: str | None = None
    dhcp_server_ip: str | None = None
    sensor_ips: set[str] = field(default_factory=set)
    sensor_macs: set[str] = field(default_factory=set)
    exceptions: set[str] = field(default_factory=set)
    learning: bool = True
    last_sweep_ts: int = 0


class SynTracker:
    """Ventanas de SYN para RF-12 con memoria acotada."""

    def __init__(self, span_ms: int, max_per_key: int = 600, max_keys: int = 4000):
        self.span_ms = span_ms
        self.max_per_key = max_per_key
        self.max_keys = max_keys
        self._ports: dict[tuple[str, str], deque[tuple[int, int]]] = {}
        self._dsts: dict[str, deque[tuple[int, str]]] = {}

    def add(self, src: str, dst: str, port: int, ts: int) -> tuple[int, int]:
        """Devuelve (puertos distintos al mismo destino, destinos distintos del origen)."""
        cutoff = ts - self.span_ms
        key = (src, dst)
        dq = self._ports.get(key)
        if dq is None:
            if len(self._ports) >= self.max_keys:
                self._ports.pop(next(iter(self._ports)), None)
            dq = deque(maxlen=self.max_per_key)
            self._ports[key] = dq
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        dq.append((ts, port))
        distinct_ports = len({p for _, p in dq})

        dq_dst = self._dsts.get(src)
        if dq_dst is None:
            if len(self._dsts) >= self.max_keys:
                self._dsts.pop(next(iter(self._dsts)), None)
            dq_dst = deque(maxlen=self.max_per_key)
            self._dsts[src] = dq_dst
        while dq_dst and dq_dst[0][0] < cutoff:
            dq_dst.popleft()
        dq_dst.append((ts, dst))
        distinct_dsts = len({d for _, d in dq_dst})
        return distinct_ports, distinct_dsts

    def prune(self, now_ts: int, idle_ms: int | None = None) -> int:
        cutoff = now_ts - (idle_ms or self.span_ms * 4)
        removed = 0
        for key in [k for k, dq in self._ports.items() if not dq or dq[-1][0] < cutoff]:
            self._ports.pop(key, None)
            removed += 1
        for src in [s for s, dq in self._dsts.items() if not dq or dq[-1][0] < cutoff]:
            self._dsts.pop(src, None)
            removed += 1
        return removed

    def __len__(self) -> int:
        return len(self._ports) + len(self._dsts)


@dataclass(slots=True)
class EngineState:
    span_ms: int
    bindings: dict[str, Binding] = field(default_factory=dict)
    max_bindings: int = 4096
    # MAC -> IPs reclamadas en la ventana (regla "una MAC, varias IPs")
    mac_claims: TimeWindow = field(init=False)
    arp_replies: TimeWindow = field(init=False)
    arp_requests: TimeWindow = field(init=False)
    conflicts: TimeWindow = field(init=False)
    syn: SynTracker = field(init=False)

    def __post_init__(self) -> None:
        self.mac_claims = TimeWindow(self.span_ms, max_per_key=40, max_keys=2048)
        self.arp_replies = TimeWindow(self.span_ms, max_per_key=200, max_keys=2048)
        self.arp_requests = TimeWindow(self.span_ms, max_per_key=200, max_keys=2048)
        self.conflicts = TimeWindow(self.span_ms * 3, max_per_key=40, max_keys=1024)
        self.syn = SynTracker(self.span_ms)

    def binding(self, ip: str) -> Binding | None:
        return self.bindings.get(ip)

    def learn_binding(self, ip: str, mac: str, ts: int) -> Binding:
        b = self.bindings.get(ip)
        if b is None:
            if len(self.bindings) >= self.max_bindings:
                self._evict_oldest()
            b = Binding(ip=ip, mac=mac, first_ts=ts, last_ts=ts)
            self.bindings[ip] = b
        else:
            b.last_ts = ts
            b.count += 1
        return b

    def _evict_oldest(self) -> None:
        oldest = min(self.bindings.items(), key=lambda kv: kv[1].last_ts, default=None)
        if oldest:
            self.bindings.pop(oldest[0], None)

    def prune(self, now_ts: int) -> None:
        for w in (self.mac_claims, self.arp_replies, self.arp_requests, self.conflicts):
            w.prune(now_ts)
        self.syn.prune(now_ts)
        cutoff = now_ts - max(self.span_ms * 120, 3_600_000)
        stale = [ip for ip, b in self.bindings.items() if b.last_ts < cutoff]
        for ip in stale:
            self.bindings.pop(ip, None)

    def snapshot(self) -> dict[str, int]:
        return {
            "bindings": len(self.bindings),
            "mac_claims": len(self.mac_claims),
            "arp_replies": len(self.arp_replies),
            "arp_requests": len(self.arp_requests),
            "syn": len(self.syn),
        }
