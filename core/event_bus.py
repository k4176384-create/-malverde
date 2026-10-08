"""
Leviathan OSINT v4.0 — Event Bus (pub/sub central)
"""
from __future__ import annotations
import asyncio
import logging
from collections import defaultdict
from typing import Callable, Awaitable
from core.models import BusEvent, EventType

log = logging.getLogger("leviathan.bus")


class EventBus:
    """
    Pub/Sub asíncrono central. Nadie habla con nadie directamente.
    Todo pasa por aquí.
    """

    def __init__(self):
        self._subs: dict[EventType, list[Callable[[BusEvent], Awaitable[None]]]] = defaultdict(list)
        self._wildcard: list[Callable[[BusEvent], Awaitable[None]]] = []
        self._history: list[BusEvent] = []
        self._lock = asyncio.Lock()
        self._stats: dict[str, int] = defaultdict(int)

    def subscribe(self, event_type: EventType, handler: Callable[[BusEvent], Awaitable[None]]):
        """Suscribirse a un tipo de evento específico."""
        self._subs[event_type].append(handler)

    def subscribe_all(self, handler: Callable[[BusEvent], Awaitable[None]]):
        """Suscribirse a TODOS los eventos (wildcard)."""
        self._wildcard.append(handler)

    async def publish(self, event: BusEvent):
        """Publicar evento a todos los suscriptores en paralelo."""
        async with self._lock:
            self._history.append(event)
            self._stats[event.type.value] += 1

        handlers = self._subs.get(event.type, []) + self._wildcard
        if not handlers:
            return

        tasks = [asyncio.create_task(h(event)) for h in handlers]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, r in enumerate(results):
            if isinstance(r, Exception):
                log.error(f"Handler error on {event.type.value}: {r}")

    async def emit(self, event_type: EventType, payload: dict, scan_id: str = "", source_id: str = ""):
        """Shortcut para publicar sin construir BusEvent manualmente."""
        await self.publish(BusEvent(
            type=event_type,
            payload=payload,
            scan_id=scan_id,
            source_id=source_id,
        ))

    def get_history(self, scan_id: str = "", event_type: EventType | None = None) -> list[BusEvent]:
        """Obtener historial de eventos, con filtros opcionales."""
        result = self._history
        if scan_id:
            result = [e for e in result if e.scan_id == scan_id]
        if event_type:
            result = [e for e in result if e.type == event_type]
        return result

    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    def clear_history(self):
        self._history.clear()
        self._stats.clear()
