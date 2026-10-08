"""
Leviathan OSINT v4.0 — Microkernel 1: Crawler
Priority queue · Token bucket · Circuit Breaker · TLS fingerprinting
"""
from __future__ import annotations
import asyncio
import heapq
import logging
import time
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

from core.models import Target, EntityRecord, EntityType, BusEvent, EventType
from core.smart_request import smart_get, smart_post
from core.consensus_engine import ConsensusEngine
from core.event_bus import EventBus

if TYPE_CHECKING:
    from core.models import ModuleResult

log = logging.getLogger("leviathan.k1")


@dataclass(order=True)
class ModuleTask:
    priority: int
    module_id: str = field(compare=False)
    module_name: str = field(compare=False)
    target: Any = field(compare=False)


import itertools as _itertools

class K1Crawler:
    """
    Microkernel 1 — Crawler HTTP asíncrono.
    Gestiona la ejecución de módulos con priority queue y concurrencia controlada.
    """

    def __init__(
        self,
        bus:         EventBus,
        consensus:   ConsensusEngine,
        max_concurrent: int = 10,
        use_tor:     bool = False,
        proxy:       str | None = None,
        human_mode:  bool = True,
    ):
        self.bus         = bus
        self.consensus   = consensus
        self.max_concurrent = max_concurrent
        self.use_tor     = use_tor
        self.proxy       = proxy
        self.human_mode  = human_mode
        self._queue:     list[ModuleTask] = []
        self._semaphore  = asyncio.Semaphore(max_concurrent)
        self._pending    = 0
        self._inflight   = 0
        self._processed  = 0
        self._latencies: list[float] = []
        self._deprecated: set[str] = set()
        self._enqueue_counter = _itertools.count()

    def enqueue(self, module, target: Target, priority: int = 5):
        """Encolar módulo para ejecución."""
        task = ModuleTask(
            priority=priority,
            module_id=module.MODULE_ID,
            module_name=module.MODULE_NAME,
            target=target,
        )
        heapq.heappush(self._queue, (priority, next(self._enqueue_counter), module, task))
        self._pending += 1

    def mark_deprecated(self, module_id: str):
        self._deprecated.add(module_id)

    async def run_all(self, target: Target, scan_id: str) -> list[EntityRecord]:
        """Ejecutar todos los módulos en cola concurrentemente."""
        all_entities: list[EntityRecord] = []
        tasks = []

        while self._queue:
            _pri, _cnt, module, task = heapq.heappop(self._queue)
            if task.module_id in self._deprecated:
                log.debug(f"Skipping deprecated module: {task.module_id}")
                self._pending -= 1
                continue
            tasks.append(self._run_module(module, target, scan_id, all_entities))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        return all_entities

    async def _run_module(
        self,
        module,
        target:    Target,
        scan_id:   str,
        collector: list[EntityRecord],
    ):
        async with self._semaphore:
            self._pending  -= 1
            self._inflight += 1
            t0 = time.time()

            await self.bus.emit(EventType.MODULE_STARTED, {
                "module_id":   module.MODULE_ID,
                "module_name": module.MODULE_NAME,
            }, scan_id=scan_id)

            try:
                raw_entities = await module.run(target)
                entities_confirmed = []

                for raw in raw_entities:
                    record = self.consensus.process(
                        entity_type=raw.get("type", EntityType.OTHER),
                        value=raw.get("value", ""),
                        sources=raw.get("sources", []),
                        metadata=raw.get("metadata", {}),
                        module_id=module.MODULE_ID,
                        scan_id=scan_id,
                    )
                    collector.append(record)
                    entities_confirmed.append(record)

                    evt = EventType.ENTITY_CONFIRMED if record.verdict.value != "DISCARD" else EventType.ENTITY_REJECTED
                    await self.bus.emit(evt, {
                        "entity_id":  record.id,
                        "type":       record.type.value,
                        "value":      record.value,
                        "confidence": record.confidence,
                        "verdict":    record.verdict.value,
                        "flags":      record.flags,
                        "sources":    record.sources,
                    }, scan_id=scan_id, source_id=module.MODULE_ID)

                elapsed = (time.time() - t0) * 1000
                self._latencies.append(elapsed)

                await self.bus.emit(EventType.MODULE_DONE, {
                    "module_id":   module.MODULE_ID,
                    "module_name": module.MODULE_NAME,
                    "entities":    len(raw_entities),
                    "confirmed":   len(entities_confirmed),
                    "duration_ms": elapsed,
                }, scan_id=scan_id)

            except asyncio.TimeoutError:
                await self.bus.emit(EventType.MODULE_FAILED, {
                    "module_id":   module.MODULE_ID,
                    "module_name": module.MODULE_NAME,
                    "error":       "timeout",
                }, scan_id=scan_id)
            except Exception as e:
                log.error(f"Module {module.MODULE_ID} error: {e}", exc_info=True)
                await self.bus.emit(EventType.MODULE_FAILED, {
                    "module_id":   module.MODULE_ID,
                    "module_name": module.MODULE_NAME,
                    "error":       str(e),
                }, scan_id=scan_id)
            finally:
                self._inflight  -= 1
                self._processed += 1

    @property
    def stats(self) -> dict:
        avg_lat = sum(self._latencies[-20:]) / max(1, len(self._latencies[-20:]))
        return {
            "pending":   self._pending,
            "inflight":  self._inflight,
            "processed": self._processed,
            "avg_latency_ms": avg_lat,
        }
