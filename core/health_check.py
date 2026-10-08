"""
Leviathan OSINT v4.0 — Health Check
Background checker. No bloquea scans. Corre 2 min después del primer scan.
3 fallos consecutivos → módulo DEPRECATED → excluido automáticamente.
"""
from __future__ import annotations
import asyncio
import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.microkernel3_storage import K3Storage

log = logging.getLogger("leviathan.health")

# Targets de control por tipo de módulo
CONTROL_TARGETS = {
    "recon":   "google.com",
    "people":  "torvalds",        # username real y estable
    "darkweb": "google.com",
    "comms":   "8.8.8.8",
    "advanced": "google.com",
}


@dataclass
class HealthResult:
    module_id:   str
    module_name: str
    status:      str   # OK | FAILING | DEPRECATED
    entities:    int
    duration_ms: float
    error:       str | None = None


class HealthChecker:
    """
    Corre en background. No interfiere con scans activos.
    Usa los mismos módulos pero contra targets de control inocuos.
    """

    def __init__(self, storage: "K3Storage", interval_hours: float = 24.0, max_failures: int = 3):
        self.storage      = storage
        self.interval     = interval_hours * 3600
        self.max_failures = max_failures
        self._task: asyncio.Task | None = None
        self._running = False

    def start(self, api_keys: dict, delay_s: float = 120.0):
        """Iniciar checker en background con delay inicial."""
        self._running = True
        self._task    = asyncio.create_task(self._loop(api_keys, delay_s))
        log.info(f"HealthChecker iniciado — primer check en {delay_s}s")

    def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()

    async def _loop(self, api_keys: dict, delay_s: float):
        await asyncio.sleep(delay_s)
        while self._running:
            await self.run_check(api_keys)
            await asyncio.sleep(self.interval)

    async def run_check(self, api_keys: dict) -> list[HealthResult]:
        """Ejecutar health check completo de todos los módulos."""
        from modules.recon.modules_01_08 import (
            PassiveDNS, WhoisRDAP, IP2ASN, SubdomainEnum,
            PortsServices, TechFingerprint, EmailPhoneHarvester,
        )
        from modules.people.modules_09_18 import (
            UsernameEnum, SocialScrape, LeaksPaste,
        )
        from core.models import Target, TargetType

        test_modules = [
            (PassiveDNS(api_keys=api_keys),    Target("google.com", "google.com", TargetType.DOMAIN)),
            (WhoisRDAP(api_keys=api_keys),     Target("google.com", "google.com", TargetType.DOMAIN)),
            (IP2ASN(api_keys=api_keys),        Target("8.8.8.8",   "8.8.8.8",   TargetType.IP)),
            (SubdomainEnum(api_keys=api_keys), Target("google.com", "google.com", TargetType.DOMAIN)),
            (PortsServices(api_keys=api_keys), Target("8.8.8.8",   "8.8.8.8",   TargetType.IP)),
            (TechFingerprint(api_keys=api_keys), Target("google.com", "google.com", TargetType.DOMAIN)),
            (UsernameEnum(api_keys=api_keys),  Target("torvalds",  "torvalds",  TargetType.USERNAME)),
            (SocialScrape(api_keys=api_keys),  Target("torvalds",  "torvalds",  TargetType.USERNAME)),
        ]

        results = []
        for module, target in test_modules:
            t0 = time.time()
            try:
                entities = await asyncio.wait_for(module.run(target), timeout=20.0)
                duration = (time.time() - t0) * 1000
                status   = "OK" if entities else "FAILING"
                result   = HealthResult(
                    module_id=module.MODULE_ID, module_name=module.MODULE_NAME,
                    status=status, entities=len(entities), duration_ms=duration,
                )
            except asyncio.TimeoutError:
                duration = (time.time() - t0) * 1000
                result   = HealthResult(
                    module_id=module.MODULE_ID, module_name=module.MODULE_NAME,
                    status="FAILING", entities=0, duration_ms=duration, error="timeout",
                )
            except Exception as e:
                duration = (time.time() - t0) * 1000
                result   = HealthResult(
                    module_id=module.MODULE_ID, module_name=module.MODULE_NAME,
                    status="FAILING", entities=0, duration_ms=duration, error=str(e)[:80],
                )

            self.storage.update_module_health(
                result.module_id, result.module_name,
                result.status, result.entities, result.duration_ms,
            )

            # Verificar si hay que deprecar
            deprecated = self.storage.get_deprecated_modules()
            if result.module_id in deprecated:
                result.status = "DEPRECATED"
                log.warning(f"Módulo {result.module_name} DEPRECATED — 3 fallos consecutivos")

            results.append(result)
            log.info(f"HealthCheck {result.module_name}: {result.status} ({result.entities} ents, {result.duration_ms:.0f}ms)")

        return results

    def print_status(self):
        """Imprimir estado de health check en consola."""
        conn = self.storage._conn_safe()
        rows = conn.execute("""
            SELECT module_id, module_name, status, consecutive_failures,
                   last_entities, last_duration_ms, last_checked
            FROM module_health ORDER BY module_id
        """).fetchall()

        if not rows:
            print("  No hay datos de health check. Corre un scan primero.")
            return

        print(f"\n  {'ID':<5} {'MÓDULO':<26} {'STATUS':<14} {'FALLOS':<8} {'ENTS':<6} {'MS':<7} HORA")
        print("  " + "─" * 75)
        for row in rows:
            mid, name, status, fails, ents, ms, ts = row
            ts_str = __import__("time").strftime("%H:%M:%S", __import__("time").localtime(ts)) if ts else "—"
            if status == "OK":
                icon = "\033[32m✔\033[0m"
            elif fails >= 3:
                icon = "\033[31m✗ DEPRECATED\033[0m"
            else:
                icon = f"\033[33m⚠ FAIL {fails}/3\033[0m"
            print(f"  {mid:<5} {name:<26} {icon:<14} {fails:<8} {ents:<6} {ms:<7.0f} {ts_str}")
        print()
