"""
Leviathan OSINT v4.0 — Base Module
Clase padre para todos los módulos. Solo emiten, nunca juzgan.
El Consensus Engine es quien decide la verdad.
"""
from __future__ import annotations
import asyncio
import logging
import time
from typing import Any
from core.models import Target, EntityType
from core.smart_request import smart_get, smart_post

log = logging.getLogger("leviathan.modules")

MODULE_TIMEOUT = 30.0  # segundos por módulo


class BaseModule:
    """
    Clase padre para todos los módulos Leviathan.

    Regla fundamental: Los módulos SOLO emiten entidades crudas.
    Nunca calculan confidence, nunca juzgan calidad.
    Todo el juicio está en el Consensus Engine.

    ```python
    # Así trabaja cualquier módulo:
    async def _run(self, target):
        data = await self.get_json("https://api.ejemplo.com/" + target.normalized)
        if data and data.get("email"):
            self.emit("email", data["email"], {"source": "api_ejemplo"})
        # Eso es todo.
    ```
    """

    MODULE_ID:       str = "00"
    MODULE_NAME:     str = "BaseModule"
    MODULE_PRIORITY: int = 5          # 1=alta, 10=baja
    MODULE_PHASE:    str = "recon"    # recon|people|darkweb|comms|advanced
    ENTITY_TYPES:    list[str] = []   # tipos de entidad que puede emitir
    REQUIRES_API:    bool = False
    REQUIRES_TOR:    bool = False

    def __init__(self, api_keys: dict[str, str] | None = None,
                 use_tor: bool = False, proxy: str | None = None):
        self.api_keys = api_keys or {}
        self.use_tor  = use_tor
        self.proxy    = proxy
        self._emitted: list[dict[str, Any]] = []
        self.log      = logging.getLogger(f"leviathan.mod.{self.MODULE_ID}")

    def emit(self, entity_type: str, value: str, metadata: dict | None = None,
             sources: list[str] | None = None):
        """
        Emitir una entidad cruda al sistema.
        Este es el ÚNICO método que los módulos deben usar para producir output.
        """
        if not value or not value.strip():
            return
        self._emitted.append({
            "type":      entity_type,
            "value":     value.strip(),
            "sources":   sources or [],
            "metadata":  metadata or {},
            "module_id": self.MODULE_ID,
        })

    async def run(self, target: Target) -> list[dict]:
        """Punto de entrada — llama a _run con timeout."""
        self._emitted.clear()
        try:
            await asyncio.wait_for(self._run(target), timeout=MODULE_TIMEOUT)
        except asyncio.TimeoutError:
            self.log.warning(f"Module {self.MODULE_ID} timed out on {target.normalized}")
        except Exception as e:
            self.log.error(f"Module {self.MODULE_ID} error: {e}", exc_info=False)
        return self._emitted

    async def _run(self, target: Target):
        """Implementar en subclases."""
        raise NotImplementedError

    # ─── Helpers de HTTP ──────────────────────────────────────────────────────

    async def get_json(self, url: str, params: dict | None = None,
                       headers: dict | None = None, timeout: float = 12.0) -> dict | None:
        """GET que devuelve JSON o None."""
        return await smart_get(
            url=url, module=self.MODULE_ID, params=params,
            headers=headers, timeout=timeout,
            tor=self.use_tor, proxy=self.proxy,
        )

    async def get_text(self, url: str, params: dict | None = None,
                       headers: dict | None = None) -> str | None:
        """GET que devuelve texto plano o None."""
        result = await smart_get(
            url=url, module=self.MODULE_ID, params=params,
            headers=headers, timeout=12.0,
            tor=self.use_tor, proxy=self.proxy,
        )
        if result and "_text" in result:
            return result["_text"]
        return None

    async def post_json(self, url: str, json: dict,
                        headers: dict | None = None) -> dict | None:
        """POST con body JSON."""
        return await smart_post(
            url=url, module=self.MODULE_ID, json=json, headers=headers
        )

    def key(self, name: str) -> str | None:
        """Obtener API key por nombre."""
        return self.api_keys.get(name)

    def has_key(self, name: str) -> bool:
        return bool(self.api_keys.get(name))
