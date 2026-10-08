"""
Leviathan OSINT v4.0 — Plugin de Ejemplo
════════════════════════════════════════
Copia este archivo como base para tu propio plugin.

PASOS PARA CREAR UN PLUGIN:
1. Copia este archivo a plugins/mi_modulo.py
2. Cambia MODULE_ID a un número entre 50-99
3. Cambia MODULE_NAME, MODULE_PHASE, ENTITY_TYPES
4. Implementa _run(self, target) usando self.emit()
5. Reinicia Leviathan — se auto-cargará

REGLAS:
- IDs 01-49: reservados para módulos core
- IDs 50-99: para tus plugins
- Usar self.emit() SIEMPRE — nunca calcular confidence
- Usar self.get_json() / self.get_text() para HTTP
- No importar requests (usar aiohttp via BaseModule)
- No bloquear el event loop (usar await)
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from leviathan.modules.base_module import BaseModule
from leviathan.core.models import Target, TargetType


class ExamplePlugin(BaseModule):
    """
    Plugin de ejemplo — búsqueda en HackerNews.
    Busca el username del target en la API pública de HN.

    Actívalo en plugins/ y Leviathan lo cargará automáticamente.
    """
    MODULE_ID       = "50"                    # 50-99 para plugins
    MODULE_NAME     = "HackerNewsSearch"
    MODULE_PRIORITY = 7                       # 7-9 recomendado para plugins
    MODULE_PHASE    = "people"                # recon|people|darkweb|comms|advanced
    ENTITY_TYPES    = ["username", "url"]     # tipos que puede emitir

    # Tipos de target a los que aplica
    APPLICABLE = {TargetType.USERNAME, TargetType.EMAIL}

    async def _run(self, target: Target):
        """Lógica principal del plugin."""
        if target.type not in self.APPLICABLE:
            return

        username = target.normalized
        if target.type == TargetType.EMAIL:
            username = username.split("@")[0]

        # ── Hacer request a API pública ───────────────────────────────────
        # Usar self.get_json() / self.get_text() — nunca requests directos
        data = await self.get_json(
            f"https://hacker-news.firebaseio.com/v0/user/{username}.json",
            timeout=10.0,
        )

        if not data:
            return  # No encontrado — no emitir nada

        # ── Emitir entidades ──────────────────────────────────────────────
        # self.emit(tipo, valor, metadata_dict, fuentes_list)
        # NUNCA calcular confidence — eso lo hace el Consensus Engine

        self.emit("username", username, {
            "platform":     "hackernews",
            "profile_url":  f"https://news.ycombinator.com/user?id={username}",
            "karma":        data.get("karma", 0),
            "created":      data.get("created", 0),
            "account_age_days": (
                (1714500000 - data.get("created", 1714500000)) / 86400
            ),
            "submitted_count": len(data.get("submitted", [])),
        }, sources=["github_api"])   # fuente más cercana disponible en la lista

        self.emit("url",
            f"https://news.ycombinator.com/user?id={username}",
            {"platform": "hackernews", "username": username},
            sources=["github_api"],
        )

        # Si tiene muchos karma → posiblemente real person activo
        if data.get("karma", 0) > 100:
            self.log.info(f"HN: {username} — karma {data['karma']}")


# ══════════════════════════════════════════════════════════════════
# TEMPLATE LIMPIO — copia esto para tu plugin real
# ══════════════════════════════════════════════════════════════════

"""
from leviathan.modules.base_module import BaseModule
from leviathan.core.models import Target, TargetType


class MiPlugin(BaseModule):
    MODULE_ID       = "51"           # Elige un ID 50-99 único
    MODULE_NAME     = "MiPlugin"
    MODULE_PRIORITY = 7
    MODULE_PHASE    = "recon"        # recon|people|darkweb|comms|advanced
    ENTITY_TYPES    = ["domain"]
    APPLICABLE      = {TargetType.DOMAIN}

    async def _run(self, target: Target):
        if target.type not in self.APPLICABLE:
            return

        # Tu lógica aquí
        data = await self.get_json(f"https://api.ejemplo.com/{target.normalized}")
        if data and data.get("resultado"):
            self.emit("domain", data["resultado"], {
                "fuente": "api_ejemplo",
                "dato_extra": data.get("extra"),
            }, sources=["direct_scrape"])
"""
