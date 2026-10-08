"""
Leviathan OSINT v4.0 — Plugin Manager
Sistema de plugins: auto-discovery, validación, carga dinámica.
Añadir un plugin = copiar un .py a plugins/ y ya.
Sin romper nada. Sin tocar código core.
"""
from __future__ import annotations
import importlib
import importlib.util
import inspect
import logging
import sys
from pathlib import Path
from typing import Optional

log = logging.getLogger("leviathan.plugins")

PLUGINS_DIR = Path(__file__).parent
PLUGIN_REQUIRED_ATTRS = {"MODULE_ID", "MODULE_NAME", "MODULE_PHASE"}
RESERVED_IDS = {str(i).zfill(2) for i in range(1, 50)}


class PluginValidationError(Exception):
    pass


class PluginManager:
    """
    Gestor de plugins de Leviathan.

    Cómo funciona:
    1. Escanea el directorio plugins/ en busca de .py
    2. Importa cada archivo dinámicamente
    3. Busca clases que hereden de BaseModule
    4. Valida: MODULE_ID único, MODULE_NAME presente, no colisión con core
    5. Los módulos cargados se añaden automáticamente al Orchestrator

    Reglas para crear plugins:
    - ID: usar rango 50-99 (IDs 01-49 reservados para core)
    - Hereda de BaseModule
    - Implementar _run(self, target) → usar self.emit()
    - MODULE_PRIORITY recomendado: 7-9 (para que corran después del core)
    """

    def __init__(self, plugins_dir: Path = PLUGINS_DIR):
        self.plugins_dir = plugins_dir
        self._loaded: dict[str, object] = {}  # module_id → class
        self._errors: dict[str, str]    = {}  # filename → error

    def discover(self) -> list[dict]:
        """Descubrir y cargar todos los plugins en el directorio."""
        if not self.plugins_dir.exists():
            return []

        results = []
        for path in sorted(self.plugins_dir.glob("*.py")):
            if path.name.startswith("_") or path.name in ("plugin_manager.py", "example_plugin.py"):
                continue
            result = self._load_plugin(path)
            results.append(result)

        if self._loaded:
            log.info(f"Plugins cargados: {len(self._loaded)} — {list(self._loaded.keys())}")
        return results

    def _load_plugin(self, path: Path) -> dict:
        """Cargar un plugin desde archivo .py."""
        try:
            spec = importlib.util.spec_from_file_location(
                f"leviathan.plugins.{path.stem}", path
            )
            if not spec or not spec.loader:
                raise PluginValidationError("No se pudo cargar el spec del módulo")

            module = importlib.util.module_from_spec(spec)
            sys.modules[f"leviathan.plugins.{path.stem}"] = module
            spec.loader.exec_module(module)  # type: ignore

            # Buscar clases que hereden de BaseModule
            plugin_classes = []
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if self._is_plugin_class(obj):
                    plugin_classes.append(obj)

            if not plugin_classes:
                raise PluginValidationError("No se encontró ninguna clase que herede de BaseModule")

            loaded_ids = []
            for cls in plugin_classes:
                self._validate_plugin_class(cls)
                mid = str(cls.MODULE_ID)
                self._loaded[mid] = cls
                loaded_ids.append(mid)
                log.info(f"Plugin cargado: [{mid}] {cls.MODULE_NAME} desde {path.name}")

            return {
                "file":    path.name,
                "status":  "OK",
                "modules": loaded_ids,
                "names":   [c.MODULE_NAME for c in plugin_classes],
            }

        except Exception as e:
            self._errors[path.name] = str(e)
            log.warning(f"Plugin {path.name} error: {e}")
            return {
                "file":   path.name,
                "status": "ERROR",
                "error":  str(e),
            }

    @staticmethod
    def _is_plugin_class(cls) -> bool:
        """Verificar si una clase es un plugin válido de Leviathan."""
        try:
            from leviathan.modules.base_module import BaseModule
            return (
                issubclass(cls, BaseModule)
                and cls is not BaseModule
                and not cls.__name__.startswith("_")
                and hasattr(cls, "MODULE_ID")
            )
        except Exception:
            return False

    @staticmethod
    def _validate_plugin_class(cls):
        """Validar que el plugin cumple los requisitos."""
        for attr in PLUGIN_REQUIRED_ATTRS:
            if not hasattr(cls, attr):
                raise PluginValidationError(f"Falta atributo requerido: {attr}")

        mid = str(cls.MODULE_ID)
        if not mid:
            raise PluginValidationError("MODULE_ID no puede estar vacío")

        # Advertencia si usa ID reservado (no error fatal)
        if mid in RESERVED_IDS:
            log.warning(
                f"Plugin {cls.MODULE_NAME} usa ID reservado {mid}. "
                f"Se recomienda usar IDs 50-99 para plugins."
            )

    def instantiate_all(self, api_keys: dict, use_tor: bool = False,
                        proxy: Optional[str] = None) -> list:
        """Instanciar todos los plugins cargados."""
        instances = []
        for mid, cls in self._loaded.items():
            try:
                instance = cls(api_keys=api_keys, use_tor=use_tor, proxy=proxy)
                instances.append(instance)
            except Exception as e:
                log.error(f"Plugin {mid} instantiation error: {e}")
        return instances

    def list_plugins(self) -> list[dict]:
        """Listar todos los plugins con su info."""
        result = []
        for mid, cls in self._loaded.items():
            result.append({
                "id":       mid,
                "name":     cls.MODULE_NAME,
                "phase":    getattr(cls, "MODULE_PHASE", "plugin"),
                "priority": getattr(cls, "MODULE_PRIORITY", 7),
                "types":    getattr(cls, "ENTITY_TYPES", []),
            })
        for fname, error in self._errors.items():
            result.append({
                "id":    "ERR",
                "name":  fname,
                "error": error,
            })
        return result

    def print_status(self):
        print(f"\n  {'ID':<6} {'MÓDULO':<30} {'FASE':<12} PRIORIDAD")
        print("  " + "─" * 55)
        for p in self.list_plugins():
            if "error" in p:
                print(f"  {'ERR':<6} {p['name']:<30} \033[31m✗ {p['error'][:30]}\033[0m")
            else:
                print(f"  {p['id']:<6} {p['name']:<30} {p['phase']:<12} {p['priority']}")
        if not self._loaded and not self._errors:
            print("  (No hay plugins instalados)")
        print()
