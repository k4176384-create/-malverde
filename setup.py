#!/usr/bin/env python3
"""
Leviathan OSINT v4.0 — Setup automático
Crea directorios, verifica dependencias, inicializa base de datos.
"""
import os
import sys
import subprocess
from pathlib import Path

ROOT = Path(__file__).parent

DIRS = [
    "core", "modules/recon", "modules/people",
    "modules/darkweb", "modules/advanced",
    "utils", "api", "config",
    "database", "reports", "logs",
    "data/fasttext/models", "plugins",
]

REQUIRED = ["aiohttp", "rich", "networkx", "yaml"]
OPTIONAL = {
    "curl_cffi":     "TLS fingerprinting real (evitar bans Cloudflare)",
    "aiohttp_socks": "Soporte Tor y proxies SOCKS",
    "fastapi":       "REST API",
    "uvicorn":       "REST API server",
    "fasttext":      "FastText ML local",
    "pyvis":         "Grafos HTML standalone",
    "folium":        "Mapas de ubicación",
    "weasyprint":    "Export PDF",
}

RED    = "\033[31m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
RESET  = "\033[0m"


def banner():
    print(f"""
{RED}╔══════════════════════════════════════════════════╗
║   🐉  LEVIATHAN OSINT v4.0 — Setup              ║
╚══════════════════════════════════════════════════╝{RESET}
""")


def create_dirs():
    print(f"{CYAN}[1/4] Creando estructura de directorios...{RESET}")
    for d in DIRS:
        path = ROOT / d
        path.mkdir(parents=True, exist_ok=True)
        init = path / "__init__.py"
        if not init.exists() and d not in ("database", "reports", "logs", "data/fasttext/models", "plugins"):
            init.write_text("")
    print(f"  {GREEN}✔{RESET} Directorios creados\n")


def check_python():
    print(f"{CYAN}[2/4] Verificando Python...{RESET}")
    v = sys.version_info
    if v < (3, 10):
        print(f"  {RED}✗ Python {v.major}.{v.minor} — Se requiere 3.10+{RESET}")
        sys.exit(1)
    print(f"  {GREEN}✔{RESET} Python {v.major}.{v.minor}.{v.micro}\n")


def check_deps():
    print(f"{CYAN}[3/4] Verificando dependencias...{RESET}")
    missing_required = []
    for pkg in REQUIRED:
        try:
            __import__(pkg)
            print(f"  {GREEN}✔{RESET} {pkg}")
        except ImportError:
            print(f"  {RED}✗ {pkg} — REQUERIDO{RESET}")
            missing_required.append(pkg)

    print()
    for pkg, desc in OPTIONAL.items():
        try:
            __import__(pkg.replace("-", "_"))
            print(f"  {GREEN}✔{RESET} {pkg:<18} {desc}")
        except (ImportError, Exception):
            print(f"  {YELLOW}○{RESET} {pkg:<18} {desc} [opcional]")

    if missing_required:
        print(f"\n{RED}Dependencias requeridas faltantes:{RESET}")
        pkgs = " ".join(missing_required).replace("yaml", "pyyaml")
        print(f"  pip install {pkgs}")
        return False
    print()
    return True


def check_tools():
    print(f"{CYAN}[4/4] Verificando herramientas del sistema...{RESET}")
    tools = {
        "tor":    "Anonimato — sudo apt install tor",
        "fzf":    "Selector interactivo — sudo apt install fzf",
        "bat":    "Visualización de archivos — sudo apt install bat",
        "ollama": "LLM local — curl -fsSL https://ollama.ai/install.sh | sh",
    }
    for tool, hint in tools.items():
        found = subprocess.run(["which", tool], capture_output=True).returncode == 0
        icon  = f"{GREEN}✔{RESET}" if found else f"{YELLOW}○{RESET}"
        print(f"  {icon} {tool:<10} {hint if not found else 'instalado'}")
    print()


def init_config():
    config_path = ROOT / "config" / "config.yaml"
    if not config_path.exists():
        try:
            sys.path.insert(0, str(ROOT))
            from leviathan.config.api_manager import APIManager
            APIManager.generate_config_yaml(str(config_path))
        except Exception as e:
            print(f"  {YELLOW}○{RESET} config.yaml no generado ({e}) — ejecutar: python leviathan.py --init-config")
    else:
        print(f"  {GREEN}✔{RESET} config/config.yaml ya existe")


def main():
    banner()
    check_python()
    create_dirs()
    ok = check_deps()
    check_tools()
    init_config()

    print("─" * 52)
    if ok:
        print(f"""
{GREEN}✔ Setup completo. Leviathan listo.{RESET}

Uso rápido:
  {CYAN}python leviathan.py usuario@empresa.com{RESET}
  {CYAN}python leviathan.py empresa.com --tor{RESET}
  {CYAN}python leviathan.py --list-modules{RESET}
  {CYAN}python leviathan.py --apis{RESET}
  {CYAN}python leviathan.py --api{RESET}

Instalar dependencias base:
  {YELLOW}pip install aiohttp aiofiles rich networkx pyyaml{RESET}
""")
    else:
        print(f"\n{YELLOW}⚠ Instala las dependencias requeridas antes de continuar.{RESET}\n")
        print(f"  {YELLOW}pip install -r requirements.txt{RESET}\n")


if __name__ == "__main__":
    main()
