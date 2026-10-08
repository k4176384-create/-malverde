#!/usr/bin/env python3
"""
🐉 Leviathan OSINT Framework v4.0
Creado por Luis Sánchez

"OSINT puro primero. La IA es el complemento, no la dependencia."

Consensus Engine · Event Bus · 3 Microkernels · 37+ Módulos
FastText ML · SelfLearning · HealthCheck · Plugin System
Dashboard Leviathan Abyss (Rich) o Textual (mouse + tabs)

⚠ AVISO LEGAL:
Usar exclusivamente para investigaciones legales con autorización explícita.
El usuario es el único responsable del uso de esta herramienta.
"""
from __future__ import annotations
import argparse
import asyncio
import logging
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

LOG_DIR = ROOT / "logs"
LOG_DIR.mkdir(exist_ok=True)

log_level = getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO)
logging.basicConfig(
    level=log_level,
    format="%(asctime)s [%(name)s] %(levelname)s — %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / f"leviathan_{time.strftime('%Y%m%d')}.log"),
        logging.StreamHandler(sys.stderr),
    ],
)
log = logging.getLogger("leviathan.main")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="leviathan",
        description="🐉 Leviathan OSINT Framework v4.0 — Creado por Luis Sánchez",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python leviathan.py usuario@empresa.com
  python leviathan.py empresa.com --tor --llm
  python leviathan.py "+52 664 123 4567" --textual
  python leviathan.py "Juan García López" --deep-multimodal
  python leviathan.py 8.8.8.8 --no-tui --output json
  python leviathan.py --batch targets.txt
  python leviathan.py --api --port 8000
  python leviathan.py --list-modules
  python leviathan.py --list-plugins
  python leviathan.py --apis
  python leviathan.py --ft-status
  python leviathan.py --ft-train
  python leviathan.py --health-check
  python leviathan.py --init-config
        """,
    )

    # Target (opcional — puede usarse sin target para acciones de info)
    p.add_argument("target", nargs="?", help="Target: email, teléfono, dominio, IP, username, nombre, wallet, placa, onion...")

    # ── TUI ───────────────────────────────────────────────────────────────────
    tui_grp = p.add_argument_group("TUI / Display")
    tui_grp.add_argument("--no-tui",    action="store_true", help="Solo logs en consola (más rápido)")
    tui_grp.add_argument("--textual",   action="store_true", help="Usar Textual TUI (mouse, tabs, scroll) — pip install textual")
    tui_grp.add_argument("--output",    choices=["json","text","quiet"], default="text", help="Formato de output (sin TUI)")

    # ── Red / Anonimato ───────────────────────────────────────────────────────
    net_grp = p.add_argument_group("Red / Anonimato")
    net_grp.add_argument("--tor",       action="store_true", help="Usar Tor para anonimato (requiere tor corriendo)")
    net_grp.add_argument("--proxy",     metavar="URL",       help="Proxy URL: socks5://user:pass@host:port")
    net_grp.add_argument("--concurrency", type=int, default=int(os.environ.get("K1_CONCURRENCY","10")), help="Requests concurrentes (default: 10)")

    # ── Módulos especiales ────────────────────────────────────────────────────
    mod_grp = p.add_argument_group("Módulos especiales")
    mod_grp.add_argument("--llm",           action="store_true", help="Activar LLM local via Ollama")
    mod_grp.add_argument("--llm-model",     default="phi3:mini", metavar="MODEL", help="Modelo Ollama (default: phi3:mini)")
    mod_grp.add_argument("--llm-host",      default="http://localhost:11434", metavar="URL", help="Host Ollama")
    mod_grp.add_argument("--deep-multimodal", action="store_true",
                         help="Activar módulo 49 (EXIF + reverse image search) — requiere autorización sobre el target")

    # ── Plugins ───────────────────────────────────────────────────────────────
    plug_grp = p.add_argument_group("Plugins")
    plug_grp.add_argument("--plugins-dir",  default="plugins", metavar="DIR", help="Directorio de plugins (default: plugins/)")
    plug_grp.add_argument("--list-plugins", action="store_true", help="Listar plugins instalados")
    plug_grp.add_argument("--no-plugins",   action="store_true", help="Deshabilitar plugins")

    # ── Batch ─────────────────────────────────────────────────────────────────
    batch_grp = p.add_argument_group("Batch / API")
    batch_grp.add_argument("--batch",   metavar="FILE", help="Archivo de targets (txt/csv, uno por línea)")
    batch_grp.add_argument("--api",     action="store_true", help="Iniciar REST API (FastAPI)")
    batch_grp.add_argument("--port",    type=int, default=8000, help="Puerto REST API (default: 8000)")

    # ── FastText / ML ─────────────────────────────────────────────────────────
    ft_grp = p.add_argument_group("FastText ML")
    ft_grp.add_argument("--ft-status", action="store_true", help="Estado de modelos FastText")
    ft_grp.add_argument("--ft-train",  action="store_true", help="Forzar re-entrenamiento FastText")
    ft_grp.add_argument("--analyze-reports", metavar="DIR", help="Analizar carpeta de reportes + alimentar FastText")

    # ── Mantenimiento ─────────────────────────────────────────────────────────
    maint_grp = p.add_argument_group("Mantenimiento")
    maint_grp.add_argument("--list-modules",  action="store_true", help="Listar todos los módulos disponibles")
    maint_grp.add_argument("--apis",          action="store_true", help="Estado de APIs configuradas")
    maint_grp.add_argument("--init-config",   action="store_true", help="Generar config/config.yaml documentado")
    maint_grp.add_argument("--health-check",  action="store_true", help="Health check manual de módulos")
    maint_grp.add_argument("--reset-module",  metavar="ID",        help="Resetear módulo deprecated")
    maint_grp.add_argument("--db",            default="database/leviathan.db", metavar="PATH")
    maint_grp.add_argument("--reports-dir",   default="reports",   metavar="DIR")

    return p


RED   = "\033[31m"
CYAN  = "\033[36m"
BOLD  = "\033[1m"
RESET = "\033[0m"
DIM   = "\033[2m"

def print_banner():
    print(f"""
{RED}{BOLD}╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║      🐉  L E V I A T H A N   O S I N T   v 4 . 0               ║
║                                                                  ║
║              Creado por  L u i s  S á n c h e z                 ║
║                                                                  ║
╠══════════════════════════════════════════════════════════════════╣
║  Consensus Engine · Event Bus · 3 Microkernels · 37+ Módulos    ║
║  FastText ML · SelfLearning · Plugin System · Leviathan Abyss   ║
╚══════════════════════════════════════════════════════════════════╝{RESET}
{DIM}"OSINT puro primero. La IA es el complemento, no la dependencia."{RESET}
""")


def print_legal():
    print(f"""{RED}⚠  AVISO LEGAL — Solo para uso legal y autorizado{RESET}
{DIM}Investigaciones con autorización · OSINT defensivo · Threat Intelligence
Periodismo investigativo · Investigación académica · Incident Response
El usuario es el único responsable.  MX: Art. 211 bis CPF.{RESET}
""")


def list_modules():
    MODULES = [
        ("01","recon","TargetSanitizer","Detecta y normaliza cualquier tipo de input","🔑 core"),
        ("02","recon","PassiveDNS","DNS lookup + MX + reverse DNS","HackerTarget"),
        ("03","recon","WhoisRDAP","WHOIS + RDAP (IANA, ARIN, RIPE)","iana_rdap"),
        ("04","recon","IP2ASN","ASN, BGP prefix, geolocalización","BGPView, ipinfo"),
        ("05","recon","SubdomainEnum","Subdominios via Certificate Transparency","crt.sh"),
        ("06","recon","PortsServices","Puertos abiertos, CVEs (sin key)","Shodan InternetDB"),
        ("07","recon","TechFingerprint","Stack tecnológico via headers HTTP","http_direct"),
        ("08","recon","EmailPhoneHarvester","Emails y teléfonos del sitio web","Hunter, scrape"),
        ("09","people","UsernameEnum","Username en 30+ plataformas","async directo"),
        ("10","people","SocialScrape","Metadata pública de perfiles","GitHub, Telegram, Reddit"),
        ("11","people","PhotoReverse","Links búsqueda inversa de imágenes","GitHub avatar"),
        ("12","people","FamilyMapper","Seguidores, conexiones, orgs","GitHub API"),
        ("13","people","EmploymentHistory","Historial laboral público","GitHub, Keybase"),
        ("14","people","EducationCerts","Afiliaciones académicas","Google Scholar"),
        ("15","people","VehiclePlate","Placas MX + estado (REPUVE)","REPUVE, DB local"),
        ("16","people","CriminalRecords","Solo listas públicas","INTERPOL, OFAC SDN"),
        ("17","people","LeaksPaste","Breaches + reputación email","HIBP, EmailRep"),
        ("18","people","DarkwebLeakCorrelator","Pastes públicos con el target","psbdmp"),
        ("19","darkweb","DarkwebIntel","Índices .onion vía clearnet","Ahmia.fi"),
        ("20","darkweb","RansomwareIntel","Víctimas de grupos de ransomware","ransomware.live"),
        ("21","darkweb","DarkwebForumMonitor","Threat Intel pasivo — índices públicos","DarkSearch, IntelX"),
        ("22","darkweb","BreachAggregator","Índices públicos de breaches","BreachDir, Dehashed"),
        ("26","comms","PhoneDeepOSINT","Carrier, lada MX, ciudad, reputación","DB ladas, Numverify"),
        ("27","comms","TelegramIntel","Perfil, tipo de cuenta, canales","t.me, TGStat"),
        ("28","comms","CryptoWallet","BTC, ETH, cluster analysis","blockchain.info, Etherscan"),
        ("30","comms","SIMSwapRisk","Evaluación heurística riesgo SIM swap","local + Numverify"),
        ("31","comms","VoIPDetection","Detecta números VoIP / virtuales","rangos conocidos"),
        ("32","comms","MessengerFootprint","WhatsApp, Telegram por teléfono","click-to-chat"),
        ("33","advanced","LLMSemanticAnalyzer","Análisis semántico LLM local","Ollama (--llm)"),
        ("34","advanced","RelationshipGraph","Export grafo GraphML + GEXF + D3","networkx"),
        ("35","advanced","TimelineGenerator","Cronología completa de eventos","todos los módulos"),
        ("36","advanced","RiskScoreEngine","Score 0-100 con factores explicados","consensus flags"),
        ("37","advanced","AnomalyDetector","Inconsistencias y anomalías (7)","cruce interno"),
        ("38","advanced","CrossRefValidator","Validación cruzada multi-fuente","interno"),
        ("39","advanced","ExportReport","Reportes HTML + JSON + D3.js","interno"),
        ("40","advanced","SelfLearning","Reglas dinámicas + FastText feed","SQLite"),
        ("41","people","EcommerceFootprint","Huella e-commerce MX pública","MercadoLibre, Rappi"),
        ("49","advanced","MultiModalAnalyzer","EXIF metadata imágenes (--deep-multimodal)","PIL/manual"),
        ("50+","plugins","[tus plugins]","Auto-descubiertos desde plugins/","user-defined"),
    ]
    PHASE_CLR = {
        "recon":"\033[36m","people":"\033[35m","darkweb":"\033[31m",
        "comms":"\033[33m","advanced":"\033[32m","plugins":"\033[34m",
    }
    print(f"\n  {'ID':<5} {'FASE':<10} {'MÓDULO':<26} {'DESCRIPCIÓN':<38} FUENTES")
    print("  " + "─" * 100)
    cur_phase = None
    for mid, phase, name, desc, sources in MODULES:
        if phase != cur_phase:
            cur_phase = phase
            print()
        c = PHASE_CLR.get(phase,"")
        print(f"  {c}{mid:<5} {phase:<10} {name:<26}{RESET} {desc:<38} {DIM}{sources}{RESET}")
    print(f"\n  Total: {len(MODULES)} módulos  (50+ = plugins de usuario)\n")


def ft_status():
    try:
        from core.fasttext_engine import get_classifier
        clf = get_classifier()
        statuses = clf.status()
        print(f"\n  {'TASK':<22} {'CARGADO':<10} {'MUESTRAS':<12} {'MIN':<8} {'TAMAÑO':<10} LISTO")
        print("  " + "─" * 68)
        for s in statuses:
            loaded  = f"{CYAN}✔ SÍ{RESET}"  if s["loaded"] else f"{DIM}✗ NO{RESET}"
            ready   = f"{CYAN}✔ LISTO{RESET}" if s["ready"] else f"{RED}⏳ {s['sample_count']}/{s['min_needed']}{RESET}"
            size    = f"{s['model_size']/1024:.1f}KB" if s["model_size"] else "—"
            print(f"  {s['task']:<22} {loaded:<10} {s['sample_count']:<12} {s['min_needed']:<8} {size:<10} {ready}")
        print()
    except Exception as e:
        print(f"  FastText no disponible: {e}")
        print("  Instalar: pip install fasttext-wheel\n")


def ft_train():
    try:
        from core.fasttext_engine import get_trainer
        trainer = get_trainer()
        print("  Entrenando modelos FastText...")
        results = trainer.train_all(force=True)
        for task, ok in results.items():
            icon = f"{CYAN}✔{RESET}" if ok else f"{DIM}○{RESET}"
            print(f"  {icon} {task}")
        print()
    except Exception as e:
        print(f"  Error entrenando FastText: {e}\n")


async def run_scan(target: str, args: argparse.Namespace, api_manager):
    use_tor     = args.tor or os.environ.get("LEVIATHAN_TOR") == "1"
    use_textual = args.textual and not args.no_tui
    use_rich    = not args.no_tui and not args.textual
    plugins_dir = None if args.no_plugins else args.plugins_dir

    # Seleccionar dashboard
    dashboard = None
    if use_textual:
        try:
            from utils.dashboard_textual import LeviathanTextualApp, HAS_TEXTUAL
            if not HAS_TEXTUAL:
                print(f"\n  \033[31m✗\033[0m textual no instalado.")
                print(f"  Instalar: \033[36mpip install textual\033[0m")
                print(f"  O correr sin --textual para el dashboard Rich.\n")
                sys.exit(1)
            dashboard = LeviathanTextualApp(target_raw=target)
        except ImportError as e:
            print(f"\n  \033[31m✗\033[0m {e}\n")
            sys.exit(1)
    elif use_rich:
        from utils.dashboard import LeviathanlDashboard
        dashboard = LeviathanlDashboard(target_raw=target)

    # Mostrar disclaimer módulo 49
    if args.deep_multimodal:
        from modules.advanced.module_49_multimodal import DISCLAIMER
        print(DISCLAIMER)
        resp = input("  ¿Confirmas que tienes autorización sobre el target? [s/N] ").strip().lower()
        if resp not in ("s", "si", "sí", "y", "yes"):
            print("  Módulo 49 desactivado.")
            args.deep_multimodal = False

    from core.orchestrator_v2 import Orchestrator
    orchestrator = Orchestrator(
        api_keys=api_manager.as_dict(),
        use_tor=use_tor,
        proxy=args.proxy,
        human_mode=True,
        max_concurrent=args.concurrency,
        db_path=args.db,
        reports_dir=args.reports_dir,
        dashboard=dashboard,
        use_llm=args.llm or os.environ.get("LEVIATHAN_LLM") == "1",
        llm_host=args.llm_host,
        llm_model=args.llm_model,
        deep_multimodal=getattr(args, "deep_multimodal", False),
        plugins_dir=plugins_dir,
        enable_health=True,
    )

    scan_coro = orchestrator.scan(target)

    if use_textual:
        state = await dashboard.run_with_scan(scan_coro)
    elif use_rich:
        state = await dashboard.run(scan_coro)
    else:
        state = await scan_coro

    # Output sin TUI
    if args.no_tui:
        if args.output == "json":
            import json
            print(json.dumps({
                "scan_id":      state.target.scan_id,
                "target":       state.target.normalized,
                "type":         state.target.type.value,
                "risk_score":   state.risk_score,
                "risk_level":   state.risk_level.value,
                "entities":     len(state.entities),
                "trusted":      len(state.trusted_entities()),
                "correlations": len(state.correlations),
                "elapsed":      state.elapsed(),
                "top_entities": [
                    {"type": e.type.value, "value": e.value,
                     "confidence": e.confidence, "verdict": e.verdict.value,
                     "flags": e.flags}
                    for e in sorted(state.trusted_entities(), key=lambda x: -x.confidence)[:10]
                ],
            }, indent=2, ensure_ascii=False))
        elif args.output != "quiet":
            print(f"\n{CYAN}✔ Scan completo:{RESET} {state.target.normalized}")
            print(f"  Entidades: {len(state.entities)} ({len(state.trusted_entities())} confirmadas)")
            print(f"  Correlaciones: {len(state.correlations)}")
            print(f"  Riesgo: {state.risk_score}/100 [{state.risk_level.value}]")
            print(f"  Tiempo: {state.elapsed():.1f}s")
            print(f"  Reporte: {args.reports_dir}/leviathan_{state.target.scan_id}_*.html\n")
    return state


async def run_batch(filepath: str, args: argparse.Namespace, api_manager):
    path = Path(filepath)
    if not path.exists():
        print(f"  {RED}✗{RESET} Archivo no encontrado: {filepath}")
        return
    targets = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            t = line.split(",")[0].strip().strip('"')
            if t:
                targets.append(t)

    print(f"\n  🐉 Batch mode: {len(targets)} targets\n")
    results = []
    for i, t in enumerate(targets, 1):
        print(f"  [{i}/{len(targets)}] {t}")
        state = await run_scan(t, args, api_manager)
        results.append({
            "target": t,
            "risk_score":   state.risk_score,
            "risk_level":   state.risk_level.value,
            "entities":     len(state.trusted_entities()),
            "correlations": len(state.correlations),
            "elapsed":      state.elapsed(),
        })

    print(f"\n  {'TARGET':<40} {'RIESGO':>8} {'NIVEL':<10} ENTS  CORR  TIEMPO")
    print("  " + "─" * 78)
    for r in sorted(results, key=lambda x: -x["risk_score"]):
        print(f"  {r['target']:<40} {r['risk_score']:>5}/100  {r['risk_level']:<10} "
              f"{r['entities']:<5} {r['correlations']:<5} {r['elapsed']:.1f}s")
    print()


def main():
    parser = build_parser()
    args   = parser.parse_args()

    # ── Acciones sin scan ─────────────────────────────────────────────────────
    if args.init_config:
        from config.api_manager import APIManager
        APIManager.generate_config_yaml()
        return

    from config.api_manager import APIManager
    api_manager = APIManager()

    if args.list_modules:
        print_banner()
        list_modules()
        return

    if args.list_plugins:
        print_banner()
        from pathlib import Path
        from plugins.plugin_manager import PluginManager
        pm = PluginManager(Path(args.plugins_dir))
        pm.discover()
        print(f"\n  Plugins en: {args.plugins_dir}/")
        pm.print_status()
        return

    if args.apis:
        print_banner()
        print(api_manager.status_report())
        return

    if args.ft_status:
        print_banner()
        ft_status()
        return

    if args.ft_train:
        print_banner()
        ft_train()
        return

    if args.health_check:
        print_banner()
        from core.microkernel3_storage import K3Storage
        from core.health_check import HealthChecker
        storage = K3Storage(args.db)
        storage.init()
        if args.reset_module:
            storage.reset_module_health(args.reset_module)
            print(f"  {CYAN}✔{RESET} Módulo {args.reset_module} reseteado\n")
            return
        checker = HealthChecker(storage)
        checker.print_status()
        print(f"  Para ejecutar check en vivo: python leviathan.py target (activa HealthCheck en background)\n")
        return

    if args.api:
        print_banner()
        try:
            from api.rest import create_app
            import uvicorn
            app = create_app(api_manager)
            print(f"  🐉 Leviathan API → http://localhost:{args.port}")
            print(f"  📖 Docs         → http://localhost:{args.port}/docs\n")
            uvicorn.run(app, host="0.0.0.0", port=args.port, log_level="warning")
        except ImportError as e:
            print(f"  {RED}✗{RESET} Falta: {e}\n  Instalar: pip install fastapi uvicorn\n")
        return

    if args.analyze_reports:
        print_banner()
        print(f"  Analizando reportes en: {args.analyze_reports}...")
        try:
            import json
            from pathlib import Path
            from core.fasttext_engine import get_collector, get_trainer
            collector = get_collector()
            reports   = list(Path(args.analyze_reports).glob("*.json"))
            count = 0
            for rpath in reports:
                try:
                    data = json.loads(rpath.read_text())
                    for e in data.get("entities", []):
                        if e.get("verdict") in ("TRUSTED","LIKELY"):
                            collector.add_entity(e["type"], e["value"], e.get("metadata",{}))
                            count += 1
                except Exception:
                    pass
            collector.flush()
            print(f"  {CYAN}✔{RESET} {count} entidades alimentadas desde {len(reports)} reportes")
            if args.ft_train:
                ft_train()
        except Exception as e:
            print(f"  {RED}✗{RESET} Error: {e}")
        return

    # ── Batch ──────────────────────────────────────────────────────────────────
    if args.batch:
        print_banner()
        print_legal()
        asyncio.run(run_batch(args.batch, args, api_manager))
        return

    # ── Scan individual ────────────────────────────────────────────────────────
    if not args.target:
        parser.print_help()
        print(f"\n  {RED}✗{RESET} Especifica un target o usa --batch, --api, --list-modules, etc.\n")
        sys.exit(1)

    print_banner()
    print_legal()

    try:
        asyncio.run(run_scan(args.target, args, api_manager))
    except KeyboardInterrupt:
        print(f"\n\n  🐉 Scan interrumpido.\n")
    except Exception as e:
        log.error(f"Error: {e}", exc_info=True)
        print(f"\n  {RED}✗{RESET} Error: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
