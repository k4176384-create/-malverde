"""
Leviathan OSINT v4.0 — API Manager
3 niveles de APIs. Carga desde env vars, config.yaml, o sin key (free tier).
"""
from __future__ import annotations
import os
import logging
from pathlib import Path

log = logging.getLogger("leviathan.config")

# ─── Definición de APIs por nivel ─────────────────────────────────────────────
API_REGISTRY = {
    # Nivel 0 — Sin key, funciona siempre
    "shodan_free":    {"level": 0, "env": None,                "desc": "Shodan InternetDB (sin key)"},
    "crt_sh":         {"level": 0, "env": None,                "desc": "Certificate Transparency"},
    "hackertarget":   {"level": 0, "env": None,                "desc": "DNS, WHOIS (100/día)"},
    "bgpview":        {"level": 0, "env": None,                "desc": "ASN, BGP"},
    "ipinfo_anon":    {"level": 0, "env": None,                "desc": "Geo básica (1k/día)"},
    "iana_rdap":      {"level": 0, "env": None,                "desc": "Registro de dominios"},
    "github_anon":    {"level": 0, "env": None,                "desc": "GitHub (60 req/hora)"},
    "ransomware_live":{"level": 0, "env": None,                "desc": "Víctimas ransomware"},
    "blockchain_info":{"level": 0, "env": None,                "desc": "Wallets Bitcoin"},
    "etherscan_free": {"level": 0, "env": None,                "desc": "Wallets Ethereum (5/seg)"},
    "ahmia":          {"level": 0, "env": None,                "desc": "Índice .onion clearnet"},
    "interpol":       {"level": 0, "env": None,                "desc": "Red Notices públicas"},
    "emailrep_free":  {"level": 0, "env": None,                "desc": "Email reputation básica"},

    # Nivel 1 — Free tier (registro gratuito)
    "github":         {"level": 1, "env": "GITHUB_TOKEN",      "desc": "GitHub API (5k req/hora)"},
    "ipinfo":         {"level": 1, "env": "IPINFO_TOKEN",      "desc": "IP info completa (50k/mes)"},
    "shodan":         {"level": 1, "env": "SHODAN_API_KEY",    "desc": "Shodan (búsquedas avanzadas)"},
    "hunter":         {"level": 1, "env": "HUNTER_API_KEY",    "desc": "Hunter.io emails"},
    "securitytrails": {"level": 1, "env": "SECURITYTRAILS_KEY","desc": "DNS histórico"},
    "numverify":      {"level": 1, "env": "NUMVERIFY_KEY",     "desc": "Validación de teléfonos"},
    "intelx":         {"level": 1, "env": "INTELX_KEY",        "desc": "Darkweb / pastes"},
    "virustotal":     {"level": 1, "env": "VIRUSTOTAL_KEY",    "desc": "Reputación IPs/dominios"},
    "greynoise":      {"level": 1, "env": "GREYNOISE_KEY",     "desc": "Clasifica IPs maliciosas"},
    "abstract_phone": {"level": 1, "env": "ABSTRACT_PHONE_KEY","desc": "Phone validation"},
    "darksearch":     {"level": 1, "env": "DARKSEARCH_KEY",    "desc": "Índice darkweb"},

    # Nivel 2 — De pago (mayor calidad)
    "hibp":           {"level": 2, "env": "HIBP_API_KEY",      "desc": "HaveIBeenPwned ($3.50/mes)"},
    "etherscan":      {"level": 2, "env": "ETHERSCAN_KEY",     "desc": "Etherscan avanzado"},
    "dehashed":       {"level": 2, "env": "DEHASHED_KEY",      "desc": "Dehashed breach search"},
    "rapidapi":       {"level": 2, "env": "RAPIDAPI_KEY",      "desc": "RapidAPI (BreachDirectory)"},
    "tgstat":         {"level": 2, "env": "TGSTAT_KEY",        "desc": "TGStat Telegram analytics"},
    "fullcontact":    {"level": 2, "env": "FULLCONTACT_KEY",   "desc": "FullContact identity"},
}


class APIManager:
    """Gestiona carga de API keys desde env vars y config.yaml."""

    def __init__(self, config_path: str = "config/config.yaml"):
        self.config_path = Path(config_path)
        self.keys: dict[str, str] = {}
        self._load()

    def _load(self):
        # 1. Cargar desde env vars
        for api_name, meta in API_REGISTRY.items():
            env = meta.get("env")
            if env and os.environ.get(env):
                self.keys[api_name] = os.environ[env]

        # 2. Cargar desde config.yaml (si existe)
        if self.config_path.exists():
            try:
                import yaml  # type: ignore
                with open(self.config_path) as f:
                    config = yaml.safe_load(f) or {}
                apis = config.get("apis", {})
                for api_name, meta in API_REGISTRY.items():
                    # Buscar por nombre de API o por env var name (sin prefijo)
                    yaml_key = api_name
                    if yaml_key in apis and apis[yaml_key]:
                        self.keys.setdefault(api_name, apis[yaml_key])
            except Exception as e:
                log.debug(f"config.yaml load warning: {e}")

        configured = sum(1 for v in self.keys.values() if v)
        log.info(f"API Manager: {configured} keys cargadas")

    def get(self, name: str) -> str | None:
        return self.keys.get(name) or None

    def has(self, name: str) -> bool:
        return bool(self.keys.get(name))

    def status_report(self) -> str:
        lines = ["", "─── API Keys Status ───────────────────────────────"]
        for level in range(3):
            lvl_names = {0: "Nivel 0 (free, sin key)", 1: "Nivel 1 (free tier)", 2: "Nivel 2 (de pago)"}
            lines.append(f"\n  {lvl_names[level]}:")
            for name, meta in API_REGISTRY.items():
                if meta["level"] != level:
                    continue
                if meta["env"] is None:
                    status = "  ✔ SIEMPRE"
                elif self.has(name):
                    status = f"  ✔ CONFIGURADO ({meta['env']})"
                else:
                    status = f"  ✗ Sin key     ({meta['env']})"
                lines.append(f"    {name:<18} {status:<35} {meta['desc']}")
        lines.append("─" * 55)
        return "\n".join(lines)

    def as_dict(self) -> dict[str, str]:
        return dict(self.keys)

    @classmethod
    def generate_config_yaml(cls, output_path: str = "config/config.yaml"):
        """Genera config.yaml documentado con las env vars actuales pre-rellenadas."""
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        lines = [
            "# Leviathan OSINT v4.0 — Configuración principal",
            "# Generado automáticamente. Editar según necesidades.",
            "",
            "leviathan:",
            '  version: "4.0"',
            '  db_path: "database/leviathan.db"',
            '  reports_dir: "reports"',
            '  logs_dir: "logs"',
            "",
            "apis:",
            "  # ── NIVEL 1 (más importantes) ────────────────────",
        ]
        for name, meta in API_REGISTRY.items():
            if meta["level"] == 0:
                continue
            current = os.environ.get(meta["env"] or "", "")
            value   = f'"{current}"' if current else '""'
            lines.append(f'  {name}: {value:<30}  # {meta["desc"]}')
        lines += [
            "",
            "tor:",
            "  enabled: false",
            "  socks_port: 9050",
            "  new_circuit_on_rate_limit: true",
            "",
            "proxy:",
            "  enabled: false",
            "  type: socks5",
            "  host: 127.0.0.1",
            "  port: 1080",
            "  fallback_direct: true",
            "  proxy_list: []",
            "",
            "llm:",
            "  enabled: false",
            "  backend: ollama",
            "  host: http://localhost:11434",
            '  model: "phi3:mini"',
            "  timeout: 120",
            "",
            "kernels:",
            "  crawler:",
            "    max_concurrent_requests: 10",
            "    human_mode: true",
            "    jitter_factor: 0.3",
            "  correlator:",
            "    min_confidence_threshold: 0.4",
            "",
            "health_check:",
            "  enabled: true",
            "  interval_hours: 24",
            "  max_consecutive_failures: 3",
        ]
        Path(output_path).write_text("\n".join(lines))
        print(f"✔ Config generado: {output_path}")
