"""
Leviathan OSINT v4.0 — Source Genealogy
Evita la "ilusión de verdad" por redundancia de upstream.

Problema: Shodan + Censys + Zoomeye todas usan MaxMind para geo.
3 fuentes → Consensus da 90% confianza → en realidad es 1 fuente × 3.
"""
from __future__ import annotations

# Mapa de fuentes a su proveedor upstream real
UPSTREAM_MAP: dict[str, str] = {
    # Geolocalización IP
    "shodan":           "maxmind_geo",
    "censys":           "maxmind_geo",
    "zoomeye":          "maxmind_geo",
    "ipinfo":           "maxmind_geo",
    "ip2location":      "maxmind_geo",
    "ipgeolocation":    "maxmind_geo",
    "maxmind":          "maxmind_geo",
    # BGP / Routing
    "bgpview":          "bgp_routing",
    "routeviews":       "bgp_routing",
    "ripestat":         "bgp_routing",
    "arin":             "iana_rdap",
    "ripe":             "iana_rdap",
    "apnic":            "iana_rdap",
    # DNS
    "hackertarget_dns": "dns_authoritative",
    "google_dns":       "dns_authoritative",
    "cloudflare_dns":   "dns_authoritative",
    "crt.sh":           "certificate_transparency",
    "censys_certs":     "certificate_transparency",
    # Breaches
    "haveibeenpwned":   "hibp_db",
    "hibp":             "hibp_db",
    "emailrep":         "emailrep_db",
    "breachdirectory":  "breach_directory_db",
    "dehashed":         "breach_directory_db",
    "intelx":           "intelx_db",
    # Pastes
    "pastebin":         "pastebin_index",
    "psbdmp":           "pastebin_index",
    "paste.ee":         "pastebin_index",
    # Crawlers
    "hunter":           "hunter_crawler",
    "clearbit":         "hunter_crawler",
    # Directo
    "github_api":       "github_api",
    "telegram_direct":  "telegram_direct",
    "web_scrape":       "direct_scrape",
    "http_direct":      "direct_scrape",
    # Crypto
    "blockchain_info":  "blockchain_info",
    "etherscan":        "etherscan_api",
    "walletexplorer":   "blockchain_info",
    # Darkweb
    "ahmia":            "ahmia_index",
    "darksearch":       "darksearch_index",
    "ransomware_live":  "ransomware_live_db",
    # Autoridades
    "interpol":         "interpol_db",
    "ofac":             "ofac_db",
    "repuve":           "local_db",
    "sat_mx":           "local_db",
}

# Penalizaciones por repetición del mismo upstream
REPEAT_PENALTY: dict[int, float] = {
    1: 1.0,   # Primera vez → valor completo
    2: 0.5,   # Segunda → 50% penalización
    3: 0.2,   # Tercera → 80% penalización
}

def get_upstream(source: str) -> str:
    """Devuelve el proveedor upstream real de una fuente."""
    return UPSTREAM_MAP.get(source.lower(), source.lower())


class SourceGenealogyTracker:
    """
    Rastrea upstreams vistos por entidad.
    Aplica penalización cuando el mismo upstream aparece múltiples veces.
    """

    def __init__(self):
        self._seen: dict[str, dict[str, int]] = {}  # entity_key → {upstream: count}

    def get_weight_multiplier(self, entity_key: str, source: str) -> float:
        """
        Devuelve el multiplicador de peso para esta fuente.
        Penaliza si el upstream ya fue contado para esta entidad.
        """
        upstream = get_upstream(source)

        if entity_key not in self._seen:
            self._seen[entity_key] = {}

        count = self._seen[entity_key].get(upstream, 0) + 1
        self._seen[entity_key][upstream] = count

        return REPEAT_PENALTY.get(count, 0.1)

    def reset(self, entity_key: str | None = None):
        if entity_key:
            self._seen.pop(entity_key, None)
        else:
            self._seen.clear()

    def diversity_score(self, entity_key: str) -> float:
        """
        Qué tan diversos son los upstreams de esta entidad.
        1.0 = todos diferentes, 0.0 = todos el mismo upstream.
        """
        if entity_key not in self._seen:
            return 0.0
        counts = list(self._seen[entity_key].values())
        if not counts:
            return 0.0
        unique = len(counts)
        total  = sum(counts)
        return unique / total if total > 0 else 0.0
