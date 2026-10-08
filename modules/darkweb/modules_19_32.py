"""
Leviathan OSINT v4.0 — Módulos Darkweb (19–22) y Comms (26–32)
Darkweb: solo índices públicos, monitoreo pasivo, sin autenticación.
"""
from __future__ import annotations
import re
import asyncio
import logging
from modules.base_module import BaseModule
from core.models import Target, TargetType

log = logging.getLogger("leviathan.darkweb")

# ─── 19: DarkwebIntel ────────────────────────────────────────────────────────

class DarkwebIntel(BaseModule):
    MODULE_ID       = "19"
    MODULE_NAME     = "DarkwebIntel"
    MODULE_PRIORITY = 6
    MODULE_PHASE    = "darkweb"
    ENTITY_TYPES    = ["url", "snippet"]
    APPLICABLE      = {TargetType.DOMAIN, TargetType.EMAIL, TargetType.USERNAME}

    async def _run(self, target: Target):
        if target.type not in self.APPLICABLE:
            return
        query = target.normalized

        # Ahmia.fi — índice .onion vía clearnet
        result = await self.get_json(
            "https://ahmia.fi/search/",
            params={"q": query},
        )
        if result and "_text" in result:
            onion_matches = re.findall(r'[a-z2-7]{16,56}\.onion', result["_text"])
            seen = set()
            for onion in onion_matches[:10]:
                if onion not in seen:
                    seen.add(onion)
                    self.emit("onion", onion, {
                        "query": query,
                        "found_via": "ahmia_clearnet",
                    }, ["ahmia_index"])


# ─── 20: RansomwareIntel ─────────────────────────────────────────────────────

class RansomwareIntel(BaseModule):
    MODULE_ID       = "20"
    MODULE_NAME     = "RansomwareIntel"
    MODULE_PRIORITY = 5
    MODULE_PHASE    = "darkweb"
    ENTITY_TYPES    = ["other", "org"]
    APPLICABLE      = {TargetType.DOMAIN, TargetType.ORG}

    async def _run(self, target: Target):
        if target.type not in self.APPLICABLE:
            return
        domain = target.normalized.split("/")[0].lstrip("www.")
        org_name = domain.split(".")[0]

        # ransomware.live — API pública de víctimas
        data = await self.get_json("https://api.ransomware.live/v2/recentvictims")
        if isinstance(data, list):
            for victim in data:
                victim_domain = victim.get("website", "").lower()
                victim_name   = victim.get("victim", "").lower()
                if domain.lower() in victim_domain or org_name.lower() in victim_name:
                    self.emit("other", victim.get("victim", ""), {
                        "type":     "ransomware_victim",
                        "group":    victim.get("group", ""),
                        "date":     victim.get("published", ""),
                        "domain":   victim_domain,
                        "url":      victim.get("post_url", ""),
                        "criminal_record": False,
                        "darkweb_mention": True,
                    }, ["ransomware_live_db"])


# ─── 21: DarkwebForumMonitor ─────────────────────────────────────────────────

class DarkwebForumMonitor(BaseModule):
    """
    Threat Intel pasivo — menciones en índices públicos de foros.
    Solo búsqueda pasiva en contenido ya indexado públicamente.
    Sin autenticación, sin interacción directa con foros.
    """
    MODULE_ID       = "21"
    MODULE_NAME     = "DarkwebForumMonitor"
    MODULE_PRIORITY = 7
    MODULE_PHASE    = "darkweb"
    ENTITY_TYPES    = ["snippet", "url"]
    APPLICABLE      = {TargetType.EMAIL, TargetType.USERNAME, TargetType.DOMAIN}
    REQUIRES_API    = False

    async def _run(self, target: Target):
        if target.type not in self.APPLICABLE:
            return
        query = target.normalized

        # DarkSearch API — índice clearnet de contenido darkweb público
        if self.has_key("darksearch"):
            ds = await self.get_json(
                "https://darksearch.io/api/search",
                params={"query": query, "page": 1},
                headers={"Authorization": f"Bearer {self.key('darksearch')}"},
            )
            if ds and "data" in ds:
                for item in ds["data"][:5]:
                    self.emit("snippet", item.get("title", ""), {
                        "source":         "darksearch_index",
                        "url":            item.get("link", ""),
                        "description":    item.get("description", "")[:200],
                        "query":          query,
                        "darkweb_mention": True,
                    }, ["darksearch_index"])

        # IntelX
        if self.has_key("intelx"):
            search = await self.get_json(
                "https://2.intelx.io/intelligent/search",
                params={"term": query, "maxresults": 5, "media": 0},
                headers={"x-key": self.key("intelx")},
            )
            if search and "records" in search:
                for rec in search["records"][:5]:
                    self.emit("snippet", rec.get("name", ""), {
                        "source":    "intelx",
                        "date":      rec.get("date", ""),
                        "query":     query,
                        "darkweb_mention": True,
                    }, ["intelx_db"])


# ─── 22: BreachAggregator ────────────────────────────────────────────────────

class BreachAggregator(BaseModule):
    MODULE_ID       = "22"
    MODULE_NAME     = "BreachAggregator"
    MODULE_PRIORITY = 4
    MODULE_PHASE    = "darkweb"
    ENTITY_TYPES    = ["breach", "credential"]
    APPLICABLE      = {TargetType.EMAIL, TargetType.USERNAME, TargetType.DOMAIN}

    async def _run(self, target: Target):
        if target.type not in self.APPLICABLE:
            return
        query = target.normalized

        # BreachDirectory
        bd = await self.get_json(
            "https://breachdirectory.p.rapidapi.com/",
            params={"func": "auto", "term": query},
            headers={
                "X-RapidAPI-Key":  self.key("rapidapi") or "",
                "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com",
            },
        )
        if bd and "result" in bd and isinstance(bd["result"], list):
            for entry in bd["result"][:10]:
                self.emit("credential", entry.get("password", "")[:4] + "****", {
                    "email":   entry.get("email", query),
                    "source":  entry.get("source", ""),
                    "partial": True,
                }, ["breach_directory_db"])

        # Dehashed (si hay key)
        if self.has_key("dehashed"):
            dh = await self.get_json(
                "https://api.dehashed.com/search",
                params={"query": query, "size": 5},
                headers={"Authorization": f"Bearer {self.key('dehashed')}"},
            )
            if dh and "entries" in dh:
                for entry in dh["entries"][:5]:
                    self.emit("breach", entry.get("database_name", ""), {
                        "email":    entry.get("email", ""),
                        "username": entry.get("username", ""),
                        "source":   "dehashed",
                        "emails": [entry.get("email", "")],
                    }, ["breach_directory_db"])


# ─── 26: PhoneDeepOSINT ──────────────────────────────────────────────────────

log2 = logging.getLogger("leviathan.comms")

LADAS_MX_FULL = {
    "55": "Ciudad de México (CDMX)", "56": "Ciudad de México (CDMX)",
    "33": "Guadalajara, Jalisco", "34": "Guadalajara, Jalisco",
    "81": "Monterrey, Nuevo León", "82": "Monterrey, Nuevo León",
    "664": "Tijuana, Baja California", "665": "Mexicali, Baja California",
    "667": "Culiacán, Sinaloa", "668": "Los Mochis, Sinaloa",
    "669": "Mazatlán, Sinaloa", "614": "Chihuahua, Chihuahua",
    "626": "Delicias, Chihuahua", "461": "Irapuato, Guanajuato",
    "477": "León, Guanajuato", "449": "Aguascalientes",
    "442": "Querétaro", "222": "Puebla", "229": "Veracruz",
    "998": "Cancún, Quintana Roo", "999": "Mérida, Yucatán",
    "744": "Acapulco, Guerrero", "951": "Oaxaca", "961": "Tuxtla Gutiérrez",
    "312": "Colima", "777": "Cuernavaca, Morelos",
}

TELCEL_PREFIXES   = ["55", "81", "33", "664", "667", "449", "442"]
MOVISTAR_PREFIXES = ["56", "222", "229", "951"]
ATT_PREFIXES      = ["614", "626", "477"]

class PhoneDeepOSINT(BaseModule):
    MODULE_ID       = "26"
    MODULE_NAME     = "PhoneDeepOSINT"
    MODULE_PRIORITY = 3
    MODULE_PHASE    = "comms"
    ENTITY_TYPES    = ["phone", "location", "org"]
    APPLICABLE      = {TargetType.PHONE}

    async def _run(self, target: Target):
        if target.type != TargetType.PHONE:
            return
        phone = re.sub(r'[\s\-\(\)\+]', '', target.normalized)
        if phone.startswith("52"):
            phone = phone[2:]

        lada3 = phone[:3]
        lada2 = phone[:2]
        city  = LADAS_MX_FULL.get(lada3) or LADAS_MX_FULL.get(lada2, "Desconocida, México")

        carrier = "Desconocido"
        if lada3 in TELCEL_PREFIXES or lada2 in TELCEL_PREFIXES:
            carrier = "Telcel"
        elif lada3 in MOVISTAR_PREFIXES or lada2 in MOVISTAR_PREFIXES:
            carrier = "Movistar"
        elif lada3 in ATT_PREFIXES or lada2 in ATT_PREFIXES:
            carrier = "AT&T México"

        self.emit("phone", target.normalized, {
            "carrier":  carrier,
            "city":     city,
            "lada":     lada3 or lada2,
            "country":  "MX",
            "is_voip":  False,
        }, ["local_db"])
        self.emit("location", city, {
            "type":   "phone_lada",
            "phone":  target.normalized,
            "source": "ladas_mx_db",
        }, ["local_db"])

        # Numverify
        if self.has_key("numverify"):
            data = await self.get_json(
                "http://apilayer.net/api/validate",
                params={
                    "access_key": self.key("numverify"),
                    "number":     target.normalized,
                    "country_code": "MX",
                },
            )
            if data and data.get("valid"):
                self.emit("phone", target.normalized, {
                    "carrier":       data.get("carrier", carrier),
                    "line_type":     data.get("line_type", "mobile"),
                    "country":       "MX",
                    "is_voip":       data.get("line_type") in ("voip", "virtual"),
                    "local_format":  data.get("local_format", ""),
                    "source_count":  2,
                }, ["local_db"])

        # Abstract API Phone
        if self.has_key("abstract_phone"):
            abstract = await self.get_json(
                "https://phonevalidation.abstractapi.com/v1/",
                params={
                    "api_key": self.key("abstract_phone"),
                    "phone":   target.normalized,
                },
            )
            if abstract and abstract.get("valid"):
                self.emit("phone", target.normalized, {
                    "carrier":   abstract.get("carrier", {}).get("name", ""),
                    "line_type": abstract.get("type", "mobile"),
                    "country":   "MX",
                }, ["local_db"])


# ─── 27: TelegramIntel ───────────────────────────────────────────────────────

class TelegramIntel(BaseModule):
    MODULE_ID       = "27"
    MODULE_NAME     = "TelegramIntel"
    MODULE_PRIORITY = 4
    MODULE_PHASE    = "comms"
    ENTITY_TYPES    = ["username", "person", "url"]
    APPLICABLE      = {TargetType.USERNAME, TargetType.PHONE}

    async def _run(self, target: Target):
        if target.type not in self.APPLICABLE:
            return
        query = target.normalized
        if target.type == TargetType.PHONE:
            # Intentar verificar si tiene cuenta Telegram via click-to-chat
            phone_clean = re.sub(r'[\s\-\(\)\+]', '', query)
            result = await self.get_text(
                f"https://t.me/+{phone_clean}",
                headers={"Accept": "text/html"},
            )
            if result and "tgme_page" in result:
                self.emit("phone", query, {
                    "has_telegram": True,
                    "platform": "telegram",
                }, ["telegram_direct"])
            return

        # Username en Telegram
        result = await self.get_text(f"https://t.me/{query}")
        if not result:
            return

        # Tipo de cuenta
        account_type = "unknown"
        if "tgme_page_extra" in result:
            extra = re.search(r'<div class="tgme_page_extra">(.*?)</div>', result)
            if extra:
                extra_text = extra.group(1)
                if "members" in extra_text.lower() or "subscribers" in extra_text.lower():
                    account_type = "channel_or_group"
                else:
                    account_type = "user"

        # TGStat para canales
        tgstat = await self.get_json(f"https://api.tgstat.ru/channels/stat",
                                     params={"token": self.key("tgstat") or "",
                                             "channelId": f"@{query}"})
        if tgstat and "response" in tgstat:
            r = tgstat["response"]
            self.emit("username", query, {
                "platform":     "telegram",
                "account_type": account_type,
                "subscribers":  r.get("subscribersCount", 0),
                "avg_views":    r.get("avgPostReach", 0),
                "profile_url":  f"https://t.me/{query}",
            }, ["telegram_direct"])
        else:
            self.emit("username", query, {
                "platform":     "telegram",
                "account_type": account_type,
                "profile_url":  f"https://t.me/{query}",
            }, ["telegram_direct"])


# ─── 28: CryptoWallet ────────────────────────────────────────────────────────

class CryptoWallet(BaseModule):
    MODULE_ID       = "28"
    MODULE_NAME     = "CryptoWallet"
    MODULE_PRIORITY = 5
    MODULE_PHASE    = "comms"
    ENTITY_TYPES    = ["crypto", "other"]
    APPLICABLE      = {TargetType.CRYPTO}

    async def _run(self, target: Target):
        if target.type != TargetType.CRYPTO:
            return
        addr = target.normalized

        # Bitcoin — blockchain.info
        if re.match(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[a-z0-9]{39,59}$', addr):
            data = await self.get_json(f"https://blockchain.info/rawaddr/{addr}?limit=5")
            if data:
                self.emit("crypto", addr, {
                    "type":          "btc",
                    "balance_sat":   data.get("final_balance", 0),
                    "tx_count":      data.get("n_tx", 0),
                    "total_sent":    data.get("total_sent", 0),
                    "total_received": data.get("total_received", 0),
                    "first_seen":    data.get("txs", [{}])[-1].get("time", 0) if data.get("txs") else 0,
                }, ["blockchain_info"])

                # WalletExplorer cluster
                cluster = await self.get_json(
                    f"https://www.walletexplorer.com/api/1/address",
                    params={"address": addr, "caller": "leviathan_osint"},
                )
                if cluster and "wallet" in cluster:
                    self.emit("other", cluster["wallet"].get("id", ""), {
                        "type":           "btc_cluster",
                        "wallet_label":   cluster["wallet"].get("label", ""),
                        "address_count":  cluster["wallet"].get("address_count", 0),
                    }, ["blockchain_info"])

        # Ethereum — Etherscan
        elif re.match(r'^0x[0-9a-fA-F]{40}$', addr):
            data = await self.get_json(
                "https://api.etherscan.io/api",
                params={
                    "module": "account",
                    "action": "balance",
                    "address": addr,
                    "tag":    "latest",
                    "apikey": self.key("etherscan") or "YourApiKeyToken",
                },
            )
            if data and data.get("status") == "1":
                balance_wei = int(data.get("result", "0"))
                self.emit("crypto", addr, {
                    "type":        "eth",
                    "balance_wei": balance_wei,
                    "balance_eth": balance_wei / 1e18,
                }, ["etherscan_api"])


# ─── 30: SIMSwapRisk ─────────────────────────────────────────────────────────

class SIMSwapRisk(BaseModule):
    MODULE_ID       = "30"
    MODULE_NAME     = "SIMSwapRisk"
    MODULE_PRIORITY = 6
    MODULE_PHASE    = "comms"
    ENTITY_TYPES    = ["phone"]
    APPLICABLE      = {TargetType.PHONE}

    async def _run(self, target: Target):
        if target.type != TargetType.PHONE:
            return
        phone = target.normalized

        # Evaluación heurística de riesgo SIM swap
        # Factores: carrier prepago, número VoIP, número reusado
        risk_factors = []
        risk_score   = 0

        clean = re.sub(r'[\s\-\(\)\+]', '', phone)
        lada = clean[:3] if len(clean) >= 3 else clean[:2]
        
        # Carriers de prepago son más vulnerables
        prepaid_ladas = ["800", "900"]
        if any(clean.startswith(p) for p in prepaid_ladas):
            risk_factors.append("prefijo_prepago")
            risk_score += 25

        self.emit("phone", phone, {
            "simswap_risk":    risk_score > 20,
            "risk_score":      risk_score,
            "risk_factors":    risk_factors,
            "assessment_type": "heuristic",
        }, ["local_db"])


# ─── 31: VoIPDetection ───────────────────────────────────────────────────────

class VoIPDetection(BaseModule):
    MODULE_ID       = "31"
    MODULE_NAME     = "VoIPDetection"
    MODULE_PRIORITY = 5
    MODULE_PHASE    = "comms"
    ENTITY_TYPES    = ["phone"]
    APPLICABLE      = {TargetType.PHONE}

    VOIP_RANGES = [
        "555", "800", "844", "855", "866", "877", "888",
        "900",  # premium / VoIP
    ]
    VIRTUAL_KEYWORDS = ["google voice", "twilio", "vonage", "magicjack", "ooma", "textnow"]

    async def _run(self, target: Target):
        if target.type != TargetType.PHONE:
            return
        phone = re.sub(r'[\s\-\(\)\+]', '', target.normalized)

        is_voip = any(phone.startswith(prefix) for prefix in self.VOIP_RANGES)
        self.emit("phone", target.normalized, {
            "is_voip":   is_voip,
            "detection": "range_heuristic" if is_voip else "likely_physical",
        }, ["local_db"])


# ─── 32: MessengerFootprint ──────────────────────────────────────────────────

class MessengerFootprint(BaseModule):
    MODULE_ID       = "32"
    MODULE_NAME     = "MessengerFootprint"
    MODULE_PRIORITY = 5
    MODULE_PHASE    = "comms"
    ENTITY_TYPES    = ["phone", "url"]
    APPLICABLE      = {TargetType.PHONE}

    async def _run(self, target: Target):
        if target.type != TargetType.PHONE:
            return
        phone = re.sub(r'[\s\-\(\)\+]', '', target.normalized)
        intl  = f"52{phone}" if not phone.startswith("52") else phone

        # WhatsApp click-to-chat (verificación pública)
        wa_url = f"https://api.whatsapp.com/send?phone={intl}"
        self.emit("url", wa_url, {
            "platform": "whatsapp",
            "phone":    target.normalized,
            "type":     "click_to_chat",
        }, ["direct_scrape"])

        # Telegram por número
        tg_url = f"https://t.me/+{intl}"
        result = await self.get_text(tg_url)
        if result and "tgme_page" in result:
            self.emit("phone", target.normalized, {
                "has_telegram": True,
                "telegram_url": tg_url,
            }, ["telegram_direct"])
