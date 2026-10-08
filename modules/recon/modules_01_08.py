"""
Leviathan OSINT v4.0 — Módulos Recon (01–08)
Todos los módulos solo emiten entidades crudas. Sin juzgar.
"""
from __future__ import annotations
import re
import asyncio
import logging
from modules.base_module import BaseModule
from core.models import Target, TargetType, EntityType

log = logging.getLogger("leviathan.recon")

# ─── Regex MX/LATAM ──────────────────────────────────────────────────────────
RE_EMAIL    = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
RE_PHONE_MX = re.compile(
    r'(?:\+?52[-\s]?)?(?:\(?(\d{3})\)?[-\s]?)?(\d{3,4})[-\s]?(\d{4})'
)
RE_IP       = re.compile(r'\b(\d{1,3}\.){3}\d{1,3}\b')
RE_DOMAIN   = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
RE_PLATE_MX = re.compile(r'\b([A-Z]{3}[-\s]?\d{3,4}[A-Z]?|[A-Z]{2,3}[-\s]?\d{2,4}[-\s]?[A-Z]{0,2})\b')
RE_BTC      = re.compile(r'\b([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b')
RE_ETH      = re.compile(r'\b0x[0-9a-fA-F]{40}\b')
RE_ONION    = re.compile(r'\b([a-z2-7]{16,56}\.onion)\b')
RE_USERNAME = re.compile(r'^[a-zA-Z0-9_\.\-]{2,32}$')

LADAS_MX = {
    "55": "Ciudad de México", "33": "Guadalajara", "81": "Monterrey",
    "664": "Tijuana", "667": "Culiacán", "668": "Los Mochis",
    "614": "Chihuahua", "461": "Irapuato", "462": "Salamanca",
    "449": "Aguascalientes", "442": "Querétaro", "222": "Puebla",
    "229": "Veracruz", "998": "Cancún", "999": "Mérida",
    "744": "Acapulco", "951": "Oaxaca", "961": "Tuxtla Gutiérrez",
    "312": "Colima", "376": "Chapala", "777": "Cuernavaca",
    "341": "Jiquilpan", "921": "Coatzacoalcos", "782": "Poza Rica",
}


# ─── 01: TargetSanitizer ─────────────────────────────────────────────────────

class TargetSanitizer(BaseModule):
    MODULE_ID       = "01"
    MODULE_NAME     = "TargetSanitizer"
    MODULE_PRIORITY = 1
    MODULE_PHASE    = "recon"

    async def _run(self, target: Target):
        t = target.raw.strip()

        if RE_EMAIL.match(t):
            target.type = TargetType.EMAIL
            self.emit("email", t, {"normalized": True}, ["local"])

        elif RE_BTC.match(t):
            target.type = TargetType.CRYPTO
            self.emit("crypto", t, {"subtype": "btc"}, ["local"])

        elif RE_ETH.match(t):
            target.type = TargetType.CRYPTO
            self.emit("crypto", t, {"subtype": "eth"}, ["local"])

        elif RE_ONION.match(t):
            target.type = TargetType.ONION
            self.emit("onion", t, {}, ["local"])

        elif RE_IP.fullmatch(t):
            target.type = TargetType.IP
            parts = [int(p) for p in t.split(".")]
            private = (parts[0] == 10 or
                       (parts[0] == 172 and 16 <= parts[1] <= 31) or
                       (parts[0] == 192 and parts[1] == 168))
            self.emit("ip", t, {"is_private": private}, ["local"])

        elif RE_PLATE_MX.match(t.upper()):
            target.type = TargetType.PLATE
            self.emit("plate", t.upper(), {"country": "MX"}, ["local"])

        elif RE_DOMAIN.match(t) and "." in t and not t.startswith("@"):
            target.type = TargetType.DOMAIN
            self.emit("domain", t.lstrip("www."), {}, ["local"])

        elif m := RE_PHONE_MX.search(re.sub(r'[\s\-\(\)\.]', '', t)):
            target.type = TargetType.PHONE
            clean = re.sub(r'[\s\-\(\)]', '', t)
            lada3 = clean[:3] if len(clean) >= 3 else ""
            lada2 = clean[:2] if len(clean) >= 2 else ""
            city  = LADAS_MX.get(lada3) or LADAS_MX.get(lada2, "Desconocida")
            self.emit("phone", clean, {
                "country": "MX",
                "lada":    lada3 or lada2,
                "city":    city,
            }, ["local"])

        elif " " in t and len(t.split()) >= 2:
            target.type = TargetType.PERSON
            self.emit("person", t.title(), {"raw_name": t}, ["local"])

        else:
            target.type = TargetType.USERNAME
            self.emit("username", t, {}, ["local"])

        target.normalized = self._emitted[0]["value"] if self._emitted else t


# ─── 02: PassiveDNS ──────────────────────────────────────────────────────────

class PassiveDNS(BaseModule):
    MODULE_ID       = "02"
    MODULE_NAME     = "PassiveDNS"
    MODULE_PRIORITY = 2
    MODULE_PHASE    = "recon"
    ENTITY_TYPES    = ["ip", "domain", "asn"]

    APPLICABLE = {TargetType.DOMAIN, TargetType.IP, TargetType.URL}

    async def _run(self, target: Target):
        if target.type not in self.APPLICABLE:
            return
        domain = target.normalized.split("/")[0].lstrip("www.")

        # HackerTarget DNS lookup
        data = await self.get_json(
            f"https://api.hackertarget.com/dnslookup/?q={domain}&output=json"
        )
        if isinstance(data, list):
            for record in data:
                rtype = record.get("type", "")
                value = record.get("value", "")
                if rtype == "A" and RE_IP.match(value):
                    self.emit("ip", value, {
                        "dns_record": "A", "hostname": domain
                    }, ["hackertarget"])
                elif rtype == "MX":
                    self.emit("domain", value.rstrip("."), {
                        "dns_record": "MX", "for_domain": domain
                    }, ["hackertarget"])
                elif rtype == "NS":
                    self.emit("domain", value.rstrip("."), {
                        "dns_record": "NS", "for_domain": domain
                    }, ["hackertarget"])

        # Reverse DNS
        if target.type == TargetType.IP:
            rdns = await self.get_json(
                f"https://api.hackertarget.com/reversedns/?q={target.normalized}"
            )
            if rdns and "_text" in rdns:
                for line in rdns["_text"].splitlines():
                    if domain_match := RE_DOMAIN.search(line):
                        self.emit("domain", domain_match.group(), {
                            "dns_record": "PTR", "ip": target.normalized
                        }, ["hackertarget"])


# ─── 03: WhoisRDAP ───────────────────────────────────────────────────────────

class WhoisRDAP(BaseModule):
    MODULE_ID       = "03"
    MODULE_NAME     = "WhoisRDAP"
    MODULE_PRIORITY = 2
    MODULE_PHASE    = "recon"
    ENTITY_TYPES    = ["domain", "email", "org", "person"]

    APPLICABLE = {TargetType.DOMAIN, TargetType.IP}

    async def _run(self, target: Target):
        if target.type not in self.APPLICABLE:
            return
        domain = target.normalized.split("/")[0].lstrip("www.")

        # IANA RDAP
        if target.type == TargetType.DOMAIN:
            rdap = await self.get_json(f"https://rdap.org/domain/{domain}")
        else:
            rdap = await self.get_json(f"https://rdap.org/ip/{target.normalized}")

        if not rdap:
            return

        # Extraer entidades RDAP
        for entity in rdap.get("entities", []):
            vcard = entity.get("vcardArray", [None, []])[1]
            for item in vcard:
                if not isinstance(item, list):
                    continue
                prop = item[0]
                val  = item[3] if len(item) > 3 else None
                if not val:
                    continue
                if prop == "email" and isinstance(val, str):
                    self.emit("email", val, {
                        "source_context": "whois_rdap", "domain": domain
                    }, ["iana_rdap"])
                elif prop == "fn" and isinstance(val, str):
                    self.emit("person", val, {
                        "source_context": "whois_registrant"
                    }, ["iana_rdap"])
                elif prop == "org" and isinstance(val, str):
                    self.emit("org", val, {"domain": domain}, ["iana_rdap"])
                elif prop == "tel" and isinstance(val, str):
                    self.emit("phone", val, {
                        "source_context": "whois_rdap"
                    }, ["iana_rdap"])

        # Fechas
        events = rdap.get("events", [])
        for ev in events:
            if ev.get("eventAction") == "registration":
                self.emit("other", ev.get("eventDate", ""), {
                    "type": "registration_date", "domain": domain
                }, ["iana_rdap"])


# ─── 04: IP2ASN ──────────────────────────────────────────────────────────────

class IP2ASN(BaseModule):
    MODULE_ID       = "04"
    MODULE_NAME     = "IP2ASN"
    MODULE_PRIORITY = 3
    MODULE_PHASE    = "recon"
    ENTITY_TYPES    = ["asn", "org", "location"]

    APPLICABLE = {TargetType.IP, TargetType.DOMAIN}

    async def _run(self, target: Target):
        if target.type not in self.APPLICABLE:
            return
        ip = target.normalized

        # BGPView
        data = await self.get_json(f"https://api.bgpview.io/ip/{ip}")
        if not data or "data" not in data:
            return
        d = data["data"]
        prefixes = d.get("prefixes", [])
        for prefix in prefixes:
            asn_obj = prefix.get("asn", {})
            asn_num = asn_obj.get("asn")
            asn_name = asn_obj.get("description", "")
            if asn_num:
                self.emit("asn", f"AS{asn_num}", {
                    "name": asn_name,
                    "prefix": prefix.get("prefix", ""),
                    "country": prefix.get("country_code", ""),
                }, ["bgpview"])
            if asn_name:
                self.emit("org", asn_name, {
                    "asn": f"AS{asn_num}", "ip": ip
                }, ["bgpview"])

        # ipinfo
        if self.has_key("ipinfo"):
            info = await self.get_json(
                f"https://ipinfo.io/{ip}/json",
                headers={"Authorization": f"Bearer {self.key('ipinfo')}"}
            )
        else:
            info = await self.get_json(f"https://ipinfo.io/{ip}/json")

        if info:
            if city := info.get("city"):
                region = info.get("region", "")
                country = info.get("country", "")
                self.emit("location", f"{city}, {region}, {country}", {
                    "ip": ip, "type": "geo"
                }, ["ipinfo"])
            if org := info.get("org"):
                self.emit("org", org, {"ip": ip}, ["ipinfo"])


# ─── 05: SubdomainEnum ───────────────────────────────────────────────────────

class SubdomainEnum(BaseModule):
    MODULE_ID       = "05"
    MODULE_NAME     = "SubdomainEnum"
    MODULE_PRIORITY = 3
    MODULE_PHASE    = "recon"
    ENTITY_TYPES    = ["domain"]

    APPLICABLE = {TargetType.DOMAIN}

    async def _run(self, target: Target):
        if target.type not in self.APPLICABLE:
            return
        domain = target.normalized.split("/")[0].lstrip("www.")

        # crt.sh — Certificate Transparency logs
        data = await self.get_json(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
        )
        seen: set[str] = set()
        if isinstance(data, list):
            for cert in data:
                names = cert.get("name_value", "")
                for name in names.splitlines():
                    name = name.strip().lstrip("*.")
                    if name and name.endswith(f".{domain}") and name not in seen:
                        seen.add(name)
                        self.emit("domain", name, {
                            "subdomain_of": domain,
                            "cert_id": cert.get("id"),
                        }, ["crt.sh"])

        # HackerTarget subdomain lookup
        result = await self.get_text(
            f"https://api.hackertarget.com/hostsearch/?q={domain}"
        )
        if result:
            for line in result.splitlines():
                sub = line.split(",")[0].strip()
                if sub and sub.endswith(f".{domain}") and sub not in seen:
                    seen.add(sub)
                    self.emit("domain", sub, {
                        "subdomain_of": domain
                    }, ["hackertarget"])


# ─── 06: PortsServices ───────────────────────────────────────────────────────

class PortsServices(BaseModule):
    MODULE_ID       = "06"
    MODULE_NAME     = "PortsServices"
    MODULE_PRIORITY = 4
    MODULE_PHASE    = "recon"
    ENTITY_TYPES    = ["ip", "cve", "other"]

    APPLICABLE = {TargetType.IP, TargetType.DOMAIN}

    async def _run(self, target: Target):
        if target.type not in self.APPLICABLE:
            return
        ip = target.normalized

        # Shodan InternetDB (sin key, pública)
        data = await self.get_json(f"https://internetdb.shodan.io/{ip}")
        if not data:
            return

        ports = data.get("ports", [])
        if ports:
            self.emit("other", ",".join(str(p) for p in ports), {
                "type": "open_ports", "ip": ip, "count": len(ports)
            }, ["shodan"])

        for cve in data.get("vulns", []):
            self.emit("cve", cve, {
                "ip": ip, "open_ports": ports
            }, ["shodan"])

        for hostname in data.get("hostnames", []):
            self.emit("domain", hostname, {
                "ip": ip, "source_context": "shodan_hostname"
            }, ["shodan"])

        if tags := data.get("tags"):
            reputation = "malicious" if "malicious" in tags else (
                "suspicious" if "scanner" in tags or "vpn" in tags else "clean"
            )
            self.emit("ip", ip, {
                "reputation": reputation,
                "tags": tags,
                "ports": ports,
            }, ["shodan"])


# ─── 07: TechFingerprint ─────────────────────────────────────────────────────

class TechFingerprint(BaseModule):
    MODULE_ID       = "07"
    MODULE_NAME     = "TechFingerprint"
    MODULE_PRIORITY = 4
    MODULE_PHASE    = "recon"
    ENTITY_TYPES    = ["other"]

    APPLICABLE = {TargetType.DOMAIN, TargetType.URL}

    TECH_SIGNATURES = {
        "WordPress":    ["wp-content", "wp-includes", "xmlrpc.php"],
        "Shopify":      ["cdn.shopify.com", "myshopify.com"],
        "Cloudflare":   ["cloudflare", "__cfduid", "cf-ray"],
        "Laravel":      ["laravel_session", "XSRF-TOKEN"],
        "Django":       ["csrftoken", "djdt", "django"],
        "React":        ["__REACT_QUERY", "_reactFiber", "react-root"],
        "jQuery":       ["jquery.min.js", "jquery.js"],
        "Bootstrap":    ["bootstrap.min.css", "bootstrap.min.js"],
        "nginx":        ["server: nginx", "nginx"],
        "Apache":       ["server: apache", "apache"],
    }

    async def _run(self, target: Target):
        if target.type not in self.APPLICABLE:
            return
        url = target.normalized
        if not url.startswith("http"):
            url = f"https://{url}"

        result = await self.get_text(url, headers={"Accept": "text/html"})
        if not result:
            return
        lower = result.lower()
        found: list[str] = []
        for tech, signatures in self.TECH_SIGNATURES.items():
            if any(sig.lower() in lower for sig in signatures):
                found.append(tech)
        if found:
            self.emit("other", ",".join(found), {
                "type": "tech_stack",
                "domain": target.normalized,
            }, ["http_direct"])


# ─── 08: EmailPhoneHarvester ─────────────────────────────────────────────────

class EmailPhoneHarvester(BaseModule):
    MODULE_ID       = "08"
    MODULE_NAME     = "EmailPhoneHarvester"
    MODULE_PRIORITY = 4
    MODULE_PHASE    = "recon"
    ENTITY_TYPES    = ["email", "phone"]

    APPLICABLE = {TargetType.DOMAIN, TargetType.URL}

    async def _run(self, target: Target):
        if target.type not in self.APPLICABLE:
            return
        domain = target.normalized.split("/")[0].lstrip("www.")

        # Hunter.io
        if self.has_key("hunter"):
            data = await self.get_json(
                "https://api.hunter.io/v2/domain-search",
                params={
                    "domain":  domain,
                    "api_key": self.key("hunter"),
                    "limit":   10,
                },
            )
            if data and "data" in data:
                for email_obj in data["data"].get("emails", []):
                    email = email_obj.get("value", "")
                    if email:
                        self.emit("email", email, {
                            "first_name":  email_obj.get("first_name"),
                            "last_name":   email_obj.get("last_name"),
                            "position":    email_obj.get("position"),
                            "confidence":  email_obj.get("confidence"),
                            "domain":      domain,
                            "source_count": 1,
                        }, ["hunter"])

        # Web scraping básico
        url = f"https://{domain}"
        html = await self.get_text(url)
        if html:
            for email in set(RE_EMAIL.findall(html)):
                if domain in email or len(email) < 60:
                    self.emit("email", email, {
                        "scraped_from": url
                    }, ["web_scrape"])
            for phone in set(RE_PHONE_MX.findall(html)):
                raw_phone = "".join(phone)
                if len(raw_phone) >= 7:
                    self.emit("phone", raw_phone, {
                        "scraped_from": url, "country": "MX"
                    }, ["web_scrape"])
