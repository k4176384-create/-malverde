"""
Leviathan OSINT v4.0 — Módulos People (09–18)
Enumeración de identidades en plataformas públicas.
"""
from __future__ import annotations
import asyncio
import re
import logging
from modules.base_module import BaseModule
from core.models import Target, TargetType

log = logging.getLogger("leviathan.people")

RE_EMAIL = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
RE_PHONE = re.compile(r'[\+]?[\d\s\-\(\)]{7,20}')


# ─── 09: UsernameEnum ────────────────────────────────────────────────────────

PLATFORMS = {
    "github":    "https://api.github.com/users/{}",
    "gitlab":    "https://gitlab.com/{}",
    "twitter":   "https://twitter.com/{}",
    "instagram": "https://www.instagram.com/{}/",
    "tiktok":    "https://www.tiktok.com/@{}",
    "reddit":    "https://www.reddit.com/user/{}/about.json",
    "youtube":   "https://www.youtube.com/@{}",
    "twitch":    "https://www.twitch.tv/{}",
    "pinterest": "https://www.pinterest.com/{}/",
    "medium":    "https://medium.com/@{}",
    "dev.to":    "https://dev.to/{}",
    "keybase":   "https://keybase.io/{}/key.asc",
    "telegram":  "https://t.me/{}",
    "producthunt": "https://www.producthunt.com/@{}",
    "hackernews": "https://hacker-news.firebaseio.com/v0/user/{}.json",
    "npm":       "https://www.npmjs.com/~{}",
    "pypi":      "https://pypi.org/user/{}/",
    "docker":    "https://hub.docker.com/u/{}",
    "linktree":  "https://linktr.ee/{}",
    "about.me":  "https://about.me/{}",
    "gravatar":  "https://en.gravatar.com/{}",
    "soundcloud": "https://soundcloud.com/{}",
    "spotify":   "https://open.spotify.com/user/{}",
    "behance":   "https://www.behance.net/{}",
    "dribbble":  "https://dribbble.com/{}",
    "flickr":    "https://www.flickr.com/people/{}",
    "vimeo":     "https://vimeo.com/{}",
    "steam":     "https://steamcommunity.com/id/{}",
    "xbox":      "https://xboxgamertag.com/search/{}",
    "chess.com": "https://api.chess.com/pub/player/{}",
}


class UsernameEnum(BaseModule):
    MODULE_ID       = "09"
    MODULE_NAME     = "UsernameEnum"
    MODULE_PRIORITY = 2
    MODULE_PHASE    = "people"
    ENTITY_TYPES    = ["username", "url"]

    APPLICABLE = {TargetType.USERNAME, TargetType.EMAIL}

    async def _run(self, target: Target):
        if target.type not in self.APPLICABLE:
            return
        username = target.normalized
        if target.type == TargetType.EMAIL:
            username = username.split("@")[0]

        tasks = [self._check_platform(name, url_tpl, username)
                 for name, url_tpl in PLATFORMS.items()]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_platform(self, platform: str, url_tpl: str, username: str):
        url = url_tpl.format(username)
        try:
            result = await self.get_json(url, timeout=8.0)
            if result and not result.get("message") and not result.get("error"):
                self.emit("username", username, {
                    "platform": platform,
                    "profile_url": url,
                    "exists": True,
                }, [platform])
                self.emit("url", url, {
                    "platform": platform,
                    "username": username,
                }, [platform])
        except Exception:
            pass


# ─── 10: SocialScrape ────────────────────────────────────────────────────────

class SocialScrape(BaseModule):
    MODULE_ID       = "10"
    MODULE_NAME     = "SocialScrape"
    MODULE_PRIORITY = 3
    MODULE_PHASE    = "people"
    ENTITY_TYPES    = ["person", "email", "url", "org"]

    APPLICABLE = {TargetType.USERNAME, TargetType.EMAIL}

    async def _run(self, target: Target):
        if target.type not in self.APPLICABLE:
            return
        username = target.normalized
        if target.type == TargetType.EMAIL:
            username = username.split("@")[0]

        # GitHub API pública
        gh = await self.get_json(
            f"https://api.github.com/users/{username}",
            headers={"Authorization": f"token {self.key('github')}"} if self.has_key("github") else None,
        )
        if gh and gh.get("login"):
            if name := gh.get("name"):
                self.emit("person", name, {
                    "platform": "github", "username": username,
                    "avatar_url": gh.get("avatar_url"),
                }, ["github_api"])
            if email := gh.get("email"):
                self.emit("email", email, {
                    "platform": "github", "username": username,
                    "source_count": 1,
                }, ["github_api"])
            if company := gh.get("company"):
                self.emit("org", company.strip("@"), {
                    "platform": "github"
                }, ["github_api"])
            if blog := gh.get("blog"):
                self.emit("url", blog, {"platform": "github"}, ["github_api"])
            if location := gh.get("location"):
                self.emit("location", location, {
                    "platform": "github", "type": "self_reported"
                }, ["github_api"])
            if bio := gh.get("bio"):
                # Extraer emails/phones de bio
                for email in RE_EMAIL.findall(bio):
                    self.emit("email", email, {
                        "scraped_from": "github_bio"
                    }, ["github_api"])

        # Telegram público
        tg = await self.get_text(f"https://t.me/{username}")
        if tg and "tgme_page_title" in tg:
            title_match = re.search(r'<div class="tgme_page_title"><span>(.*?)</span>', tg)
            desc_match  = re.search(r'<div class="tgme_page_description">(.*?)</div>', tg, re.DOTALL)
            if title_match:
                self.emit("person", re.sub(r'<[^>]+>', '', title_match.group(1)), {
                    "platform": "telegram", "username": username,
                    "profile_url": f"https://t.me/{username}",
                }, ["telegram_direct"])
            if desc_match:
                desc = re.sub(r'<[^>]+>', '', desc_match.group(1)).strip()
                for email in RE_EMAIL.findall(desc):
                    self.emit("email", email, {
                        "scraped_from": "telegram_bio"
                    }, ["telegram_direct"])

        # Reddit JSON
        reddit = await self.get_json(
            f"https://www.reddit.com/user/{username}/about.json",
            headers={"Accept": "application/json"},
        )
        if reddit and "data" in reddit:
            d = reddit["data"]
            self.emit("username", username, {
                "platform": "reddit",
                "karma_post": d.get("link_karma", 0),
                "karma_comment": d.get("comment_karma", 0),
                "account_age_days": (
                    (1714500000 - d.get("created_utc", 1714500000)) / 86400
                ),
            }, ["github_api"])


# ─── 11: PhotoReverse ────────────────────────────────────────────────────────

class PhotoReverse(BaseModule):
    MODULE_ID       = "11"
    MODULE_NAME     = "PhotoReverse"
    MODULE_PRIORITY = 5
    MODULE_PHASE    = "people"
    ENTITY_TYPES    = ["url"]

    APPLICABLE = {TargetType.USERNAME}

    async def _run(self, target: Target):
        if target.type not in self.APPLICABLE:
            return
        username = target.normalized

        # Buscar avatar en GitHub y generar links de búsqueda inversa
        gh = await self.get_json(f"https://api.github.com/users/{username}")
        if gh and gh.get("avatar_url"):
            avatar_url = gh["avatar_url"]
            for engine, url_tpl in {
                "google_lens": f"https://lens.google.com/uploadbyurl?url={avatar_url}",
                "yandex":      f"https://yandex.com/images/search?rpt=imageview&url={avatar_url}",
                "tineye":      f"https://tineye.com/search?url={avatar_url}",
            }.items():
                self.emit("url", url_tpl, {
                    "type":    "reverse_image_search",
                    "engine":  engine,
                    "source":  "github_avatar",
                    "image":   avatar_url,
                }, ["github_api"])


# ─── 12: FamilyMapper ────────────────────────────────────────────────────────

class FamilyMapper(BaseModule):
    MODULE_ID       = "12"
    MODULE_NAME     = "FamilyMapper"
    MODULE_PRIORITY = 5
    MODULE_PHASE    = "people"
    ENTITY_TYPES    = ["username", "person", "org"]

    APPLICABLE = {TargetType.USERNAME}

    async def _run(self, target: Target):
        if target.type not in self.APPLICABLE:
            return
        username = target.normalized

        # GitHub seguidores y organizaciones
        headers = {"Authorization": f"token {self.key('github')}"} if self.has_key("github") else None

        orgs = await self.get_json(
            f"https://api.github.com/users/{username}/orgs",
            headers=headers,
        )
        if isinstance(orgs, list):
            for org in orgs[:10]:
                self.emit("org", org.get("login", ""), {
                    "platform": "github",
                    "avatar":   org.get("avatar_url"),
                    "member":   username,
                }, ["github_api"])

        followers = await self.get_json(
            f"https://api.github.com/users/{username}/followers?per_page=20",
            headers=headers,
        )
        if isinstance(followers, list):
            for f in followers[:10]:
                self.emit("username", f.get("login", ""), {
                    "platform": "github",
                    "rel_type": "follower_of",
                    "rel_target": username,
                }, ["github_api"])


# ─── 13: EmploymentHistory ───────────────────────────────────────────────────

class EmploymentHistory(BaseModule):
    MODULE_ID       = "13"
    MODULE_NAME     = "EmploymentHistory"
    MODULE_PRIORITY = 5
    MODULE_PHASE    = "people"
    ENTITY_TYPES    = ["org", "other"]

    APPLICABLE = {TargetType.USERNAME, TargetType.EMAIL}

    async def _run(self, target: Target):
        if target.type not in self.APPLICABLE:
            return
        username = target.normalized
        if target.type == TargetType.EMAIL:
            username = username.split("@")[0]

        # GitHub repos — infer employer/projects
        headers = {"Authorization": f"token {self.key('github')}"} if self.has_key("github") else None
        repos = await self.get_json(
            f"https://api.github.com/users/{username}/repos?per_page=20&sort=updated",
            headers=headers,
        )
        if isinstance(repos, list):
            langs = {}
            for repo in repos:
                lang = repo.get("language")
                if lang:
                    langs[lang] = langs.get(lang, 0) + 1
            if langs:
                top_lang = max(langs, key=langs.get)
                self.emit("other", top_lang, {
                    "type": "primary_language",
                    "username": username,
                    "all_langs": langs,
                }, ["github_api"])

        # Keybase
        kb = await self.get_json(f"https://keybase.io/{username}/key.asc")
        if kb and "_text" in kb:
            self.emit("username", username, {
                "platform": "keybase",
                "has_pgp_key": True,
            }, ["github_api"])


# ─── 14: EducationCerts ──────────────────────────────────────────────────────

class EducationCerts(BaseModule):
    MODULE_ID       = "14"
    MODULE_NAME     = "EducationCerts"
    MODULE_PRIORITY = 6
    MODULE_PHASE    = "people"
    ENTITY_TYPES    = ["org", "url"]

    APPLICABLE = {TargetType.PERSON, TargetType.USERNAME, TargetType.EMAIL}

    async def _run(self, target: Target):
        if target.type not in self.APPLICABLE:
            return
        query = target.normalized
        if target.type == TargetType.EMAIL:
            query = query.split("@")[0]

        # Google Scholar search (public)
        result = await self.get_text(
            "https://scholar.google.com/scholar",
            params={"q": query, "hl": "es"},
        )
        if result and "scholar" in result.lower():
            # Extraer nombres de instituciones académicas
            affil_match = re.findall(r'<span class="gs_aff">(.*?)</span>', result)
            for aff in affil_match[:5]:
                clean = re.sub(r'<[^>]+>', '', aff).strip()
                if clean:
                    self.emit("org", clean, {
                        "type": "academic_affiliation",
                        "query": query,
                    }, ["web_scrape"])


# ─── 15: VehiclePlate ────────────────────────────────────────────────────────

class VehiclePlate(BaseModule):
    MODULE_ID       = "15"
    MODULE_NAME     = "VehiclePlate"
    MODULE_PRIORITY = 4
    MODULE_PHASE    = "people"
    ENTITY_TYPES    = ["plate", "other"]

    APPLICABLE = {TargetType.PLATE}

    ESTADO_CODES = {
        "A": "Aguascalientes", "B": "Baja California", "C": "Coahuila",
        "CH": "Chihuahua", "CDMX": "Ciudad de México", "CL": "Colima",
        "CS": "Chiapas", "D": "Durango", "GR": "Guerrero", "GT": "Guanajuato",
        "HG": "Hidalgo", "JC": "Jalisco", "MC": "Estado de México",
        "MN": "Michoacán", "MS": "Morelos", "NA": "Nayarit", "NL": "Nuevo León",
        "OA": "Oaxaca", "PL": "Puebla", "QR": "Quintana Roo", "QT": "Querétaro",
        "SL": "San Luis Potosí", "SN": "Sinaloa", "SO": "Sonora",
        "TB": "Tabasco", "TL": "Tlaxcala", "TS": "Tamaulipas",
        "VZ": "Veracruz", "YN": "Yucatán", "ZS": "Zacatecas",
    }

    async def _run(self, target: Target):
        if target.type != TargetType.PLATE:
            return
        plate = target.normalized.upper().replace("-", "").replace(" ", "")

        # REPUVE consulta pública
        result = await self.get_json(
            "https://www.repuve.gob.mx:8443/ws/rest/consultaPublica",
            params={"placa": plate},
        )
        if result and "estatus" in result:
            self.emit("plate", plate, {
                "status": result.get("estatus"),
                "model":  result.get("modelo"),
                "brand":  result.get("marca"),
                "year":   result.get("anio"),
                "country": "MX",
                "source": "repuve",
            }, ["repuve"])

        # Inferir estado por prefijo
        for code, estado in self.ESTADO_CODES.items():
            if plate.startswith(code):
                self.emit("location", estado, {
                    "type": "plate_state_mx",
                    "plate": plate,
                    "code": code,
                }, ["local_db"])
                break

        self.emit("plate", plate, {
            "country": "MX",
            "normalized": plate,
        }, ["local"])


# ─── 16: CriminalRecords ─────────────────────────────────────────────────────

class CriminalRecords(BaseModule):
    MODULE_ID       = "16"
    MODULE_NAME     = "CriminalRecords"
    MODULE_PRIORITY = 6
    MODULE_PHASE    = "people"
    ENTITY_TYPES    = ["other"]
    # Solo listas públicas: INTERPOL Red Notices, OFAC SDN, SAT México

    APPLICABLE = {TargetType.PERSON, TargetType.EMAIL, TargetType.USERNAME}

    async def _run(self, target: Target):
        if target.type not in self.APPLICABLE:
            return
        name = target.normalized.replace(",", " ").strip()

        # INTERPOL Red Notices — API pública
        interpol = await self.get_json(
            "https://ws-public.interpol.int/notices/v1/red",
            params={"name": name, "resultPerPage": 5},
        )
        if interpol and "data" in interpol:
            notices = interpol["data"].get("notices", [])
            for notice in notices:
                self.emit("other", notice.get("entity_id", ""), {
                    "type":     "interpol_red_notice",
                    "name":     notice.get("name", ""),
                    "url":      notice.get("_links", {}).get("self", {}).get("href", ""),
                    "source":   "interpol",
                    "criminal_record": True,
                }, ["interpol_db"])

        # OFAC SDN List — Tesoro USA
        ofac = await self.get_json(
            "https://api.ofac-api.com/v3/search",
            params={"program": "ALL", "name": name, "limit": 5},
        )
        if ofac and "matches" in ofac:
            for match in ofac["matches"][:3]:
                self.emit("other", match.get("name", ""), {
                    "type":     "ofac_sdn_match",
                    "programs": match.get("programs", []),
                    "score":    match.get("score", 0),
                    "source":   "ofac",
                    "criminal_record": True,
                }, ["ofac_db"])


# ─── 17: LeaksPaste ──────────────────────────────────────────────────────────

class LeaksPaste(BaseModule):
    MODULE_ID       = "17"
    MODULE_NAME     = "LeaksPaste"
    MODULE_PRIORITY = 3
    MODULE_PHASE    = "people"
    ENTITY_TYPES    = ["breach", "email", "credential"]

    APPLICABLE = {TargetType.EMAIL, TargetType.USERNAME}

    async def _run(self, target: Target):
        if target.type not in self.APPLICABLE:
            return

        if target.type == TargetType.EMAIL:
            email = target.normalized

            # HaveIBeenPwned
            if self.has_key("hibp"):
                data = await self.get_json(
                    f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                    headers={
                        "hibp-api-key": self.key("hibp"),
                        "User-Agent":   "Leviathan-OSINT-Framework",
                    },
                )
                if isinstance(data, list):
                    for breach in data:
                        self.emit("breach", breach.get("Name", ""), {
                            "email":        email,
                            "domain":       breach.get("Domain", ""),
                            "date":         breach.get("BreachDate", ""),
                            "data_classes": breach.get("DataClasses", []),
                            "is_sensitive": breach.get("IsSensitive", False),
                            "emails": [email],
                            "breach_count": len(data),
                            "breach_date_months": 12,  # estimado
                        }, ["hibp"])
                    if data:
                        self.emit("email", email, {
                            "breach_count": len(data),
                            "breach_date_months": 12,
                            "breaches": [b.get("Name") for b in data],
                        }, ["hibp"])

            # EmailRep.io (free tier)
            emailrep = await self.get_json(
                f"https://emailrep.io/{email}",
                headers={"User-Agent": "Leviathan-OSINT-Framework"},
            )
            if emailrep and "reputation" in emailrep:
                self.emit("email", email, {
                    "reputation":    emailrep.get("reputation", "unknown"),
                    "suspicious":    emailrep.get("suspicious", False),
                    "spam":          emailrep.get("details", {}).get("spam", False),
                    "source_count":  2,
                }, ["emailrep"])


# ─── 18: DarkwebLeakCorrelator ───────────────────────────────────────────────

class DarkwebLeakCorrelator(BaseModule):
    MODULE_ID       = "18"
    MODULE_NAME     = "DarkwebLeakCorrelator"
    MODULE_PRIORITY = 5
    MODULE_PHASE    = "people"
    ENTITY_TYPES    = ["snippet", "breach"]

    APPLICABLE = {TargetType.EMAIL, TargetType.USERNAME, TargetType.DOMAIN}

    async def _run(self, target: Target):
        if target.type not in self.APPLICABLE:
            return
        query = target.normalized

        # psbdmp.ws — índice público de pastes
        result = await self.get_json(
            f"https://psbdmp.ws/api/v3/search/{query}",
        )
        if result and "data" in result:
            for paste in result["data"][:5]:
                self.emit("snippet", paste.get("id", ""), {
                    "source":    "pastebin",
                    "url":       f"https://pastebin.com/{paste.get('id', '')}",
                    "date":      paste.get("time", ""),
                    "contains":  query,
                    "darkweb_mention": True,
                }, ["pastebin_index"])
