"""
Leviathan OSINT v4.0 — ProfileComposite
El perfil que se cuenta solo. Sin etiquetas manuales.
"""
from __future__ import annotations
import re
import logging
import time
from collections import Counter
from core.models import EntityRecord, EntityType, Verdict, ScanState

log = logging.getLogger("leviathan.profile")


class ProfileCompositeBuilder:
    """
    Cuando hay 3+ entidades vinculadas al mismo pivot,
    construye automáticamente un perfil enriquecido con narrativa natural.
    """

    MIN_ENTITIES = 3

    def build(self, state: ScanState) -> dict:
        entities = state.trusted_entities()
        if len(entities) < self.MIN_ENTITIES:
            return {}

        profile: dict = {
            "pivot":           self._find_pivot(entities),
            "identity":        self._extract_identity(entities),
            "digital_age":     self._extract_digital_age(entities),
            "platforms":       self._extract_platforms(entities),
            "location":        self._infer_location(entities),
            "ecommerce":       self._extract_ecommerce(entities),
            "breaches":        self._extract_breaches(entities),
            "behavioral_tags": self._extract_behavioral_tags(entities),
            "phones":          self._extract_phones(entities),
            "emails":          self._extract_emails(entities),
            "domains":         self._extract_domains(entities),
            "risk_score":      state.risk_score,
            "risk_level":      state.risk_level.value,
        }
        profile["narrative"] = self._build_narrative(profile, state)
        return profile

    def _find_pivot(self, entities: list[EntityRecord]) -> str:
        """La entidad de alta confianza (≥0.75) que sirve como nodo central."""
        for etype in (EntityType.EMAIL, EntityType.PHONE, EntityType.USERNAME):
            candidates = [e for e in entities
                          if e.type == etype and e.confidence >= 0.75]
            if candidates:
                return max(candidates, key=lambda x: x.confidence).value
        return entities[0].value if entities else ""

    def _extract_identity(self, entities: list[EntityRecord]) -> dict:
        names     = []
        aliases   = []
        for e in entities:
            if e.type == EntityType.PERSON:
                names.append(e.value)
            elif e.type == EntityType.USERNAME:
                aliases.append(f"{e.value} ({e.metadata.get('platform', '?')})")
        return {
            "names":   list(dict.fromkeys(names))[:5],
            "aliases": list(dict.fromkeys(aliases))[:8],
        }

    def _extract_digital_age(self, entities: list[EntityRecord]) -> dict:
        dates = []
        for e in entities:
            for key in ("date", "breach_date", "registration_date", "first_seen"):
                if d := e.metadata.get(key):
                    dates.append(str(d))
        if not dates:
            return {"first_seen": "Desconocido", "activity_years": 0}
        dates.sort()
        first = dates[0]
        try:
            year = int(first[:4])
            current_year = 2025
            years = current_year - year
        except Exception:
            years = 0
        return {"first_seen": first, "activity_years": max(0, years)}

    def _extract_platforms(self, entities: list[EntityRecord]) -> list[str]:
        platforms = set()
        for e in entities:
            if p := e.metadata.get("platform"):
                platforms.add(p)
        return sorted(platforms)

    def _infer_location(self, entities: list[EntityRecord]) -> str:
        locations: list[str] = []
        for e in entities:
            if e.type == EntityType.LOCATION:
                locations.append(e.value)
            elif city := e.metadata.get("city"):
                locations.append(str(city))
            elif lada := e.metadata.get("lada"):
                locations.append(e.metadata.get("lada_city", "México"))
        if not locations:
            return "Desconocida"
        most_common = Counter(locations).most_common(1)
        return most_common[0][0] if most_common else "Desconocida"

    def _extract_ecommerce(self, entities: list[EntityRecord]) -> list[dict]:
        results = []
        for e in entities:
            if e.metadata.get("ecommerce_platform"):
                results.append({
                    "platform": e.metadata["ecommerce_platform"],
                    "since":    e.metadata.get("since", ""),
                    "zones":    e.metadata.get("delivery_zones", []),
                })
        return results

    def _extract_breaches(self, entities: list[EntityRecord]) -> list[dict]:
        breaches = []
        seen = set()
        for e in entities:
            if e.type == EntityType.BREACH and e.value not in seen:
                seen.add(e.value)
                breaches.append({
                    "name":        e.value,
                    "date":        e.metadata.get("date", ""),
                    "data_classes": e.metadata.get("data_classes", []),
                    "has_credentials": "Passwords" in e.metadata.get("data_classes", []),
                })
            elif "BREACH_HIT" in e.flags:
                for breach_name in e.metadata.get("breaches", []):
                    if breach_name not in seen:
                        seen.add(breach_name)
                        breaches.append({
                            "name": breach_name,
                            "date": "",
                            "has_credentials": True,
                        })
        return breaches[:10]

    def _extract_behavioral_tags(self, entities: list[EntityRecord]) -> list[str]:
        """Detecta patrones de comportamiento neutrales a partir de datos públicos."""
        tags: set[str] = set()

        # Actividad en mensajería
        messenger_platforms = {"telegram", "whatsapp", "signal"}
        platform_set = {e.metadata.get("platform", "") for e in entities}
        if platform_set & messenger_platforms:
            tags.add("messaging_apps")

        # Compras online
        ecommerce_platforms = {"amazon", "rappi", "mercadolibre", "shopify"}
        if platform_set & ecommerce_platforms:
            tags.add("online_shopper")

        # Actividad en código / tech
        tech_platforms = {"github", "gitlab", "npm", "pypi", "docker", "dev.to"}
        if platform_set & tech_platforms:
            tags.add("developer_profile")

        # Múltiples breaches = online activo por mucho tiempo
        breach_count = sum(1 for e in entities if "BREACH_HIT" in e.flags)
        if breach_count >= 3:
            tags.add("long_digital_history")

        # Número VoIP
        voip_entities = [e for e in entities if "VOIP" in e.flags]
        if voip_entities:
            tags.add("uses_voip")

        # Wallet crypto
        crypto = [e for e in entities if e.type == EntityType.CRYPTO]
        if crypto:
            tags.add("crypto_user")

        # Darkweb mention
        dw = [e for e in entities if "DARKWEB_MENTION" in e.flags]
        if dw:
            tags.add("darkweb_footprint")

        return sorted(tags)

    def _extract_phones(self, entities: list[EntityRecord]) -> list[dict]:
        phones = []
        seen = set()
        for e in entities:
            if e.type == EntityType.PHONE and e.value not in seen:
                seen.add(e.value)
                phones.append({
                    "number":  e.value,
                    "carrier": e.metadata.get("carrier", "Desconocido"),
                    "city":    e.metadata.get("city", ""),
                    "is_voip": e.metadata.get("is_voip", False),
                })
        return phones[:5]

    def _extract_emails(self, entities: list[EntityRecord]) -> list[str]:
        emails = []
        seen = set()
        for e in entities:
            if e.type == EntityType.EMAIL and e.value not in seen:
                seen.add(e.value)
                emails.append(e.value)
        return emails[:5]

    def _extract_domains(self, entities: list[EntityRecord]) -> list[str]:
        domains = []
        seen = set()
        for e in entities:
            if e.type == EntityType.DOMAIN and e.value not in seen:
                seen.add(e.value)
                domains.append(e.value)
        return domains[:8]

    def _build_narrative(self, profile: dict, state: ScanState) -> str:
        lines = []
        identity = profile.get("identity", {})
        names = identity.get("names", [])
        aliases = identity.get("aliases", [])

        # Línea 1: identidad principal
        if names:
            lines.append(f"• {names[0]} — ubicación: {profile.get('location', 'Desconocida')}")
        else:
            lines.append(f"• Objetivo: {state.target.normalized} — ubicación: {profile.get('location', 'Desconocida')}")

        # Línea 2: antigüedad digital
        age = profile.get("digital_age", {})
        first = age.get("first_seen", "Desconocido")
        years = age.get("activity_years", 0)
        if years > 0:
            lines.append(f"• Primera huella digital: {first} ({years} años de actividad)")
        else:
            lines.append(f"• Primera huella digital: {first}")

        # Línea 3: identidad — emails, teléfonos, plataformas
        emails = profile.get("emails", [])
        phones = profile.get("phones", [])
        platforms = profile.get("platforms", [])
        id_parts = []
        if emails:
            id_parts.append(f"{len(emails)} email(s)")
        if phones:
            for ph in phones[:2]:
                ph_desc = ph["number"]
                if ph.get("carrier"):
                    ph_desc += f" {ph['carrier']}"
                id_parts.append(ph_desc)
        if platforms:
            id_parts.append(", ".join(platforms[:5]))
        if id_parts:
            lines.append(f"• Identidad: {'; '.join(id_parts)}")

        # Línea 4: e-commerce
        ecommerce = profile.get("ecommerce", [])
        if ecommerce:
            ec_str = ", ".join(e["platform"] for e in ecommerce[:4])
            lines.append(f"• E-commerce: {ec_str}")

        # Línea 5: breaches
        breaches = profile.get("breaches", [])
        if breaches:
            breach_str = ", ".join(
                f"{b['name']}{' (credenciales)' if b.get('has_credentials') else ''}"
                for b in breaches[:3]
            )
            lines.append(f"• Breaches: {breach_str}")

        # Línea 6: behavioral tags
        tags = profile.get("behavioral_tags", [])
        if tags:
            lines.append(f"• Patrones: {', '.join(tags)}")

        # Línea 7: riesgo
        lines.append(f"• Riesgo: {profile['risk_score']}/100 [{profile['risk_level']}]")

        return "\n".join(lines)
