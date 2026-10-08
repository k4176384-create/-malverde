"""
Leviathan OSINT v4.0 — Consensus Engine
Un solo lugar donde se decide qué es verdad. Consistente. Explicable.
"""
from __future__ import annotations
import asyncio
import re
import logging
import time
from typing import Any
from core.models import (
    EntityRecord, EntityType, ValidatorVote, Verdict
)
from core.source_genealogy import SourceGenealogyTracker

log = logging.getLogger("leviathan.consensus")

# Pesos de fuentes conocidas
SOURCE_REPUTATION: dict[str, float] = {
    "haveibeenpwned": 1.8, "hibp": 1.8,
    "shodan": 1.6,
    "iana_rdap": 1.5, "bgpview": 1.5, "ripe": 1.5, "arin": 1.5,
    "hunter": 1.4, "github_api": 1.4,
    "emailrep": 1.3,
    "virustotal": 1.3, "greynoise": 1.3,
    "crt.sh": 1.2,
    "hackertarget": 1.1,
    "web_scrape": 0.9, "http_direct": 0.9,
    "photo_reverse": 0.5,
}

# Flags que siempre son notables (elevan a mínimo 0.65)
CRITICAL_FLAGS = {"BREACH_HIT", "RANSOMWARE_VICTIM", "DARKWEB_MENTION",
                  "CRIMINAL_RECORD", "HIGH_RISK_IP", "SIMSWAP_RISK"}

# Listas disposables (dominio → descartado)
DISPOSABLE_DOMAINS = {
    "mailinator.com","guerrillamail.com","tempmail.com","throwam.com",
    "sharklasers.com","guerrillamailblock.com","yopmail.com","10minutemail.com",
    "trashmail.com","dispostable.com","maildrop.cc","mailnull.com","spamgourmet.com",
}

# Regex fundamentales
RE_EMAIL   = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')
RE_PHONE   = re.compile(r'^\+?[\d\s\-\(\)]{7,20}$')
RE_DOMAIN  = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
RE_IP      = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
RE_IPV6    = re.compile(r'^[0-9a-fA-F:]{2,39}$')
RE_USER    = re.compile(r'^[a-zA-Z0-9_\.\-]{2,32}$')
RE_ONION   = re.compile(r'^[a-z2-7]{16,56}\.onion$')
RE_BTC     = re.compile(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[a-z0-9]{39,59}$')
RE_ETH     = re.compile(r'^0x[0-9a-fA-F]{40}$')


def _freshness_multiplier(months_old: int) -> float:
    if months_old < 6:    return 1.5
    if months_old < 18:   return 1.2
    if months_old < 36:   return 1.0
    if months_old < 60:   return 0.9
    return 0.8


def _source_weight(source: str) -> float:
    key = source.lower().replace(" ", "_")
    for k, v in SOURCE_REPUTATION.items():
        if k in key:
            return v
    return 1.0


# ─── Validators ────────────────────────────────────────────────────────────────

def validate_email(value: str, metadata: dict) -> list[ValidatorVote]:
    votes: list[ValidatorVote] = []

    # Regex
    if RE_EMAIL.match(value):
        domain = value.split("@")[-1].lower()
        votes.append(ValidatorVote(
            name="email_regex", score=0.30, weight=1.0, flag=None,
            reason=f"Formato válido. local={value.split('@')[0]} tld={domain.split('.')[-1]}"
        ))
        # Disposable
        if domain in DISPOSABLE_DOMAINS:
            votes.append(ValidatorVote(
                name="email_disposable", score=-0.20, weight=1.8, flag="DISPOSABLE",
                reason=f"Dominio {domain} es temporal/desechable"
            ))
        else:
            votes.append(ValidatorVote(
                name="email_disposable", score=0.10, weight=1.8, flag=None,
                reason=f"Dominio {domain} no está en lista negra"
            ))
    else:
        votes.append(ValidatorVote(
            name="email_regex", score=-0.50, weight=1.0, flag="INVALID_FORMAT",
            reason="Formato de email inválido"
        ))

    # MX record (si viene en metadata)
    mx_ok = metadata.get("mx_record")
    if mx_ok is True:
        votes.append(ValidatorVote(
            name="email_mx_record", score=0.30, weight=1.2, flag=None,
            reason="DNS MX existe y responde"
        ))
    elif mx_ok is False:
        votes.append(ValidatorVote(
            name="email_mx_record", score=-0.25, weight=1.2, flag="NO_MX",
            reason="Dominio sin registro MX — email inentregable"
        ))

    # Breach
    breach_count = metadata.get("breach_count", 0)
    breach_date  = metadata.get("breach_date_months", 999)
    if breach_count > 0:
        fresh = _freshness_multiplier(breach_date)
        votes.append(ValidatorVote(
            name="email_breach", score=0.40, weight=1.5, flag="BREACH_HIT",
            reason=f"Encontrado en {breach_count} breach(es).",
            freshness=fresh
        ))

    return votes


def validate_phone(value: str, metadata: dict) -> list[ValidatorVote]:
    votes: list[ValidatorVote] = []
    clean = re.sub(r'[\s\-\(\)]', '', value)

    if RE_PHONE.match(value) and 7 <= len(clean.lstrip('+')) <= 15:
        votes.append(ValidatorVote(
            name="phone_regex", score=0.35, weight=1.0, flag=None,
            reason=f"Formato válido. Dígitos={len(clean.lstrip('+'))}"
        ))
    else:
        votes.append(ValidatorVote(
            name="phone_regex", score=-0.40, weight=1.0, flag="INVALID_FORMAT",
            reason="Número de teléfono con formato inválido"
        ))

    carrier = metadata.get("carrier")
    if carrier:
        votes.append(ValidatorVote(
            name="phone_carrier", score=0.25, weight=1.3, flag=None,
            reason=f"Operador confirmado: {carrier}"
        ))
    voip = metadata.get("is_voip")
    if voip:
        votes.append(ValidatorVote(
            name="phone_voip", score=-0.10, weight=1.1, flag="VOIP",
            reason="Número VoIP / virtual detectado"
        ))
    sim_risk = metadata.get("simswap_risk")
    if sim_risk:
        votes.append(ValidatorVote(
            name="simswap_risk", score=0.0, weight=1.0, flag="SIMSWAP_RISK",
            reason="Patrón de riesgo SIM swap detectado"
        ))
    return votes


def validate_ip(value: str, metadata: dict) -> list[ValidatorVote]:
    votes: list[ValidatorVote] = []
    if RE_IP.match(value):
        parts = [int(p) for p in value.split(".")]
        all_ok = all(0 <= p <= 255 for p in parts)
        is_private = (parts[0] == 10 or
                      (parts[0] == 172 and 16 <= parts[1] <= 31) or
                      (parts[0] == 192 and parts[1] == 168))
        if all_ok:
            votes.append(ValidatorVote(
                name="ip_format", score=0.30, weight=1.0,
                flag="PRIVATE_IP" if is_private else None,
                reason=f"IPv4 válida. {'Privada/RFC1918' if is_private else 'Pública'}"
            ))
    elif RE_IPV6.match(value):
        votes.append(ValidatorVote(
            name="ip_format", score=0.30, weight=1.0, flag=None,
            reason="IPv6 válida"
        ))
    else:
        votes.append(ValidatorVote(
            name="ip_format", score=-0.50, weight=1.0, flag="INVALID_FORMAT",
            reason="Formato de IP inválido"
        ))
    rep = metadata.get("reputation")  # "malicious","suspicious","clean"
    if rep == "malicious":
        votes.append(ValidatorVote(
            name="ip_reputation", score=0.40, weight=1.5, flag="HIGH_RISK_IP",
            reason="IP con reputación maliciosa (VirusTotal/GreyNoise)"
        ))
    elif rep == "suspicious":
        votes.append(ValidatorVote(
            name="ip_reputation", score=0.20, weight=1.3, flag="SUSPICIOUS_IP",
            reason="IP marcada como sospechosa"
        ))
    return votes


def validate_domain(value: str, metadata: dict) -> list[ValidatorVote]:
    votes: list[ValidatorVote] = []
    if RE_DOMAIN.match(value) or RE_ONION.match(value):
        votes.append(ValidatorVote(
            name="domain_format", score=0.30, weight=1.0, flag=None,
            reason=f"Formato válido. TLD={value.split('.')[-1]}"
        ))
    else:
        votes.append(ValidatorVote(
            name="domain_format", score=-0.40, weight=1.0, flag="INVALID_FORMAT",
            reason="Formato de dominio inválido"
        ))
    age_months = metadata.get("domain_age_months")
    if age_months is not None:
        if age_months < 1:
            votes.append(ValidatorVote(
                name="domain_age", score=-0.15, weight=1.2, flag="NEWLY_REGISTERED",
                reason="Dominio registrado hace menos de 1 mes"
            ))
        elif age_months > 24:
            votes.append(ValidatorVote(
                name="domain_age", score=0.20, weight=1.1, flag=None,
                reason=f"Dominio establecido: {age_months} meses de antigüedad"
            ))
    return votes


def validate_username(value: str, metadata: dict) -> list[ValidatorVote]:
    votes: list[ValidatorVote] = []
    if RE_USER.match(value):
        votes.append(ValidatorVote(
            name="username_pattern", score=0.25, weight=1.0, flag=None,
            reason=f"Patrón de username válido. Longitud={len(value)}"
        ))
    platforms = metadata.get("platforms_found", 0)
    if platforms >= 3:
        votes.append(ValidatorVote(
            name="username_multi_platform", score=0.35, weight=1.4, flag=None,
            reason=f"Encontrado en {platforms} plataformas — identidad consistente"
        ))
    elif platforms >= 1:
        votes.append(ValidatorVote(
            name="username_multi_platform", score=0.15, weight=1.1, flag=None,
            reason=f"Encontrado en {platforms} plataforma(s)"
        ))
    return votes


def validate_generic(value: str, entity_type: EntityType, metadata: dict) -> list[ValidatorVote]:
    votes: list[ValidatorVote] = []
    # Multi-source boost
    source_count = metadata.get("source_count", 1)
    if source_count >= 2:
        boost = min(0.20, 0.05 * source_count)
        votes.append(ValidatorVote(
            name="multi_source", score=boost, weight=0.6, flag=None,
            reason=f"{source_count} fuentes independientes confirman"
        ))
    # Breach / darkweb specific
    if metadata.get("darkweb_mention"):
        votes.append(ValidatorVote(
            name="darkweb_mention", score=0.35, weight=1.3, flag="DARKWEB_MENTION",
            reason="Mencionado en contenido darkweb indexado"
        ))
    if metadata.get("criminal_record"):
        votes.append(ValidatorVote(
            name="criminal_record", score=0.40, weight=1.5, flag="CRIMINAL_RECORD",
            reason="Encontrado en registros criminales públicos"
        ))
    return votes


# ─── Engine principal ──────────────────────────────────────────────────────────

class ConsensusEngine:
    """
    Recibe RawEntity del Event Bus, aplica validators, emite EntityRecord.
    Un solo lugar donde se decide qué es verdad.
    """

    def __init__(self):
        self._genealogy = SourceGenealogyTracker()
        self._timeout   = 4.0

    def _run_validators(self, entity_type: EntityType, value: str, metadata: dict) -> list[ValidatorVote]:
        votes: list[ValidatorVote] = []
        if entity_type == EntityType.EMAIL:
            votes.extend(validate_email(value, metadata))
        elif entity_type == EntityType.PHONE:
            votes.extend(validate_phone(value, metadata))
        elif entity_type in (EntityType.IP,):
            votes.extend(validate_ip(value, metadata))
        elif entity_type == EntityType.DOMAIN:
            votes.extend(validate_domain(value, metadata))
        elif entity_type == EntityType.USERNAME:
            votes.extend(validate_username(value, metadata))
        votes.extend(validate_generic(value, entity_type, metadata))
        return votes

    def _compute_confidence(self, votes: list[ValidatorVote], entity_key: str, sources: list[str]) -> float:
        if not votes:
            return 0.3

        total_weight = 0.0
        weighted_sum = 0.0
        positive_votes = 0
        negative_votes = 0

        for vote in votes:
            # Penalización por genealogía de upstream si hay fuente
            genealogy_mult = 1.0
            if sources:
                for src in sources:
                    genealogy_mult = self._genealogy.get_weight_multiplier(entity_key, src)

            eff_weight  = vote.weight * genealogy_mult * vote.freshness
            weighted_sum += vote.score * eff_weight
            total_weight += eff_weight

            if vote.score > 0:
                positive_votes += 1
            elif vote.score < 0:
                negative_votes += 1

        raw_score = (weighted_sum / total_weight) if total_weight > 0 else 0.0

        # Penalización por conflicto
        conflict_penalty = 0.0
        if positive_votes > 0 and negative_votes > 0:
            conflict_penalty = 0.05 * negative_votes

        # Base + raw - penalty
        confidence = 0.30 + raw_score - conflict_penalty
        confidence = max(0.0, min(1.0, confidence))
        return confidence

    def _determine_verdict(self, confidence: float, flags: list[str]) -> Verdict:
        # Flags críticos elevan a mínimo LIKELY
        if any(f in CRITICAL_FLAGS for f in flags):
            confidence = max(confidence, 0.65)

        if confidence >= 0.80:  return Verdict.TRUSTED
        if confidence >= 0.60:  return Verdict.LIKELY
        if confidence >= 0.40:  return Verdict.UNCERTAIN
        if confidence >= 0.25:  return Verdict.SUSPECT
        return Verdict.DISCARD

    def process(
        self,
        entity_type: EntityType,
        value:       str,
        sources:     list[str],
        metadata:    dict[str, Any],
        module_id:   str = "",
        scan_id:     str = "",
    ) -> EntityRecord:
        """
        Procesa una entidad emitida por un módulo.
        Devuelve EntityRecord con veredicto final.
        """
        entity_key = f"{entity_type.value}:{value}"

        votes = self._run_validators(entity_type, value, metadata)
        confidence = self._compute_confidence(votes, entity_key, sources)
        flags = [v.flag for v in votes if v.flag]
        verdict = self._determine_verdict(confidence, flags)

        record = EntityRecord(
            type=entity_type,
            value=value,
            confidence=confidence,
            verdict=verdict,
            sources=sources,
            votes=votes,
            flags=flags,
            metadata=metadata,
            module_id=module_id,
            scan_id=scan_id,
        )
        return record

    def batch_process(self, entities: list[dict]) -> list[EntityRecord]:
        """Procesa una lista de entidades en batch."""
        return [
            self.process(
                entity_type=EntityType(e.get("type", "other")),
                value=e.get("value", ""),
                sources=e.get("sources", []),
                metadata=e.get("metadata", {}),
                module_id=e.get("module_id", ""),
                scan_id=e.get("scan_id", ""),
            )
            for e in entities
        ]
