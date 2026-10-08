"""
Leviathan OSINT v4.0 — Microkernel 2: Correlator
Correlaciones automáticas + NetworkX + Source Genealogy
"""
from __future__ import annotations
import asyncio
import logging
from typing import Any
from core.models import EntityRecord, EntityType, Verdict, Correlation, BusEvent, EventType
from core.event_bus import EventBus

log = logging.getLogger("leviathan.k2")

try:
    import networkx as nx  # type: ignore
    HAS_NX = True
except ImportError:
    HAS_NX = False
    log.warning("networkx no instalado — grafo en memoria básico")


# ─── Reglas de correlación ────────────────────────────────────────────────────

class CorrelationRule:
    """Clase base para reglas de correlación."""
    rel_type:    str = "linked"
    min_conf:    float = 0.6
    description: str  = ""

    def match(self, a: EntityRecord, b: EntityRecord) -> float:
        """Devuelve score de correlación (0.0 = no match)."""
        return 0.0


class EmailDomainRule(CorrelationRule):
    rel_type = "same_owner"
    description = "Email y dominio comparten host"

    def match(self, a, b) -> float:
        if a.type == EntityType.EMAIL and b.type == EntityType.DOMAIN:
            domain_in_email = a.value.split("@")[-1].lower()
            if domain_in_email == b.value.lower():
                return 0.90
        return 0.0


class UsernameMultiPlatformRule(CorrelationRule):
    rel_type = "alias_of"
    description = "Mismo username en múltiples plataformas"

    def match(self, a, b) -> float:
        if a.type == EntityType.USERNAME and b.type == EntityType.USERNAME:
            if a.value.lower() == b.value.lower() and a.module_id != b.module_id:
                return 0.85
        return 0.0


class IPDomainRule(CorrelationRule):
    rel_type = "resolves_to"
    description = "IP asociada a dominio"

    def match(self, a, b) -> float:
        if a.type == EntityType.IP and b.type == EntityType.DOMAIN:
            ips_of_domain = b.metadata.get("ips", [])
            if a.value in ips_of_domain:
                return 0.88
        return 0.0


class BreachEmailRule(CorrelationRule):
    rel_type = "leaked_in"
    description = "Email encontrado en breach"

    def match(self, a, b) -> float:
        if a.type == EntityType.EMAIL and b.type == EntityType.BREACH:
            emails_in_breach = b.metadata.get("emails", [])
            if a.value.lower() in [e.lower() for e in emails_in_breach]:
                return 0.95
        if "BREACH_HIT" in a.flags and a.type == EntityType.EMAIL:
            breach_name = a.metadata.get("breach_name", "")
            if b.type == EntityType.BREACH and breach_name == b.value:
                return 0.90
        return 0.0


class EmailPhoneOwnerRule(CorrelationRule):
    rel_type = "same_owner"
    description = "Email y teléfono apuntan al mismo perfil"

    def match(self, a, b) -> float:
        if a.type == EntityType.EMAIL and b.type == EntityType.PHONE:
            phones_of_email = a.metadata.get("linked_phones", [])
            if b.value in phones_of_email or a.value in b.metadata.get("linked_emails", []):
                return 0.85
        return 0.0


class ASNDomainRule(CorrelationRule):
    rel_type = "linked"
    description = "Dominio en el mismo ASN"

    def match(self, a, b) -> float:
        if a.type == EntityType.ASN and b.type in (EntityType.DOMAIN, EntityType.IP):
            if a.value in b.metadata.get("asn", ""):
                return 0.75
        return 0.0


class DarkwebMentionRule(CorrelationRule):
    rel_type = "leaked_in"
    description = "Entidad mencionada en contenido darkweb"

    def match(self, a, b) -> float:
        if "DARKWEB_MENTION" in a.flags and b.type == EntityType.SNIPPET:
            if a.value.lower() in b.value.lower():
                return 0.80
        return 0.0


class UsernameEmailRule(CorrelationRule):
    rel_type = "alias_of"
    description = "Username coincide con parte del email"

    def match(self, a, b) -> float:
        if a.type == EntityType.USERNAME and b.type == EntityType.EMAIL:
            local = b.value.split("@")[0].lower()
            if a.value.lower() == local or a.value.lower() in local:
                return 0.75
        return 0.0


CORRELATION_RULES = [
    EmailDomainRule(),
    UsernameMultiPlatformRule(),
    IPDomainRule(),
    BreachEmailRule(),
    EmailPhoneOwnerRule(),
    ASNDomainRule(),
    DarkwebMentionRule(),
    UsernameEmailRule(),
]


class K2Correlator:
    """
    Microkernel 2 — Correlaciones automáticas entre entidades.
    Construye grafo NetworkX en memoria.
    Emite CORRELATION_FOUND al bus para cada match.
    """

    def __init__(self, bus: EventBus, min_confidence: float = 0.4):
        self.bus            = bus
        self.min_confidence = min_confidence
        self.graph          = nx.DiGraph() if HAS_NX else None
        self._correlations: list[Correlation] = []

    async def correlate_all(
        self,
        entities: list[EntityRecord],
        scan_id:  str,
    ) -> list[Correlation]:
        """
        Correlaciona todas las entidades entre sí aplicando las reglas.
        O(n²) — aceptable para n < 1000.
        """
        new_correlations: list[Correlation] = []
        trusted = [e for e in entities if e.verdict.value not in ("DISCARD",)]

        for i, a in enumerate(trusted):
            for b in trusted[i+1:]:
                if a.id == b.id:
                    continue
                for rule in CORRELATION_RULES:
                    score = rule.match(a, b)
                    if score < self.min_confidence:
                        # Probar inversa
                        score = rule.match(b, a)
                        if score < self.min_confidence:
                            continue
                        a, b = b, a  # invertir para emisión correcta

                    corr = Correlation(
                        entity_a=a.id,
                        entity_b=b.id,
                        rel_type=rule.rel_type,
                        confidence=score,
                        evidence=[rule.description, f"A={a.value}", f"B={b.value}"],
                        scan_id=scan_id,
                    )
                    new_correlations.append(corr)
                    self._correlations.append(corr)

                    if HAS_NX and self.graph is not None:
                        self.graph.add_node(a.id, label=a.value, type=a.type.value,
                                           verdict=a.verdict.value, conf=a.confidence)
                        self.graph.add_node(b.id, label=b.value, type=b.type.value,
                                           verdict=b.verdict.value, conf=b.confidence)
                        self.graph.add_edge(a.id, b.id, rel=rule.rel_type, weight=score)

                    await self.bus.emit(EventType.CORRELATION_FOUND, {
                        "correlation_id": corr.id,
                        "entity_a":       a.value,
                        "entity_b":       b.value,
                        "entity_a_type":  a.type.value,
                        "entity_b_type":  b.type.value,
                        "rel_type":       rule.rel_type,
                        "confidence":     score,
                        "evidence":       corr.evidence,
                    }, scan_id=scan_id)

        await self.bus.emit(EventType.GRAPH_UPDATED, {
            "nodes": len(self.graph.nodes) if self.graph else len(trusted),
            "edges": len(self.graph.edges) if self.graph else len(new_correlations),
            "correlations": len(new_correlations),
        }, scan_id=scan_id)

        return new_correlations

    def get_neighbors(self, entity_id: str) -> list[str]:
        if self.graph is None:
            return []
        return list(self.graph.neighbors(entity_id))

    def get_all_correlations(self) -> list[Correlation]:
        return self._correlations

    def to_dict(self) -> dict:
        if self.graph is None:
            return {"nodes": [], "edges": []}
        return {
            "nodes": [
                {"id": n, **self.graph.nodes[n]}
                for n in self.graph.nodes
            ],
            "edges": [
                {"source": u, "target": v, **self.graph.edges[u, v]}
                for u, v in self.graph.edges
            ],
        }
