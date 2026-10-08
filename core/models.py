"""
Leviathan OSINT Framework v4.0 — Core Data Models
Creado por Luis Sánchez
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Optional
import time
import uuid


# ─── Enumeraciones ────────────────────────────────────────────────────────────

class TargetType(str, Enum):
    EMAIL    = "email"
    PHONE    = "phone"
    DOMAIN   = "domain"
    IP       = "ip"
    USERNAME = "username"
    PERSON   = "person"
    CRYPTO   = "crypto"
    PLATE    = "plate"
    URL      = "url"
    ONION    = "onion"
    ORG      = "org"
    UNKNOWN  = "unknown"


class EntityType(str, Enum):
    EMAIL      = "email"
    PHONE      = "phone"
    DOMAIN     = "domain"
    IP         = "ip"
    USERNAME   = "username"
    PERSON     = "person"
    ORG        = "org"
    CRYPTO     = "crypto"
    LOCATION   = "location"
    URL        = "url"
    HASH       = "hash"
    CREDENTIAL = "credential"
    BREACH     = "breach"
    ASN        = "asn"
    CVE        = "cve"
    PLATE      = "plate"
    ONION      = "onion"
    SNIPPET    = "snippet"
    OTHER      = "other"


class Verdict(str, Enum):
    TRUSTED   = "TRUSTED"    # ≥ 0.80
    LIKELY    = "LIKELY"     # 0.60–0.79
    UNCERTAIN = "UNCERTAIN"  # 0.40–0.59
    SUSPECT   = "SUSPECT"    # 0.25–0.39
    DISCARD   = "DISCARD"    # < 0.25


class ModuleStatus(str, Enum):
    PENDING    = "pending"
    RUNNING    = "running"
    DONE       = "done"
    FAILED     = "failed"
    RATELIMIT  = "ratelimited"
    DEPRECATED = "deprecated"
    SKIPPED    = "skipped"


class EventType(str, Enum):
    TARGET_STARTED      = "TARGET_STARTED"
    NEW_ENTITY          = "NEW_ENTITY"
    ENTITY_CONFIRMED    = "ENTITY_CONFIRMED"
    ENTITY_REJECTED     = "ENTITY_REJECTED"
    CORRELATION_FOUND   = "CORRELATION_FOUND"
    RISK_UPDATED        = "RISK_UPDATED"
    MODULE_STARTED      = "MODULE_STARTED"
    MODULE_DONE         = "MODULE_DONE"
    MODULE_RATELIMIT    = "MODULE_RATELIMIT"
    MODULE_FAILED       = "MODULE_FAILED"
    GRAPH_UPDATED       = "GRAPH_UPDATED"
    PROFILE_UPDATED     = "PROFILE_UPDATED"
    HEALTH_STATUS       = "HEALTH_STATUS"
    SCAN_COMPLETE       = "SCAN_COMPLETE"
    THREAT_ALERT        = "THREAT_ALERT"


class RiskLevel(str, Enum):
    CRITICAL = "CRÍTICO"
    HIGH     = "ALTO"
    MEDIUM   = "MEDIO"
    LOW      = "BAJO"
    NONE     = "NINGUNO"


# ─── Estructuras de datos ──────────────────────────────────────────────────────

@dataclass
class Target:
    raw:        str
    normalized: str
    type:       TargetType
    scan_id:    str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    started_at: float = field(default_factory=time.time)
    metadata:   dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"[{self.type.value.upper()}] {self.normalized}"


@dataclass
class ValidatorVote:
    name:       str
    score:      float          # -1.0 a +1.0
    weight:     float          # multiplicador de fuente
    flag:       Optional[str]  # "BREACH_HIT", "DISPOSABLE", etc.
    reason:     str
    freshness:  float = 1.0    # multiplicador de frescura


@dataclass
class EntityRecord:
    id:           str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    type:         EntityType = EntityType.OTHER
    value:        str = ""
    confidence:   float = 0.0
    verdict:      Verdict = Verdict.UNCERTAIN
    sources:      list[str] = field(default_factory=list)
    votes:        list[ValidatorVote] = field(default_factory=list)
    flags:        list[str] = field(default_factory=list)
    metadata:     dict[str, Any] = field(default_factory=dict)
    upstream_ids: list[str] = field(default_factory=list)
    module_id:    str = ""
    emitted_at:   float = field(default_factory=time.time)
    scan_id:      str = ""

    def explain(self) -> str:
        lines = [
            f"ENTIDAD: [{self.type.value}] {self.value}",
            f"VEREDICTO: {self.verdict.value} (confianza={self.confidence:.0%})",
            f"FUENTES: {', '.join(self.sources) or 'N/A'}",
            "─" * 42,
            "VOTOS DE VALIDADORES:",
        ]
        for v in self.votes:
            sign = "+" if v.score >= 0 else ""
            fresh = f" [freshness×{v.freshness:.1f}]" if v.freshness != 1.0 else ""
            flag  = f" [{v.flag}]" if v.flag else ""
            lines.append(f"  {v.name:<22} {sign}{v.score:.2f} (w={v.weight:.1f}){fresh}{flag}")
            lines.append(f"    → {v.reason}")
        if self.flags:
            lines.append(f"FLAGS: {', '.join(self.flags)}")
        return "\n".join(lines)


@dataclass
class BusEvent:
    type:      EventType
    payload:   dict[str, Any]
    scan_id:   str = ""
    ts:        float = field(default_factory=time.time)
    source_id: str = ""


@dataclass
class Correlation:
    id:          str = field(default_factory=lambda: str(uuid.uuid4())[:10])
    entity_a:    str = ""
    entity_b:    str = ""
    rel_type:    str = ""      # same_owner, alias_of, linked, leaked_in, resolves_to
    confidence:  float = 0.0
    evidence:    list[str] = field(default_factory=list)
    scan_id:     str = ""


@dataclass
class ModuleResult:
    module_id:    str
    module_name:  str
    status:       ModuleStatus
    entities_out: int = 0
    duration_ms:  float = 0.0
    error:        Optional[str] = None
    scan_id:      str = ""


@dataclass
class ScanState:
    scan_id:        str
    target:         Target
    entities:       list[EntityRecord] = field(default_factory=list)
    correlations:   list[Correlation]  = field(default_factory=list)
    module_results: list[ModuleResult] = field(default_factory=list)
    risk_score:     int = 0
    risk_level:     RiskLevel = RiskLevel.NONE
    started_at:     float = field(default_factory=time.time)
    finished_at:    Optional[float] = None

    def trusted_entities(self) -> list[EntityRecord]:
        return [e for e in self.entities if e.verdict in (Verdict.TRUSTED, Verdict.LIKELY)]

    def elapsed(self) -> float:
        end = self.finished_at or time.time()
        return end - self.started_at
