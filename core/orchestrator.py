"""
Leviathan OSINT v4.0 — Orchestrator
El cerebro coordinador. Conecta los 3 microkernels con el Event Bus.
"""
from __future__ import annotations
import asyncio
import logging
import time
from pathlib import Path

from core.event_bus import EventBus
from core.consensus_engine import ConsensusEngine
from core.microkernel1_crawler import K1Crawler
from core.microkernel2_correlator import K2Correlator
from core.microkernel3_storage import K3Storage
from core.profile_composite import ProfileCompositeBuilder
from core.models import (
    Target, TargetType, ScanState, EventType, RiskLevel, ModuleResult, ModuleStatus
)

log = logging.getLogger("leviathan.orchestrator")


def _build_module_registry(api_keys: dict, use_tor: bool, proxy: str | None):
    """Construye el registro de módulos activos."""
    from modules.recon.modules_01_08 import (
        TargetSanitizer, PassiveDNS, WhoisRDAP, IP2ASN,
        SubdomainEnum, PortsServices, TechFingerprint, EmailPhoneHarvester,
    )
    from modules.people.modules_09_18 import (
        UsernameEnum, SocialScrape, PhotoReverse, FamilyMapper,
        EmploymentHistory, EducationCerts, VehiclePlate, CriminalRecords,
        LeaksPaste, DarkwebLeakCorrelator,
    )
    from modules.darkweb.modules_19_32 import (
        DarkwebIntel, RansomwareIntel, DarkwebForumMonitor, BreachAggregator,
        PhoneDeepOSINT, TelegramIntel, CryptoWallet,
        SIMSwapRisk, VoIPDetection, MessengerFootprint,
    )
    from modules.advanced.modules_33_40 import (
        RiskScoreEngine, TimelineGenerator, AnomalyDetector,
        CrossRefValidator, ExportReport,
    )

    kwargs = {"api_keys": api_keys, "use_tor": use_tor, "proxy": proxy}
    return [
        TargetSanitizer(**kwargs),
        PassiveDNS(**kwargs),
        WhoisRDAP(**kwargs),
        IP2ASN(**kwargs),
        SubdomainEnum(**kwargs),
        PortsServices(**kwargs),
        TechFingerprint(**kwargs),
        EmailPhoneHarvester(**kwargs),
        UsernameEnum(**kwargs),
        SocialScrape(**kwargs),
        PhotoReverse(**kwargs),
        FamilyMapper(**kwargs),
        EmploymentHistory(**kwargs),
        EducationCerts(**kwargs),
        VehiclePlate(**kwargs),
        CriminalRecords(**kwargs),
        LeaksPaste(**kwargs),
        DarkwebLeakCorrelator(**kwargs),
        DarkwebIntel(**kwargs),
        RansomwareIntel(**kwargs),
        DarkwebForumMonitor(**kwargs),
        BreachAggregator(**kwargs),
        PhoneDeepOSINT(**kwargs),
        TelegramIntel(**kwargs),
        CryptoWallet(**kwargs),
        SIMSwapRisk(**kwargs),
        VoIPDetection(**kwargs),
        MessengerFootprint(**kwargs),
    ], {
        "risk":       RiskScoreEngine(**kwargs),
        "timeline":   TimelineGenerator(**kwargs),
        "anomaly":    AnomalyDetector(**kwargs),
        "crossref":   CrossRefValidator(**kwargs),
        "export":     ExportReport(**kwargs),
    }


class Orchestrator:
    """
    Cerebro del sistema. Coordina:
      K1 Crawler → Consensus → K2 Correlator → K3 Storage
      → ProfileComposite → Report
    Todo via Event Bus. Nadie habla directamente con nadie.
    """

    def __init__(
        self,
        api_keys:    dict | None = None,
        use_tor:     bool = False,
        proxy:       str | None = None,
        human_mode:  bool = True,
        max_concurrent: int = 10,
        db_path:     str = "database/leviathan.db",
        reports_dir: str = "reports",
        dashboard=None,
    ):
        self.api_keys    = api_keys or {}
        self.use_tor     = use_tor
        self.proxy       = proxy
        self.reports_dir = reports_dir
        self.dashboard   = dashboard

        self.bus         = EventBus()
        self.consensus   = ConsensusEngine()
        self.k2          = K2Correlator(self.bus)
        self.k3          = K3Storage(db_path)
        self.k3.init()

        self.k1 = K1Crawler(
            bus=self.bus,
            consensus=self.consensus,
            max_concurrent=max_concurrent,
            use_tor=use_tor,
            proxy=proxy,
            human_mode=human_mode,
        )

        # Cargar módulos deprecated del storage
        deprecated = self.k3.get_deprecated_modules()
        for mod_id in deprecated:
            self.k1.mark_deprecated(mod_id)
            log.info(f"Module {mod_id} deprecated — skipping")

        # Conectar dashboard al bus si existe
        if dashboard:
            self.bus.subscribe_all(dashboard.on_event)

    async def scan(self, raw_target: str) -> ScanState:
        """
        Ejecutar un scan completo sobre un target.
        Devuelve ScanState con todos los resultados.
        """
        from modules.recon.modules_01_08 import TargetSanitizer
        from core.models import Target, TargetType

        # 1. Construir target inicial
        target = Target(raw=raw_target, normalized=raw_target, type=TargetType.UNKNOWN)

        # 2. Inicializar módulos
        modules, advanced = _build_module_registry(self.api_keys, self.use_tor, self.proxy)

        # Sanitizar primero (síncrono)
        sanitizer = modules[0]
        await sanitizer.run(target)

        # Guardar target en storage
        self.k3.save_target(target)

        state = ScanState(
            scan_id=target.scan_id,
            target=target,
        )

        await self.bus.emit(EventType.TARGET_STARTED, {
            "target":    target.normalized,
            "type":      target.type.value,
            "scan_id":   target.scan_id,
        }, scan_id=target.scan_id)

        log.info(f"Scan started: {target} [{target.scan_id}]")

        # 3. K1: Encolar y ejecutar módulos (saltar sanitizer ya corrido)
        for module in modules[1:]:
            self.k1.enqueue(module, target, priority=module.MODULE_PRIORITY)

        entities = await self.k1.run_all(target, target.scan_id)

        # Buffer entities en K3
        for e in entities:
            e.scan_id = target.scan_id
            self.k3.buffer_entity(e)

        state.entities = entities

        # 4. K2: Correlaciones
        log.info(f"Running correlations on {len(entities)} entities...")
        correlations = await self.k2.correlate_all(entities, target.scan_id)
        state.correlations = correlations
        for c in correlations:
            self.k3.buffer_correlation(c)

        # 5. Risk Score
        risk_engine   = advanced["risk"]
        risk, level, factors = risk_engine.compute_risk(entities)
        state.risk_score = risk
        state.risk_level = RiskLevel(level)
        self.k3.finish_target(target.scan_id, risk, level)

        await self.bus.emit(EventType.RISK_UPDATED, {
            "risk_score": risk,
            "risk_level": level,
            "factors":    factors,
        }, scan_id=target.scan_id)

        # 6. ProfileComposite
        profile_builder = ProfileCompositeBuilder()
        profile = profile_builder.build(state)
        if profile:
            await self.bus.emit(EventType.PROFILE_UPDATED, {
                "profile": profile,
            }, scan_id=target.scan_id)

        # 7. Timeline + Anomalías
        timeline_engine  = advanced["timeline"]
        anomaly_engine   = advanced["anomaly"]
        crossref_engine  = advanced["crossref"]
        timeline  = timeline_engine.build_timeline(entities)
        anomalies = anomaly_engine.detect(entities)
        crossref  = crossref_engine.validate(entities)

        # 8. Executive Summary (sin LLM — determinístico)
        summary = self._build_summary(state, profile, anomalies)

        # 9. Generar reporte HTML
        export = advanced["export"]
        html   = export.generate_html(state, summary, timeline, anomalies)
        report_path = export.save(html, target.scan_id, self.reports_dir)

        # 10. Finalizar
        state.finished_at = time.time()
        self.k3.flush_all()

        await self.bus.emit(EventType.SCAN_COMPLETE, {
            "scan_id":     target.scan_id,
            "entities":    len(entities),
            "trusted":     len(state.trusted_entities()),
            "correlations": len(correlations),
            "risk_score":  risk,
            "risk_level":  level,
            "elapsed":     state.elapsed(),
            "report":      str(report_path),
            "profile":     profile,
            "summary":     summary,
            "anomalies":   anomalies,
            "timeline":    timeline[:20],
            "crossref":    crossref,
        }, scan_id=target.scan_id)

        log.info(
            f"Scan complete: {target.normalized} | "
            f"entities={len(entities)} trusted={len(state.trusted_entities())} "
            f"risk={risk}/{level} elapsed={state.elapsed():.1f}s"
        )
        return state

    def _build_summary(self, state: ScanState, profile: dict, anomalies: list[dict]) -> str:
        """Executive Summary determinístico (sin LLM)."""
        trusted = state.trusted_entities()
        lines   = []

        # 1. Identidad / huella
        identity = profile.get("identity", {})
        names    = identity.get("names", [])
        location = profile.get("location", "Desconocida")
        platforms = profile.get("platforms", [])
        emails   = profile.get("emails", [])
        phones   = profile.get("phones", [])

        id_desc = names[0] if names else state.target.normalized
        plat_str = ", ".join(platforms[:4]) if platforms else "no confirmado"
        lines.append(f"**1. IDENTIDAD / HUELLA CONFIRMADA**")
        lines.append(f"   {id_desc}, ubicación inferida: {location}.")
        if emails or phones:
            contact = []
            if emails: contact.append(f"{len(emails)} email(s)")
            if phones: contact.append(f"{len(phones)} teléfono(s)")
            lines.append(f"   Contacto: {', '.join(contact)}. Plataformas: {plat_str}.")

        # 2. Antigüedad digital
        age = profile.get("digital_age", {})
        lines.append(f"\n**2. HUELLA DIGITAL Y ANTIGÜEDAD**")
        if age.get("first_seen") and age["first_seen"] != "Desconocido":
            lines.append(f"   Primera actividad: {age['first_seen']} ({age.get('activity_years', 0)} años de historial).")
        breaches = profile.get("breaches", [])
        if breaches:
            lines.append(f"   {len(breaches)} breach(es) histórico(s) detectado(s).")
        ecommerce = profile.get("ecommerce", [])
        if ecommerce:
            ec_str = ", ".join(e["platform"] for e in ecommerce[:3])
            lines.append(f"   Huella e-commerce: {ec_str}.")

        # 3. Factores de riesgo
        lines.append(f"\n**3. FACTORES DE RIESGO CRÍTICO**")
        critical_anomalies = [a for a in anomalies if a.get("severity") in ("CRITICAL", "HIGH")]
        if critical_anomalies:
            for a in critical_anomalies[:3]:
                lines.append(f"   [{a['severity']}] {a['description']}.")
        breach_entities = [e for e in trusted if "BREACH_HIT" in e.flags]
        if breach_entities:
            lines.append(f"   {len(breach_entities)} entidad(es) encontrada(s) en breaches de datos.")
        dw_entities = [e for e in trusted if "DARKWEB_MENTION" in e.flags]
        if dw_entities:
            lines.append(f"   Mención en contenido darkweb indexado ({len(dw_entities)} referencia(s)).")
        lines.append(f"   Score de riesgo: {state.risk_score}/100 [{state.risk_level.value}].")

        # 4. Correlaciones clave
        lines.append(f"\n**4. CORRELACIONES CLAVE**")
        if state.correlations:
            for c in state.correlations[:3]:
                lines.append(f"   {c.entity_a[:40]} [{c.rel_type}] {c.entity_b[:40]} ({c.confidence:.0%})")
        else:
            lines.append("   No se encontraron correlaciones significativas.")

        # 5. Anomalías
        lines.append(f"\n**5. ANOMALÍAS DETECTADAS**")
        all_anomalies = [a for a in anomalies if a.get("severity") not in ("INFO",)]
        if all_anomalies:
            for a in all_anomalies[:3]:
                lines.append(f"   {a['type']}: {a['description']}")
        else:
            lines.append("   No se detectaron anomalías significativas.")

        return "\n".join(lines)
