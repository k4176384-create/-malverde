"""
Leviathan OSINT v4.0 — Orchestrator (actualizado)
Integra: FastText · SelfLearning · HealthCheck · Plugin Manager · LLM
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


def _build_core_modules(api_keys: dict, use_tor: bool, proxy, deep_multimodal: bool = False):
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
    from modules.advanced.modules_33_41 import (
        LLMSemanticAnalyzer, RelationshipGraph, SelfLearning, EcommerceFootprint,
    )
    from modules.advanced.modules_33_40 import (
        RiskScoreEngine, TimelineGenerator, AnomalyDetector,
        CrossRefValidator, ExportReport,
    )

    kw = {"api_keys": api_keys, "use_tor": use_tor, "proxy": proxy}

    core = [
        TargetSanitizer(**kw), PassiveDNS(**kw), WhoisRDAP(**kw), IP2ASN(**kw),
        SubdomainEnum(**kw), PortsServices(**kw), TechFingerprint(**kw), EmailPhoneHarvester(**kw),
        UsernameEnum(**kw), SocialScrape(**kw), PhotoReverse(**kw), FamilyMapper(**kw),
        EmploymentHistory(**kw), EducationCerts(**kw), VehiclePlate(**kw), CriminalRecords(**kw),
        LeaksPaste(**kw), DarkwebLeakCorrelator(**kw),
        DarkwebIntel(**kw), RansomwareIntel(**kw), DarkwebForumMonitor(**kw), BreachAggregator(**kw),
        PhoneDeepOSINT(**kw), TelegramIntel(**kw), CryptoWallet(**kw),
        SIMSwapRisk(**kw), VoIPDetection(**kw), MessengerFootprint(**kw),
        EcommerceFootprint(**kw),
    ]

    # Módulo 49 MultiModal — solo si está activado explícitamente
    if deep_multimodal:
        from modules.advanced.module_49_multimodal import MultiModalAnalyzer, DISCLAIMER
        print(DISCLAIMER)
        core.append(MultiModalAnalyzer(**kw, deep_enabled=True))

    advanced = {
        "risk":      RiskScoreEngine(**kw),
        "timeline":  TimelineGenerator(**kw),
        "anomaly":   AnomalyDetector(**kw),
        "crossref":  CrossRefValidator(**kw),
        "export":    ExportReport(**kw),
        "selflearn": SelfLearning(**kw),
        "graph":     RelationshipGraph(**kw),
        "llm":       LLMSemanticAnalyzer(**kw),
    }
    return core, advanced


class Orchestrator:
    def __init__(
        self,
        api_keys:       dict | None = None,
        use_tor:        bool = False,
        proxy:          str | None = None,
        human_mode:     bool = True,
        max_concurrent: int = 10,
        db_path:        str = "database/leviathan.db",
        reports_dir:    str = "reports",
        dashboard=None,
        use_llm:        bool = False,
        llm_host:       str = "http://localhost:11434",
        llm_model:      str = "phi3:mini",
        deep_multimodal: bool = False,
        plugins_dir:    str | None = None,
        enable_health:  bool = True,
    ):
        self.api_keys        = api_keys or {}
        self.use_tor         = use_tor
        self.proxy           = proxy
        self.reports_dir     = reports_dir
        self.dashboard       = dashboard
        self.use_llm         = use_llm
        self.llm_host        = llm_host
        self.llm_model       = llm_model
        self.deep_multimodal = deep_multimodal

        self.bus       = EventBus()
        self.consensus = ConsensusEngine()
        self.k2        = K2Correlator(self.bus)
        self.k3        = K3Storage(db_path)
        self.k3.init()

        self.k1 = K1Crawler(
            bus=self.bus, consensus=self.consensus,
            max_concurrent=max_concurrent,
            use_tor=use_tor, proxy=proxy, human_mode=human_mode,
        )

        # Cargar módulos deprecated
        for mod_id in self.k3.get_deprecated_modules():
            self.k1.mark_deprecated(mod_id)

        # Dashboard → suscribir al bus
        if dashboard:
            handler = getattr(dashboard, 'on_bus_event', None) or getattr(dashboard, 'on_event', None)
            if handler:
                self.bus.subscribe_all(handler)

        # Plugin Manager
        from pathlib import Path
        plugins_path = Path(plugins_dir) if plugins_dir else Path("plugins")
        from plugins.plugin_manager import PluginManager
        self.plugin_manager = PluginManager(plugins_path)
        self.plugin_manager.discover()

        # HealthCheck en background
        if enable_health:
            from core.health_check import HealthChecker
            self.health_checker = HealthChecker(self.k3)
            self.health_checker.start(self.api_keys, delay_s=120.0)
        else:
            self.health_checker = None

        # FastText classifier (lazy load)
        self._ft_classifier = None

    def _get_ft(self):
        if self._ft_classifier is None:
            try:
                from core.fasttext_engine import get_classifier
                self._ft_classifier = get_classifier()
            except Exception:
                pass
        return self._ft_classifier

    async def scan(self, raw_target: str) -> ScanState:
        from modules.recon.modules_01_08 import TargetSanitizer

        target = Target(raw=raw_target, normalized=raw_target, type=TargetType.UNKNOWN)

        core_modules, advanced = _build_core_modules(
            self.api_keys, self.use_tor, self.proxy, self.deep_multimodal
        )

        # Sanitizar primero
        sanitizer = core_modules[0]
        await sanitizer.run(target)
        self.k3.save_target(target)

        state = ScanState(scan_id=target.scan_id, target=target)

        await self.bus.emit(EventType.TARGET_STARTED, {
            "target":  target.normalized,
            "type":    target.type.value,
            "scan_id": target.scan_id,
        }, scan_id=target.scan_id)

        log.info(f"Scan started: {target} [{target.scan_id}]")

        # Enqueue core modules (skip sanitizer ya corrido)
        for module in core_modules[1:]:
            self.k1.enqueue(module, target, priority=module.MODULE_PRIORITY)

        # Enqueue plugins
        plugin_instances = self.plugin_manager.instantiate_all(
            self.api_keys, self.use_tor, self.proxy
        )
        for plugin in plugin_instances:
            self.k1.enqueue(plugin, target, priority=getattr(plugin, "MODULE_PRIORITY", 7))
            log.info(f"Plugin enqueued: [{plugin.MODULE_ID}] {plugin.MODULE_NAME}")

        # K1: Ejecutar todos
        entities = await self.k1.run_all(target, target.scan_id)
        for e in entities:
            e.scan_id = target.scan_id
            self.k3.buffer_entity(e)
        state.entities = entities

        # FastText — enriquecer metadata de entidades
        ft = self._get_ft()
        if ft:
            for e in entities:
                if e.verdict.value not in ("DISCARD",):
                    pred, conf = ft.predict_entity_type(e.value)
                    e.metadata["ft_type_pred"] = pred
                    e.metadata["ft_type_conf"] = round(conf, 3)

        # K2: Correlaciones
        correlations = await self.k2.correlate_all(entities, target.scan_id)
        state.correlations = correlations
        for c in correlations:
            self.k3.buffer_correlation(c)

        # Risk Score
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

        # ProfileComposite
        profile_builder = ProfileCompositeBuilder()
        profile = profile_builder.build(state)
        if profile:
            await self.bus.emit(EventType.PROFILE_UPDATED, {
                "profile": profile,
            }, scan_id=target.scan_id)

        # Timeline + Anomalías + CrossRef
        timeline  = advanced["timeline"].build_timeline(entities)
        anomalies = advanced["anomaly"].detect(entities)
        crossref  = advanced["crossref"].validate(entities)

        # Executive Summary
        summary = self._build_summary(state, profile, anomalies)

        # LLM semántico (si está habilitado)
        if self.use_llm:
            llm_analyzer = advanced["llm"]
            llm_analyzer.llm_host  = self.llm_host
            llm_analyzer.llm_model = self.llm_model
            try:
                llm_summary = await asyncio.wait_for(
                    llm_analyzer.analyze(state), timeout=60.0
                )
                if llm_summary and "no disponible" not in llm_summary.lower():
                    summary = f"[LLM: {self.llm_model}]\n{llm_summary}\n\n---\n{summary}"
                    log.info("LLM summary generado")
            except asyncio.TimeoutError:
                log.warning("LLM timeout — usando resumen determinístico")
            except Exception as e:
                log.debug(f"LLM error: {e}")

        # SelfLearning
        selflearn = advanced["selflearn"]
        insights  = selflearn.learn_from_scan(state, self.k3)
        if insights.get("alerts"):
            for alert in insights["alerts"]:
                log.warning(f"SelfLearning: {alert}")

        # Graph export adicional (GraphML y GEXF)
        graph_module = advanced["graph"]
        graphml_path = graph_module.save(
            graph_module.export_graphml(state), "graphml",
            target.scan_id, self.reports_dir
        )
        gexf_path = graph_module.save(
            graph_module.export_gexf(state), "gexf",
            target.scan_id, self.reports_dir
        )

        # Reporte HTML principal
        export     = advanced["export"]
        html       = export.generate_html(state, summary, timeline, anomalies)
        report_path = export.save(html, target.scan_id, self.reports_dir)

        # Finalizar
        state.finished_at = time.time()
        self.k3.flush_all()

        await self.bus.emit(EventType.SCAN_COMPLETE, {
            "scan_id":      target.scan_id,
            "entities":     len(entities),
            "trusted":      len(state.trusted_entities()),
            "correlations": len(correlations),
            "risk_score":   risk,
            "risk_level":   level,
            "elapsed":      state.elapsed(),
            "report":       str(report_path),
            "graphml":      graphml_path,
            "gexf":         gexf_path,
            "profile":      profile,
            "summary":      summary,
            "anomalies":    anomalies,
            "timeline":     timeline[:20],
            "crossref":     crossref,
            "plugins_used": len(plugin_instances),
            "ft_active":    ft is not None,
            "insights":     insights,
        }, scan_id=target.scan_id)

        log.info(
            f"Scan complete: {target.normalized} | "
            f"entities={len(entities)} trusted={len(state.trusted_entities())} "
            f"correlations={len(correlations)} risk={risk}/{level} "
            f"plugins={len(plugin_instances)} elapsed={state.elapsed():.1f}s"
        )
        return state

    def _build_summary(self, state, profile, anomalies) -> str:
        trusted = state.trusted_entities()
        lines   = []
        identity = profile.get("identity", {})
        names    = identity.get("names", [])
        location = profile.get("location", "Desconocida")
        platforms = profile.get("platforms", [])
        emails   = profile.get("emails", [])
        phones   = profile.get("phones", [])

        id_desc  = names[0] if names else state.target.normalized
        plat_str = ", ".join(platforms[:4]) if platforms else "no confirmado"

        lines.append("**1. IDENTIDAD / HUELLA CONFIRMADA**")
        lines.append(f"   {id_desc}, ubicación inferida: {location}.")
        if emails or phones:
            contact = []
            if emails: contact.append(f"{len(emails)} email(s)")
            if phones: contact.append(f"{len(phones)} teléfono(s)")
            lines.append(f"   Contacto: {', '.join(contact)}. Plataformas: {plat_str}.")

        age = profile.get("digital_age", {})
        lines.append(f"\n**2. HUELLA DIGITAL Y ANTIGÜEDAD**")
        if age.get("first_seen") and age["first_seen"] != "Desconocido":
            lines.append(f"   Primera actividad: {age['first_seen']} ({age.get('activity_years',0)} años).")
        breaches = profile.get("breaches", [])
        if breaches:
            lines.append(f"   {len(breaches)} breach(es) histórico(s).")
        ecommerce = profile.get("ecommerce", [])
        if ecommerce:
            ec_str = ", ".join(e["platform"] for e in ecommerce[:3])
            lines.append(f"   E-commerce: {ec_str}.")

        lines.append(f"\n**3. FACTORES DE RIESGO CRÍTICO**")
        critical = [a for a in anomalies if a.get("severity") in ("CRITICAL","HIGH")]
        for a in critical[:3]:
            lines.append(f"   [{a['severity']}] {a['description']}.")
        breach_ents = [e for e in trusted if "BREACH_HIT" in e.flags]
        if breach_ents:
            lines.append(f"   {len(breach_ents)} entidad(es) en breaches de datos.")
        dw_ents = [e for e in trusted if "DARKWEB_MENTION" in e.flags]
        if dw_ents:
            lines.append(f"   Mención en darkweb indexado ({len(dw_ents)} ref.).")
        lines.append(f"   Score: {state.risk_score}/100 [{state.risk_level.value}].")

        lines.append(f"\n**4. CORRELACIONES CLAVE**")
        if state.correlations:
            for c in state.correlations[:3]:
                lines.append(f"   {c.entity_a[:40]} [{c.rel_type}] {c.entity_b[:40]} ({c.confidence:.0%})")
        else:
            lines.append("   No se encontraron correlaciones significativas.")

        lines.append(f"\n**5. ANOMALÍAS DETECTADAS**")
        non_info = [a for a in anomalies if a.get("severity") != "INFO"]
        for a in non_info[:3]:
            lines.append(f"   {a['type']}: {a['description']}")
        if not non_info:
            lines.append("   No se detectaron anomalías significativas.")

        return "\n".join(lines)
