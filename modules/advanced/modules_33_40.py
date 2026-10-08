"""
Leviathan OSINT v4.0 — Módulos Advanced (33–40)
Risk Engine · Graph Export · Timeline · Anomaly Detector · Report
"""
from __future__ import annotations
import asyncio
import json
import logging
import time
from pathlib import Path
from modules.base_module import BaseModule
from core.models import Target, TargetType, EntityRecord, Verdict, ScanState

log = logging.getLogger("leviathan.advanced")


# ─── 36: RiskScoreEngine ─────────────────────────────────────────────────────

class RiskScoreEngine(BaseModule):
    MODULE_ID    = "36"
    MODULE_NAME  = "RiskScoreEngine"
    MODULE_PHASE = "advanced"

    # Factores de riesgo con sus pesos
    RISK_FACTORS = {
        "BREACH_HIT":        20,
        "DARKWEB_MENTION":   25,
        "CRIMINAL_RECORD":   30,
        "HIGH_RISK_IP":      15,
        "RANSOMWARE_VICTIM": 35,
        "SIMSWAP_RISK":      10,
        "VOIP":               5,
        "DISPOSABLE":         8,
        "NO_MX":              3,
        "NEWLY_REGISTERED":   7,
    }

    def compute_risk(self, entities: list[EntityRecord]) -> tuple[int, str, list[str]]:
        """Calcula score de riesgo 0-100 con explicación."""
        score   = 0
        factors = []
        flags_seen: set[str] = set()

        for entity in entities:
            if entity.verdict == Verdict.DISCARD:
                continue
            for flag in entity.flags:
                if flag not in flags_seen and flag in self.RISK_FACTORS:
                    pts = self.RISK_FACTORS[flag]
                    # Boost por confianza alta
                    pts = int(pts * min(1.2, entity.confidence + 0.3))
                    score   += pts
                    factors.append(f"{flag}: +{pts}")
                    flags_seen.add(flag)

        # Boost por cantidad de breaches
        breach_count = sum(1 for e in entities if "BREACH_HIT" in e.flags)
        if breach_count > 3:
            extra = min(15, breach_count * 3)
            score += extra
            factors.append(f"MULTIPLE_BREACHES ({breach_count}): +{extra}")

        # Penalización por entidades confirmadas (presencia digital alta)
        trusted = sum(1 for e in entities if e.verdict == Verdict.TRUSTED)
        if trusted > 15:
            score = min(100, score + 5)
            factors.append("HIGH_DIGITAL_FOOTPRINT: +5")

        score = max(0, min(100, score))

        if score >= 75:   level = "CRÍTICO"
        elif score >= 50: level = "ALTO"
        elif score >= 25: level = "MEDIO"
        elif score >= 10: level = "BAJO"
        else:             level = "NINGUNO"

        return score, level, factors

    async def _run(self, target: Target):
        # Este módulo es llamado directamente por el orquestador
        pass


# ─── 35: TimelineGenerator ───────────────────────────────────────────────────

class TimelineGenerator(BaseModule):
    MODULE_ID    = "35"
    MODULE_NAME  = "TimelineGenerator"
    MODULE_PHASE = "advanced"

    def build_timeline(self, entities: list[EntityRecord]) -> list[dict]:
        """Construye timeline cronológica de todos los eventos."""
        events = []
        for entity in entities:
            if entity.verdict == Verdict.DISCARD:
                continue
            ts = entity.emitted_at
            # Extraer fecha de metadata si existe
            for key in ("date", "breach_date", "registration_date", "first_seen", "published"):
                if date_str := entity.metadata.get(key):
                    events.append({
                        "ts":          ts,
                        "date_str":    str(date_str),
                        "entity_type": entity.type.value,
                        "value":       entity.value[:60],
                        "event_type":  key.upper(),
                        "source":      entity.sources[0] if entity.sources else "unknown",
                        "verdict":     entity.verdict.value,
                        "flags":       entity.flags,
                    })
                    break
            else:
                events.append({
                    "ts":          ts,
                    "date_str":    time.strftime("%Y-%m-%d", time.localtime(ts)),
                    "entity_type": entity.type.value,
                    "value":       entity.value[:60],
                    "event_type":  "ENTITY_FOUND",
                    "source":      entity.sources[0] if entity.sources else "unknown",
                    "verdict":     entity.verdict.value,
                    "flags":       entity.flags,
                })

        events.sort(key=lambda e: e["ts"])
        return events

    async def _run(self, target: Target):
        pass


# ─── 37: AnomalyDetector ─────────────────────────────────────────────────────

class AnomalyDetector(BaseModule):
    MODULE_ID    = "37"
    MODULE_NAME  = "AnomalyDetector"
    MODULE_PHASE = "advanced"

    def detect(self, entities: list[EntityRecord]) -> list[dict]:
        """7 detectores de anomalías e inconsistencias."""
        anomalies = []

        # 1. Dominio reciente con actividad antigua
        new_domains = [e for e in entities
                       if e.type.value == "domain" and "NEWLY_REGISTERED" in e.flags]
        old_activity = [e for e in entities
                        if "breach" in e.type.value and
                        e.metadata.get("breach_date_months", 999) > 24]
        if new_domains and old_activity:
            anomalies.append({
                "type":        "TEMPORAL_INCONSISTENCY",
                "description": "Dominio reciente con actividad histórica antigua",
                "severity":    "MEDIUM",
                "entities":    [d.value for d in new_domains[:3]],
            })

        # 2. Emails con carriers inconsistentes
        phones = [e for e in entities if e.type.value == "phone"]
        for phone in phones:
            if phone.metadata.get("is_voip") and not phone.metadata.get("simswap_risk"):
                anomalies.append({
                    "type":        "VOIP_NUMBER",
                    "description": f"Número VoIP detectado: {phone.value}",
                    "severity":    "LOW",
                    "entities":    [phone.value],
                })

        # 3. Múltiples breaches con diferentes emails
        breach_emails: set[str] = set()
        for e in entities:
            if "BREACH_HIT" in e.flags and e.type.value == "email":
                breach_emails.add(e.value)
        if len(breach_emails) > 2:
            anomalies.append({
                "type":        "MULTIPLE_COMPROMISED_EMAILS",
                "description": f"{len(breach_emails)} emails distintos en breaches",
                "severity":    "HIGH",
                "entities":    list(breach_emails)[:5],
            })

        # 4. Presencia en darkweb con breach reciente
        darkweb = [e for e in entities if "DARKWEB_MENTION" in e.flags]
        breaches = [e for e in entities if "BREACH_HIT" in e.flags]
        if darkweb and breaches:
            anomalies.append({
                "type":        "DARKWEB_BREACH_CORRELATION",
                "description": "Presencia en darkweb + datos comprometidos en breaches",
                "severity":    "CRITICAL",
                "entities":    [e.value for e in darkweb[:3]],
            })

        # 5. IP con reputación maliciosa y dominio corporativo
        bad_ips = [e for e in entities
                   if e.type.value == "ip" and "HIGH_RISK_IP" in e.flags]
        corp_domains = [e for e in entities
                        if e.type.value == "domain" and
                        e.metadata.get("has_mx") and not e.metadata.get("is_free_email")]
        if bad_ips and corp_domains:
            anomalies.append({
                "type":        "MALICIOUS_IP_CORPORATE_DOMAIN",
                "description": "IP maliciosa asociada a dominio corporativo",
                "severity":    "CRITICAL",
                "entities":    [ip.value for ip in bad_ips[:3]],
            })

        # 6. Disposable email en lista de breaches
        disp = [e for e in entities
                if "DISPOSABLE" in e.flags and "BREACH_HIT" in e.flags]
        if disp:
            anomalies.append({
                "type":        "DISPOSABLE_IN_BREACH",
                "description": "Email temporal encontrado en breach — posible false positive",
                "severity":    "LOW",
                "entities":    [e.value for e in disp[:2]],
            })

        # 7. Username idéntico en plataformas muy distintas
        usernames = [e for e in entities if e.type.value == "username"]
        platforms  = set(e.metadata.get("platform", "") for e in usernames if e.metadata.get("platform"))
        if len(platforms) > 5:
            anomalies.append({
                "type":        "HIGH_PLATFORM_PRESENCE",
                "description": f"Mismo username en {len(platforms)} plataformas distintas — identidad consistente o bot",
                "severity":    "INFO",
                "entities":    list(platforms)[:8],
            })

        return anomalies

    async def _run(self, target: Target):
        pass


# ─── 38: CrossRefValidator ───────────────────────────────────────────────────

class CrossRefValidator(BaseModule):
    MODULE_ID    = "38"
    MODULE_NAME  = "CrossRefValidator"
    MODULE_PHASE = "advanced"

    def validate(self, entities: list[EntityRecord]) -> dict:
        """Validación cruzada de entidades."""
        by_value: dict[str, list[EntityRecord]] = {}
        for e in entities:
            key = f"{e.type.value}:{e.value.lower()}"
            by_value.setdefault(key, []).append(e)

        multi_source = []
        for key, records in by_value.items():
            if len(records) > 1:
                all_sources = []
                for r in records:
                    all_sources.extend(r.sources)
                unique_sources = list(set(all_sources))
                multi_source.append({
                    "entity":        key,
                    "times_found":   len(records),
                    "sources":       unique_sources,
                    "avg_confidence": sum(r.confidence for r in records) / len(records),
                })

        verdicts = {}
        for e in entities:
            verdicts[e.verdict.value] = verdicts.get(e.verdict.value, 0) + 1

        return {
            "multi_source_entities": sorted(multi_source, key=lambda x: -x["times_found"])[:20],
            "verdict_distribution":  verdicts,
            "total_entities":        len(entities),
            "trusted_count":         verdicts.get("TRUSTED", 0),
            "discard_rate":          verdicts.get("DISCARD", 0) / max(1, len(entities)),
        }

    async def _run(self, target: Target):
        pass


# ─── 39: ExportReport ────────────────────────────────────────────────────────

class ExportReport(BaseModule):
    MODULE_ID    = "39"
    MODULE_NAME  = "ExportReport"
    MODULE_PHASE = "advanced"

    HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Leviathan OSINT — {target} — {date}</title>
<style>
:root {{
  --bg: #0A0A0A; --bg2: #111111; --bg3: #1a1a2e;
  --red: #C8102E; --cyan: #00F5FF; --purple: #7B2FBE;
  --text: #E0E0E0; --muted: #888; --border: #2a2a3e;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ background: var(--bg); color: var(--text); font-family: 'Courier New', monospace; padding: 20px; }}
header {{ border-left: 4px solid var(--red); padding: 12px 16px; margin-bottom: 24px; background: var(--bg3); }}
.title {{ font-size: 1.5em; color: var(--cyan); letter-spacing: 2px; }}
.subtitle {{ color: var(--muted); margin-top: 4px; }}
.risk-badge {{ display: inline-block; padding: 4px 12px; border-radius: 4px; font-weight: bold; margin-top: 8px; }}
.risk-CRÍTICO {{ background: #5c0000; color: #ff4444; border: 1px solid #ff0000; }}
.risk-ALTO    {{ background: #3d2000; color: #ff9944; border: 1px solid #ff6600; }}
.risk-MEDIO   {{ background: #3d3d00; color: #ffdd44; border: 1px solid #ffaa00; }}
.risk-BAJO    {{ background: #003d00; color: #44ff44; border: 1px solid #00aa00; }}
.risk-NINGUNO {{ background: #1a1a1a; color: #888; border: 1px solid #444; }}
section {{ margin-bottom: 28px; }}
h2 {{ color: var(--cyan); border-bottom: 1px solid var(--border); padding-bottom: 6px; margin-bottom: 12px; font-size: 0.9em; letter-spacing: 3px; text-transform: uppercase; }}
.entity-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(340px, 1fr)); gap: 12px; }}
.entity-card {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 6px; padding: 12px; }}
.entity-card.TRUSTED   {{ border-left: 3px solid var(--cyan); }}
.entity-card.LIKELY    {{ border-left: 3px solid #7B2FBE; }}
.entity-card.UNCERTAIN {{ border-left: 3px solid #888; }}
.entity-card.SUSPECT   {{ border-left: 3px solid #ff6600; }}
.entity-type {{ font-size: 0.7em; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; }}
.entity-value {{ font-size: 0.95em; color: var(--text); margin: 4px 0; word-break: break-all; }}
.entity-meta {{ font-size: 0.75em; color: var(--muted); }}
.flag {{ display: inline-block; background: #3d0000; color: #ff6666; padding: 1px 6px; border-radius: 3px; font-size: 0.7em; margin: 2px 2px 0 0; }}
.confidence {{ float: right; color: var(--cyan); font-size: 0.85em; }}
.corr-item {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 4px; padding: 8px 12px; margin-bottom: 6px; font-size: 0.85em; }}
.summary-box {{ background: var(--bg3); border: 1px solid var(--red); border-radius: 6px; padding: 16px; white-space: pre-line; line-height: 1.7; font-size: 0.9em; }}
.anomaly {{ background: var(--bg2); border-left: 3px solid #ff9900; padding: 8px 12px; margin-bottom: 6px; border-radius: 0 4px 4px 0; font-size: 0.85em; }}
.anomaly.CRITICAL {{ border-color: var(--red); }}
.anomaly.HIGH {{ border-color: #ff6600; }}
.timeline-item {{ display: flex; gap: 12px; padding: 6px 0; border-bottom: 1px solid var(--border); font-size: 0.82em; }}
.tl-date {{ color: var(--muted); min-width: 100px; }}
.tl-type {{ color: var(--cyan); min-width: 80px; }}
footer {{ margin-top: 40px; text-align: center; color: var(--muted); font-size: 0.75em; border-top: 1px solid var(--border); padding-top: 16px; }}
</style>
</head>
<body>
<header>
  <div class="title">🐉 LEVIATHAN OSINT — INTELLIGENCE REPORT</div>
  <div class="subtitle">Target: {target} | Tipo: {target_type} | Generado: {date}</div>
  <div class="subtitle">Módulos ejecutados: {modules_run} | Entidades: {total_entities} | Tiempo: {elapsed:.1f}s</div>
  <span class="risk-badge risk-{risk_level}">⚠ RIESGO: {risk_level} ({risk_score}/100)</span>
</header>

<section>
  <h2>📋 Executive Summary</h2>
  <div class="summary-box">{executive_summary}</div>
</section>

<section>
  <h2>🔗 Correlaciones ({corr_count})</h2>
  {correlations_html}
</section>

<section>
  <h2>⚠ Anomalías Detectadas ({anomaly_count})</h2>
  {anomalies_html}
</section>

<section>
  <h2>🔍 Entidades Confirmadas ({trusted_count})</h2>
  <div class="entity-grid">{entities_html}</div>
</section>

<section>
  <h2>📅 Timeline de Eventos</h2>
  {timeline_html}
</section>

<footer>
  Leviathan OSINT v4.0 — Creado por Luis Sánchez<br>
  <strong>Solo para uso legal y autorizado.</strong> El usuario es responsable del uso de esta herramienta.
</footer>
</body>
</html>"""

    def generate_html(
        self,
        state:     ScanState,
        summary:   str,
        timeline:  list[dict],
        anomalies: list[dict],
    ) -> str:
        entities_html = ""
        for e in sorted(state.trusted_entities(), key=lambda x: -x.confidence)[:50]:
            flags_html = "".join(f'<span class="flag">{f}</span>' for f in e.flags)
            entities_html += f"""
<div class="entity-card {e.verdict.value}">
  <div class="entity-type">{e.type.value}
    <span class="confidence">{e.confidence:.0%}</span>
  </div>
  <div class="entity-value">{e.value}</div>
  <div class="entity-meta">📡 {', '.join(e.sources[:3]) or 'N/A'}</div>
  {flags_html}
</div>"""

        corr_html = ""
        for c in state.correlations[:30]:
            corr_html += f'<div class="corr-item">⟷ {c.entity_a[:40]} <strong>[{c.rel_type}]</strong> {c.entity_b[:40]} — {c.confidence:.0%}</div>'
        if not corr_html:
            corr_html = "<p style='color:#888'>No se encontraron correlaciones.</p>"

        anom_html = ""
        for a in anomalies:
            sev = a.get("severity", "INFO")
            anom_html += f'<div class="anomaly {sev}"><strong>[{sev}] {a["type"]}</strong>: {a["description"]}</div>'
        if not anom_html:
            anom_html = "<p style='color:#888'>No se detectaron anomalías.</p>"

        tl_html = ""
        for ev in timeline[:40]:
            tl_html += f"""<div class="timeline-item">
  <span class="tl-date">{ev.get('date_str','?')}</span>
  <span class="tl-type">{ev.get('entity_type','?')}</span>
  <span>{ev.get('value','?')} — {ev.get('event_type','?')} [{ev.get('source','?')}]</span>
</div>"""

        import time as t
        return self.HTML_TEMPLATE.format(
            target=state.target.normalized,
            target_type=state.target.type.value.upper(),
            date=t.strftime("%Y-%m-%d %H:%M:%S"),
            modules_run=len(state.module_results),
            total_entities=len(state.entities),
            elapsed=state.elapsed(),
            risk_level=state.risk_level.value,
            risk_score=state.risk_score,
            executive_summary=summary or "No disponible",
            corr_count=len(state.correlations),
            correlations_html=corr_html,
            anomaly_count=len(anomalies),
            anomalies_html=anom_html,
            trusted_count=len(state.trusted_entities()),
            entities_html=entities_html,
            timeline_html=tl_html or "<p style='color:#888'>No hay eventos en timeline.</p>",
        )

    def save(self, html: str, scan_id: str, reports_dir: str = "reports") -> Path:
        import time as t
        Path(reports_dir).mkdir(exist_ok=True)
        ts   = t.strftime("%Y%m%d_%H%M%S")
        path = Path(reports_dir) / f"leviathan_{scan_id}_{ts}.html"
        path.write_text(html, encoding="utf-8")
        log.info(f"Report saved: {path}")
        return path

    async def _run(self, target: Target):
        pass
